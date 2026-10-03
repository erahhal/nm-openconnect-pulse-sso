#!/usr/bin/env python3
"""
HTTPS MITM proxy for Pulse VPN DSID cookie capture.

Binds to localhost:PORT, presents a local TLS cert for the VPN hostname, and
forwards all traffic to the real server (resolved via DNS-over-HTTPS to bypass
/etc/hosts). Watches server→client responses for Set-Cookie: DSID and writes
the result as JSON to --output.

The naive "exit on first DSID" approach is wrong: Pulse's SAML realm sets a
short-lived DSID during the early redirect flow, then UPDATES it with the
real session DSID after the IdP POSTs the SAML assertion back. So we:

  1. Collect EVERY Set-Cookie: DSID=... seen, in order, with timestamp +
     the most-recent request path that triggered the response.
  2. Once we've seen at least one USABLE DSID, wait until --quiesce seconds
     have passed with no new DSID arriving. The latest usable value wins.
  3. Clear-cookie / placeholder values (empty, "DELETED", short tokens like
     "DSID=1", 5xx responses) are recorded for forensics but never arm the
     quiesce commit: the gateway DELETES the stale session cookie at the
     START of a fresh sign-in flow (session-timeout welcome page), so
     committing on any candidate would kill the proxy seconds into a
     healthy re-auth.

Heavy logging to stderr (always) and optionally to a file (--log-file). Every
HTTP request line, every response status line, and every Set-Cookie header
(DSID or otherwise) is logged with timestamps and a per-connection id so the
sequence can be reconstructed after a failed auth attempt.

Output JSON:
    {"dsid": "...", "gwcert": "sha256:...", "candidates": [...]}

"candidates" is the full list of DSIDs seen, for forensics.

Usage:
    proxy.py --hostname pcs.flxvpn.net \
             --cert /path/server.crt --key /path/server.key \
             --port 8443 --output /tmp/dsid.json \
             [--timeout 300] [--quiesce 3] [--log-file /tmp/proxy.log]
"""

import argparse
import datetime
import hashlib
import itertools
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.request
from typing import Optional


# --- logging ----------------------------------------------------------------

_log_lock = threading.Lock()
_log_file = None  # type: ignore[var-annotated]


def log(msg: str) -> None:
    """Thread-safe timestamped log line. Goes to stderr and optionally a file."""
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    with _log_lock:
        print(line, file=sys.stderr, flush=True)
        if _log_file is not None:
            _log_file.write(line + "\n")
            _log_file.flush()


# --- helpers ----------------------------------------------------------------

# DoH endpoints, tried in order.  The *hostname* form comes first on purpose.
# Networks that force DNS through a local resolver normally implement it by
# dropping port 443 to a set of well-known resolver *IP addresses*, which kills
# the bare-IP endpoint while leaving the CDN address behind cloudflare-dns.com
# perfectly reachable.  Resolving that hostname through the system resolver is
# safe even though this function exists to bypass /etc/hosts: only the VPN
# gateway's own name is pinned to 127.0.0.1 there, so ordinary names still
# resolve normally.  The bare IP is kept as a fallback for the opposite
# failure — a network with no usable system DNS at all.
#
# Why this matters: a blocked bare IP here takes out *all* authentication, and
# the symptom points somewhere else entirely (openconnect never launches, so
# the logs show "Creating SSL connection failed", which reads like a gateway
# problem).  Seen 2026-10-02 on a router enforcing DNS with an exemption list
# that covered the host's wifi address but not its dock address.
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://1.1.1.1/dns-query",
)


def resolve_via_doh(hostname: str) -> str:
    """Resolve hostname via Cloudflare DoH, bypassing /etc/hosts."""
    ctx = ssl.create_default_context()
    failures = []
    for endpoint in DOH_ENDPOINTS:
        url = f"{endpoint}?name={hostname}&type=A"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            log(f"DoH endpoint {endpoint} failed: {e}")
            failures.append(f"{endpoint}: {e}")
            continue
        for answer in data.get("Answer", []):
            if answer.get("type") == 1:  # A record
                return answer["data"]
        log(f"DoH endpoint {endpoint} returned no A record")
        failures.append(f"{endpoint}: no A record")
    raise RuntimeError(f"DoH: no A record for {hostname} ({'; '.join(failures)})")


def get_real_cert_fingerprint(hostname: str, real_ip: str) -> str:
    """SHA-256 fingerprint of the real server's TLS cert (by IP, no /etc/hosts)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((real_ip, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as conn:
            cert_der = conn.getpeercert(binary_form=True)
    return "sha256:" + hashlib.sha256(cert_der).hexdigest()


# --- HTTP wire sniffing -----------------------------------------------------

# We only need to scan HTTP/1.x headers, which are ASCII. We do NOT parse
# bodies. The buffers are bounded so a long-lived persistent connection can't
# OOM us.
_BUF_CAP = 256 * 1024

# Request line: GET /foo HTTP/1.1
_REQ_LINE_RE = re.compile(rb'^([A-Z]{3,10}) ([^ ]+) HTTP/\d\.\d', re.MULTILINE)

# Response status line: HTTP/1.1 302 Found
_RESP_LINE_RE = re.compile(rb'^HTTP/\d\.\d (\d{3})( [^\r\n]*)?', re.MULTILINE)

# Any Set-Cookie line, case-insensitive on the header name.
_SETCOOKIE_RE = re.compile(rb'^[Ss]et-[Cc]ookie:[ \t]*([^\r\n]+)', re.MULTILINE)

# Just the cookie's name=value (DSID specifically).
_DSID_RE = re.compile(rb'(?:^|[;,\s])DSID=([^;\s]*)')

# Location header (lowercase compare since servers vary).
_LOCATION_RE = re.compile(rb'^[Ll]ocation:[ \t]*([^\r\n]+)', re.MULTILINE)

# Request Cookie header, so we can tell whether the BROWSER arrived already
# holding a session. Distinct from _SETCOOKIE_RE, which is the server's side.
_COOKIE_RE = re.compile(rb'^[Cc]ookie:[ \t]*([^\r\n]+)', re.MULTILINE)


def looks_like_clear_cookie(value: str) -> bool:
    """Pulse sets DSID= or DSID=DELETED to clear; we shouldn't commit those."""
    if not value:
        return True
    v = value.strip('"').lower()
    return v in ("", "deleted", "null", "0")


# A real Pulse session DSID is a long hex token (~32 chars). Anything much
# shorter is the transient placeholder Pulse sets during the early SAML
# redirect (observed: "DSID=1") — never a usable session cookie.
_MIN_REAL_DSID_LEN = 16


def looks_like_real_dsid(value: str, status: str) -> bool:
    """A committable DSID: not a clear/placeholder cookie, long enough to be a
    real session token, and not captured from a server-error (5xx) response."""
    if looks_like_clear_cookie(value):
        return False
    if len(value.strip('"')) < _MIN_REAL_DSID_LEN:
        return False
    if status and status.startswith("5"):
        return False
    return True


# --- shared connection state ------------------------------------------------

class CaptureState:
    """Aggregates DSIDs seen across all proxied connections."""

    def __init__(self):
        self._lock = threading.Lock()
        self._candidates: list[dict] = []
        self._last_seen_monotonic: float = 0.0
        self._saw_server_error: bool = False
        self._server_error_statuses: set = set()
        self._engaged: bool = False
        self._client_dsid_seen: bool = False
        self._client_dsid_monotonic: float = 0.0

    def record(self, dsid: str, raw_setcookie: str, request_path: str,
               response_status: str, location: str, conn_id: int):
        with self._lock:
            self._candidates.append({
                "ts": datetime.datetime.now().isoformat(timespec="milliseconds"),
                "monotonic": time.monotonic(),
                "dsid": dsid,
                "set_cookie": raw_setcookie,
                "request_path": request_path,
                "response_status": response_status,
                "location": location,
                "conn_id": conn_id,
            })
            self._last_seen_monotonic = time.monotonic()
        log(f"  [c{conn_id}] +DSID candidate #{len(self._candidates)}: "
            f"len={len(dsid)} status={response_status} path={request_path!r} "
            f"location={location!r}")

    def latest_committable(self) -> Optional[dict]:
        with self._lock:
            for c in reversed(self._candidates):
                if looks_like_real_dsid(c["dsid"], c["response_status"]):
                    return c
            return None

    def note_engaged(self, conn_id: int):
        """Record that a client completed a TLS handshake with us.

        This is the signal that the auth browser tab actually reached the
        proxy: the auth-dialog's readiness probe is a bare TCP connect (no
        TLS), and stray local clients that don't trust our cert abort the
        handshake with an alert — neither counts.
        """
        with self._lock:
            first = not self._engaged
            self._engaged = True
        if first:
            log(f"  [c{conn_id}] first completed client TLS handshake — "
                f"browser engaged")

    def engaged(self) -> bool:
        with self._lock:
            return self._engaged

    def note_client_dsid(self, conn_id: int, request_path: str):
        """Record that the CLIENT sent us a real-looking DSID cookie.

        This is the positive signature of a browser that is already signed in
        to the gateway portal. When it arrives before the gateway has issued
        any Set-Cookie: DSID of its own, the session predates this auth
        attempt — the gateway sees an authenticated request, has no reason to
        mint a new cookie, and our only capture surface (Set-Cookie) stays
        silent until the auth window times out.
        """
        with self._lock:
            first = not self._client_dsid_seen
            self._client_dsid_seen = True
            if first:
                self._client_dsid_monotonic = time.monotonic()
        if first:
            log(f"  [c{conn_id}] client presented an existing DSID cookie "
                f"(path={request_path!r}) — browser already has a portal "
                f"session")

    def client_presented_dsid(self) -> bool:
        with self._lock:
            return self._client_dsid_seen

    def seconds_since_client_dsid(self) -> float:
        with self._lock:
            if self._client_dsid_monotonic == 0.0:
                return float("inf")
            return time.monotonic() - self._client_dsid_monotonic

    def note_server_error(self, status: str, conn_id: int):
        """Record that the upstream gateway returned an HTTP 5xx response."""
        with self._lock:
            first = not self._saw_server_error
            self._saw_server_error = True
            self._server_error_statuses.add(status)
        if first:
            log(f"  [c{conn_id}] upstream gateway returned server error "
                f"(HTTP {status})")

    def saw_server_error(self) -> bool:
        with self._lock:
            return self._saw_server_error

    def all_candidates(self) -> list[dict]:
        with self._lock:
            return list(self._candidates)

    def seconds_since_last_dsid(self) -> float:
        with self._lock:
            if self._last_seen_monotonic == 0.0:
                return float("inf")
            return time.monotonic() - self._last_seen_monotonic


# --- per-connection sniffer -------------------------------------------------

def _sniff_request_path(buf: bytes) -> Optional[str]:
    """Return the path from the LATEST complete request line in buf, if any."""
    matches = list(_REQ_LINE_RE.finditer(buf))
    if not matches:
        return None
    method = matches[-1].group(1).decode("ascii", errors="replace")
    path = matches[-1].group(2).decode("ascii", errors="replace")
    return f"{method} {path}"


def _scan_response_headers(buf: bytes, conn_id: int, state: CaptureState,
                           current_req_path_holder: list):
    """Scan a response buffer for status line, Location, and Set-Cookie.

    Mutates nothing in buf — caller manages buffer rotation. Records any
    DSID Set-Cookies into state.
    """
    # Cheap-ish: rescan from the start since responses are small. Bounded by
    # _BUF_CAP. We track which Set-Cookie offsets we've already reported via
    # the holder so we don't double-record on each chunk.
    seen_offsets = current_req_path_holder[1]  # set[int]

    # Most recent status / location for context
    last_status = None
    for m in _RESP_LINE_RE.finditer(buf):
        last_status = m.group(1).decode("ascii", errors="replace")

    # Flag gateway server errors (HTTP 5xx). note_server_error() de-dups, so
    # re-seeing the same status as the buffer streams in is harmless.
    if last_status and last_status.startswith("5"):
        state.note_server_error(last_status, conn_id)

    last_location = ""
    for m in _LOCATION_RE.finditer(buf):
        last_location = m.group(1).decode("ascii", errors="replace").strip()

    for m in _SETCOOKIE_RE.finditer(buf):
        off = m.start()
        if off in seen_offsets:
            continue
        seen_offsets.add(off)
        raw = m.group(1).decode("ascii", errors="replace").strip()
        # Trim trailing CR if any leaked through.
        raw = raw.rstrip("\r")
        # Cookie attributes start at first ';'.
        cookie_kv = raw.split(";", 1)[0].strip()
        name = cookie_kv.split("=", 1)[0]
        # DSLastAccess is bumped on every response — logging each one drowns
        # out the signal in the log. Suppress it while keeping DSID and the
        # other one-shot cookies visible.
        if name != "DSLastAccess":
            log(f"  [c{conn_id}] Set-Cookie: {raw}")
        dm = _DSID_RE.search(m.group(1))
        if dm and name == "DSID":
            dsid = dm.group(1).decode("ascii", errors="replace")
            state.record(
                dsid=dsid,
                raw_setcookie=raw,
                request_path=current_req_path_holder[0] or "?",
                response_status=last_status or "?",
                location=last_location,
                conn_id=conn_id,
            )


def _scan_request_path_update(buf: bytes, holder: list):
    """Update current request path (most recent seen)."""
    p = _sniff_request_path(buf)
    if p:
        holder[0] = p


def _scan_request_cookies(buf: bytes, conn_id: int, state: CaptureState,
                          holder: list):
    """Note whether the client is presenting an existing DSID session cookie.

    Read-only: this never touches the bytes being relayed. We only latch a
    flag on the shared state, which the main loop uses to tell "browser
    arrived already signed in" apart from "user never completed the login".
    """
    if state.client_presented_dsid():
        return
    for m in _COOKIE_RE.finditer(buf):
        dm = _DSID_RE.search(m.group(1))
        if not dm:
            continue
        value = dm.group(1).decode("ascii", errors="replace")
        # Reuse the committable-DSID test: a cleared or placeholder cookie
        # ("DSID=", "DSID=1") is not evidence of a live portal session.
        if looks_like_real_dsid(value, ""):
            state.note_client_dsid(conn_id, holder[0] or "?")
            return


# --- core proxying ----------------------------------------------------------

def handle_connection(
    client_raw: socket.socket,
    client_addr: tuple,
    client_ctx: ssl.SSLContext,
    real_ip: str,
    hostname: str,
    state: CaptureState,
    conn_id: int,
):
    log(f"[c{conn_id}] accept from {client_addr[0]}:{client_addr[1]}")
    try:
        client = client_ctx.wrap_socket(client_raw, server_side=True)
    except ssl.SSLError as e:
        # This is normal background noise for HSTS-probing connections — the
        # browser may speculatively open extra connections that don't complete.
        log(f"[c{conn_id}] client TLS handshake failed: {e}")
        client_raw.close()
        return
    except OSError as e:
        log(f"[c{conn_id}] client socket error during handshake: {e}")
        client_raw.close()
        return

    state.note_engaged(conn_id)

    try:
        server_raw = socket.create_connection((real_ip, 443), timeout=30)
        server_ctx = ssl.create_default_context()
        server = server_ctx.wrap_socket(server_raw, server_hostname=hostname)
        log(f"[c{conn_id}] upstream connected to {real_ip}:443")
    except Exception as e:
        log(f"[c{conn_id}] upstream connect failed: {e}")
        try:
            client.close()
        except OSError:
            pass
        return

    # Per-connection holders.  current_req_path_holder[0] = latest path string;
    # [1] = set of already-reported Set-Cookie offsets in the response buffer.
    current_req_path_holder = ["", set()]

    def client_to_server():
        buf = b""
        bytes_total = 0
        try:
            while True:
                data = client.recv(8192)
                if not data:
                    break
                bytes_total += len(data)
                server.sendall(data)
                # Track most-recent request path
                buf = (buf + data)[-_BUF_CAP:]
                _scan_request_path_update(buf, current_req_path_holder)
                _scan_request_cookies(buf, conn_id, state,
                                      current_req_path_holder)
        except (ssl.SSLError, OSError) as e:
            log(f"[c{conn_id}] c→s read/write error: {e}")
        finally:
            log(f"[c{conn_id}] c→s closed ({bytes_total} bytes)")
            try:
                server.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def server_to_client():
        buf = b""
        bytes_total = 0
        try:
            while True:
                data = server.recv(8192)
                if not data:
                    break
                bytes_total += len(data)
                client.sendall(data)
                new_buf = buf + data
                # Bound the buffer; when we roll it, we lose track of older
                # Set-Cookie offsets — that's fine, the offsets are only used
                # to deduplicate within this current window.
                if len(new_buf) > _BUF_CAP:
                    new_buf = new_buf[-_BUF_CAP:]
                    current_req_path_holder[1].clear()
                buf = new_buf
                _scan_response_headers(buf, conn_id, state,
                                       current_req_path_holder)
        except (ssl.SSLError, OSError) as e:
            log(f"[c{conn_id}] s→c read/write error: {e}")
        finally:
            log(f"[c{conn_id}] s→c closed ({bytes_total} bytes)")
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    c2s = threading.Thread(target=client_to_server, daemon=True)
    c2s.start()
    server_to_client()
    c2s.join(timeout=5)

    for s in (client, server):
        try:
            s.close()
        except OSError:
            pass
    log(f"[c{conn_id}] connection done")


# --- main -------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="HTTPS MITM proxy for Pulse DSID capture")
    ap.add_argument("--hostname", required=True, help="VPN gateway hostname")
    ap.add_argument("--cert", required=True, help="Local TLS certificate (PEM)")
    ap.add_argument("--key", required=True, help="Local TLS private key (PEM)")
    ap.add_argument("--port", type=int, default=8443, help="Local listen port")
    ap.add_argument("--output", required=True, help="JSON output file path")
    ap.add_argument("--timeout", type=int, default=300,
                    help="Hard cap on total wait for a DSID (seconds)")
    ap.add_argument("--quiesce", type=float, default=3.0,
                    help="After first DSID is seen, wait this many seconds "
                         "with no new DSID before committing the latest "
                         "(default: 3). Pulse sets a transient DSID early "
                         "in the SAML flow and updates it after the IdP "
                         "POSTs the assertion back.")
    ap.add_argument("--engage-timeout", type=int, default=45,
                    help="If no client completes a TLS handshake within this "
                         "many seconds, exit with code 4 ('browser never "
                         "engaged'). A tab killed by a network change "
                         "(ERR_NETWORK_CHANGED) sits on an error page and "
                         "never retries — failing fast lets the caller open "
                         "a fresh tab instead of waiting out --timeout. "
                         "0 disables (default: 45).")
    ap.add_argument("--preauth-grace", type=float, default=10.0,
                    help="If the browser presents an existing DSID cookie "
                         "and the gateway issues no Set-Cookie: DSID of its "
                         "own within this many seconds, exit with code 5 "
                         "('already signed in'). The gateway has no reason "
                         "to mint a cookie for a session that already "
                         "exists, so waiting out --timeout cannot help; the "
                         "caller re-opens the flow via the portal logout URL "
                         "instead. 0 disables (default: 10).")
    ap.add_argument("--log-file", default="",
                    help="Optional path to also write logs to (in addition "
                         "to stderr).")
    args = ap.parse_args()

    global _log_file
    if args.log_file:
        try:
            _log_file = open(args.log_file, "a")
            log(f"--- proxy starting; log file: {args.log_file} ---")
        except OSError as e:
            print(f"Could not open log file {args.log_file}: {e}", file=sys.stderr)

    log(f"Args: hostname={args.hostname} port={args.port} "
        f"timeout={args.timeout} quiesce={args.quiesce}")

    # Bind the listening socket *first* — before DoH resolution and cert fetch.
    # If the port is already taken (EADDRINUSE) we exit immediately, before the
    # proxy ever looks "alive". Otherwise the auth-dialog's readiness probe
    # could connect to the foreign listener during the DoH window and mistake
    # it for our proxy, then open a browser against a dead backend.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", args.port))
    except OSError as e:
        log(f"Could not bind 127.0.0.1:{args.port}: {e}. Another process "
            f"grabbed this port in the gap since it was picked — the "
            f"nm-pulse-sso service will pick a fresh port and retry.")
        sys.exit(1)
    sock.listen(20)
    sock.settimeout(1.0)
    log(f"Listening on 127.0.0.1:{args.port}")

    log(f"Resolving {args.hostname} via DoH...")
    try:
        real_ip = resolve_via_doh(args.hostname)
    except Exception as e:
        log(f"DoH resolution failed: {e}")
        sys.exit(1)
    log(f"Real server IP: {real_ip}")

    log("Fetching real server certificate fingerprint...")
    try:
        gwcert = get_real_cert_fingerprint(args.hostname, real_ip)
    except Exception as e:
        log(f"Warning: could not get server cert: {e}")
        gwcert = ""
    log(f"gwcert: {gwcert}")

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    client_ctx.load_cert_chain(args.cert, args.key)

    state = CaptureState()
    conn_counter = itertools.count(1)
    deadline = time.monotonic() + args.timeout
    engage_deadline = (
        time.monotonic() + args.engage_timeout
        if args.engage_timeout > 0 else None
    )
    never_engaged = False
    preauthenticated = False

    while True:
        if time.monotonic() > deadline:
            log(f"Timed out after {args.timeout}s waiting for DSID.")
            break

        # Browser arrived already holding a portal session. The gateway will
        # not re-issue a DSID for a session it considers live, so no
        # Set-Cookie is coming and the full --timeout would be burned for
        # nothing. Require a grace window with ZERO Set-Cookie: DSID of any
        # kind: a genuine sign-in flow starts by CLEARING the stale cookie
        # ("DSID=1"), which lands as a candidate and proves the gateway is
        # actively managing the session.
        if (args.preauth_grace > 0 and not preauthenticated
                and state.client_presented_dsid()
                and not state.all_candidates()
                and state.seconds_since_client_dsid() >= args.preauth_grace):
            log(f"Browser presented an existing DSID and the gateway issued "
                f"no Set-Cookie: DSID within {args.preauth_grace}s — already "
                f"signed in. Exiting early so the caller can re-open the "
                f"flow through the portal logout URL.")
            preauthenticated = True
            break

        if (engage_deadline is not None and not state.engaged()
                and time.monotonic() > engage_deadline):
            log(f"No client completed a TLS handshake within "
                f"{args.engage_timeout}s — browser never engaged (tab dead "
                f"or never opened). Exiting early so the caller can retry "
                f"with a fresh tab.")
            never_engaged = True
            break

        # Commit once a USABLE DSID has been seen and things have been quiet
        # for --quiesce. Quiet time is measured from the last DSID activity
        # of any kind, but only a committable candidate arms the commit:
        # the gateway clears a stale cookie ("DSID=1", expires 1970) at the
        # start of a fresh sign-in flow, and committing on that would kill
        # the proxy while the browser is mid-flow. A flow that only ever
        # produces degenerate DSIDs waits out --timeout instead.
        if state.latest_committable() is not None:
            quiet_for = state.seconds_since_last_dsid()
            if quiet_for >= args.quiesce:
                log(f"DSID activity quiesced for {quiet_for:.1f}s ≥ "
                    f"{args.quiesce}s — committing.")
                break

        try:
            client_raw, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError as e:
            log(f"accept() failed: {e}")
            break

        conn_id = next(conn_counter)
        threading.Thread(
            target=handle_connection,
            args=(client_raw, addr, client_ctx, real_ip, args.hostname,
                  state, conn_id),
            daemon=True,
        ).start()

    try:
        sock.close()
    except OSError:
        pass

    chosen = state.latest_committable()
    all_seen = state.all_candidates()
    saw_server_error = state.saw_server_error()

    log(f"Total DSID candidates seen: {len(all_seen)}")
    for i, c in enumerate(all_seen, 1):
        committable = looks_like_real_dsid(c["dsid"], c["response_status"])
        tag = "" if committable else " [REJECTED]"
        marker = " <-- SELECTED" if chosen is not None and c is chosen else ""
        log(f"  candidate #{i}{tag}{marker}: status={c['response_status']} "
            f"len={len(c['dsid'])} path={c['request_path']!r} "
            f"loc={c['location']!r}")

    if chosen is None:
        # Still write the candidates list so the auth-dialog / user can see
        # what we did see (e.g. an HSTS-blocked browser would produce zero).
        with open(args.output, "w") as f:
            json.dump({"gwcert": gwcert, "candidates": all_seen,
                       "saw_server_error": saw_server_error,
                       "preauthenticated": preauthenticated}, f)
        if preauthenticated:
            # Distinct exit code: not an auth failure and not a dead tab. The
            # browser is signed in to the portal from an earlier session, so
            # the gateway never emits the Set-Cookie we capture on. Retrying
            # the same URL reproduces this exactly; the caller has to break
            # the existing session first.
            log("No usable DSID — browser already signed in to the portal "
                "(no fresh cookie issued).")
            sys.exit(5)
        if never_engaged:
            # Distinct exit code: the browser tab never reached us at all —
            # not an auth failure. The caller retries promptly with a new tab.
            log("No usable DSID — browser never engaged with the proxy.")
            sys.exit(4)
        if saw_server_error:
            # Distinct exit code: the gateway is having a server-side outage,
            # not an authentication failure. The caller backs off and retries.
            log("No usable DSID — VPN gateway returned server errors (HTTP 5xx).")
            sys.exit(3)
        log("No usable DSID captured.")
        sys.exit(1)

    # The IP we resolved via DoH is essential for openconnect: /etc/hosts
    # still points $hostname → 127.0.0.1, so without an explicit override
    # openconnect would dial loopback (where the proxy is no longer
    # listening) instead of the real gateway. Emit it as a single
    # HOST:IP token so the service can plug it straight into
    # `openconnect --resolve=...`.
    resolve = f"{args.hostname}:{real_ip}"

    result = {
        "dsid": chosen["dsid"],
        "gwcert": gwcert,
        "resolve": resolve,
        "candidates": all_seen,  # for forensics; auth-dialog ignores this
    }
    with open(args.output, "w") as f:
        json.dump(result, f)

    log(f"DSID captured (len={len(chosen['dsid'])}, "
        f"from response to {chosen['request_path']!r}). resolve={resolve}")


if __name__ == "__main__":
    main()

---
name: vpn-debug
description: |
  Debug nm-openconnect-pulse-sso VPN plugin issues.
  Activate when troubleshooting VPN connectivity, authentication, or reconnection problems.
  Keywords:
  - VPN, vpn, openconnect, pulse-sso, pulse sso
  - vpn disconnect, vpn won't connect, vpn drops
  - reconnect, resume, suspend, network change
  - auth failure, cookie, DSID, SAML, SSO
  - nm-pulse-sso, pulse-browser-auth, auth-dialog
  - tun0, route, DNS, openconnect exit
  - dock, undock, no IPv4, IP4.GATEWAY --, uncommitted DHCP lease
  - device reapply, ip -4 route show default, IPv6 masks dead IPv4
  - DoH, 1.1.1.1, DoH resolution failed, auth-dialog exit 1
  - replaceVars, substituteStream, pattern doesn't match anything, @placeholder@
  - rebuild fails after editing scripts/, unsubstituted placeholder, not found
user-invocable: true
allowed_tools: Bash, Read, Grep, Glob
---

# nm-openconnect-pulse-sso Debugging Guide

## Architecture Quick Reference

```
NM Frontend (user clicks Connect)
  -> pulse-sso-auth-dialog    (runs as user, NM stdin/stdout protocol)
    -> pulse-browser-auth      (CEF browser, outputs DSID cookie)
  -> nm-pulse-sso-service.py   (D-Bus VPN plugin, runs as root)
    -> openconnect --protocol=pulse -C <cookie>
      -> nm-pulse-sso-helper   (--script callback, configures TUN/routes/DNS)

Recovery layer (reconnection primarily goes through nmcli; service also has
NM-cooperative re-activation via D-Bus when openconnect dies externally):
  - vpn-auto-reconnect.sh     (systemd oneshot: nmcli connection up, 5 retries)
  - vpn-reconnect.sh          (post-resume: kill stale openconnect, trigger above)
  - 90-vpn-reconnect           (NM dispatcher: kill-first, cooldown, best-effort route)
  - vpnc hooks                 (auto-reconnect flag, default route fixup, Docker routes)

Flag file: /run/vpn-auto-reconnect
  - Created on successful VPN connection (vpnc post-connect hook)
  - Removed on user-initiated disconnect (plugin Disconnect())
  - Checked by recovery scripts to decide if reconnection is desired

Cooldown file: /run/vpn-reconnect-last-kill
  - Written by dispatcher after killing openconnect (timestamp:gateway:device)
  - 120-second cooldown prevents restart loops from transient WiFi glitches
  - Bypassed when the network actually changed (different gateway or device)
```

## First Steps

Always start by running the diagnostic script to collect system state:

```bash
diagnose-nm-pulse-vpn         # last 15 minutes of logs
diagnose-nm-pulse-vpn 30      # last 30 minutes
```

Output is saved to `/tmp/vpn-diagnose-<timestamp>.log`. Read this file first.

## Key Diagnostic Commands

### Process state
```bash
ps aux | grep -E '(openconnect|nm-pulse-sso)'
systemctl status nm-pulse-sso-service
```

### VPN service logs (most useful)
```bash
journalctl -u NetworkManager --since "15 minutes ago" | grep -iE '(pulse|openconnect|sso)'
```

### Post-resume / reconnect logs
```bash
journalctl -u vpn-auto-reconnect --since "15 minutes ago"
journalctl -u vpn-reconnect --since "15 minutes ago"
journalctl --since "15 minutes ago" | grep "90-vpn-reconnect"
journalctl --since "15 minutes ago" | grep -iE '(suspend|resume|sleep)'
```

### Network state
```bash
nmcli connection show --active | grep vpn
nmcli device status
ip addr show dev tun0
ip -4 route show
ip route show default
resolvectl status
```

### Configuration
```bash
cat /etc/nm-pulse-sso/config
ls -la /etc/NetworkManager/dispatcher.d/90-vpn-reconnect
ls -la /etc/vpnc/post-connect.d/ /etc/vpnc/reconnect.d/
```

## Common Failure Scenarios

### VPN won't connect at all

1. Check if the D-Bus service started:
   ```bash
   journalctl -u NetworkManager --since "5 minutes ago" | grep -i pulse
   ```
2. Check if auth-dialog launched and the browser opened:
   - Look for "Starting openconnect" or "auth failure" in logs
   - If no logs at all: the NM plugin may not be installed (`ls /etc/NetworkManager/VPN/nm-pulse-sso-service.name`)
3. Check if the gateway is reachable:
   ```bash
   curl -sI https://<gateway-url> | head -5
   ```
4. Check if CEF browser is available:
   ```bash
   which pulse-browser-auth
   ```

### VPN disconnects after suspend/resume

1. Check if the resume handler ran and killed stale openconnect:
   ```bash
   journalctl -u vpn-reconnect --since "5 minutes ago"
   ```
2. Check if the auto-reconnect service was triggered and succeeded:
   ```bash
   journalctl -u vpn-auto-reconnect --since "5 minutes ago"
   ```
3. Check that the flag file exists (should be present if VPN was connected):
   ```bash
   ls -la /run/vpn-auto-reconnect
   ```
4. Verify rpfilter is loose (required for reconnection):
   ```bash
   sysctl net.ipv4.conf.all.rp_filter   # should be 2
   ```

### VPN disconnects on network change (wifi switch, ethernet unplug)

1. Check dispatcher ran:
   ```bash
   journalctl --since "5 minutes ago" | grep "90-vpn-reconnect"
   ```
2. Check which event triggered it (look for `connectivity-change`, `down`, or `up` action)
3. Check if auto-reconnect was triggered:
   ```bash
   journalctl -u vpn-auto-reconnect --since "5 minutes ago"
   ```
4. For ethernet→WiFi switches: dispatcher should re-trigger auto-reconnect when WiFi comes UP
   - Look for "VPN should be up, triggering reconnect" in dispatcher logs
5. If reconnection seems to be skipped, check the cooldown:
   ```bash
   cat /run/vpn-reconnect-last-kill   # shows timestamp:gateway:device
   ```
   - The dispatcher skips kills for 120 seconds on the same network to prevent flapping
   - Look for "Skipping kill: last restart was" in dispatcher logs

### No IPv4 after a dock/undock, and the VPN retries forever

Symptom: `openconnect` exits instantly and repeatedly with `Failed to connect
to host <gateway>` / `Creating SSL connection failed`, every ~8s, indefinitely.
The base interface looks healthy — `nmcli` reports `connected` and `nmcli
device show` carries a full `DHCP4.OPTION[*]` lease — but the kernel has **no
IPv4 address and no IPv4 default route** on it, and `IP4.GATEWAY` is `--`.
IPv6 keeps working via SLAAC + an RA default route, so anything v6-capable is
fine and the machine only looks "partially" broken.

Two separate bugs produced this. Both are fixed; check for regressions.

1. **`ip route show default` lists both address families.** Every *decision*
   about whether a route exists must use `ip -4`. The gateway is IPv4-only, so
   a live IPv6 default route satisfies a family-agnostic check while IPv4 is
   dead. That is what made `vpn-auto-reconnect.sh`'s route repair silently skip
   itself and go straight to five futile `nmcli connection up` attempts.
2. **`nmcli device reapply` is not a safe repair.** `nm-dispatcher.sh` used to
   run it inline on an interface `down`, a few seconds after a dock's new
   interface appeared — while that interface's DHCP was still in flight, so "no
   default route" was the normal transient state, not a fault. The reapply tore
   down the IPv4 config NM had *just* committed, and since nothing ever retries
   a reapply, IPv4 stayed dead. The dispatcher now hands the repair to
   `vpn-auto-reconnect.service`, which runs out of band, can take as long as
   DHCP actually needs, and bounces the connection when a reapply isn't enough.

Confirming it — the uncommitted lease is the giveaway:

```bash
ip -4 addr show dev <dev>; ip -4 route show default    # both empty == this bug
nmcli device show <dev> | grep -E 'IP4.GATEWAY|DHCP4.OPTION'
journalctl --since "30 minutes ago" | grep -E 'ntpd.*Deleting|Leaving mDNS'
```

`expiry` minus `dhcp_lease_time` tells you when the lease actually arrived. An
address that lived only seconds (`ntpd ... active_time=3 secs`, avahi `Leaving
mDNS multicast group ... with address`) means something tore down a *good*
config, rather than DHCP never having finished.

Manual recovery, which is also what the service now does:

```bash
CON=$(nmcli -t -g GENERAL.CONNECTION device show <dev>)
sudo nmcli connection down "$CON" && sudo nmcli connection up "$CON"
```

Be aware that this bounce also makes NM tear down the VPN, which the plugin
logs as `User-initiated disconnect`: it removes `/run/vpn-auto-reconnect` and
drops the cached cookie, so the next connect needs a fresh SSO login instead of
a silent cookie reconnect.

### Auth-dialog fails after ~10s with exit 1 — DoH blocked upstream

`proxy.py` resolves the gateway over **Cloudflare DoH**, not the system
resolver, because `/etc/hosts` deliberately pins the gateway hostname to
`127.0.0.1` so the browser reaches the local proxy. It tries `DOH_ENDPOINTS` in
order — `cloudflare-dns.com` first, then the bare `1.1.1.1` — so a network that
blocks resolver *IPs* no longer breaks auth on its own. If **both** are
unreachable, authentication cannot even start:

```
Auth-dialog (attempt 1) failed (exit 1)
# and in /tmp/pulse-dsid-*.log:
DoH resolution failed: <urlopen error timed out>
```

Three attempts, then `Auth-dialog failed with non-transient error — stopping
reconnection`. ICMP to 1.1.1.1 still answers, so a ping test is misleading —
test the port, and confirm the hostname resolves fine by other means:

```bash
curl -4 -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1/   # hangs == blocked
dig +short @<lan-resolver> <gateway-host> A                      # the IP it wanted
```

Routers that force DNS through their own resolver do exactly this, usually by
dropping 443 to a set of known resolver addresses with a per-client exemption
list. That used to be a single point of failure for *all* authentication,
because the only endpoint was the bare `1.1.1.1`. The hostname endpoint added
in front of it survives that class of block, since only the gateway hostname is
hijacked in `/etc/hosts` — ordinary names still resolve normally.

Each endpoint gets a 10s timeout, so a fully-blocked network now costs ~20s per
auth attempt instead of 10s before failing. Read the proxy log to see which
endpoint answered; `DoH endpoint <url> failed:` lines name each one that
didn't.

### Authentication failure loop

OpenConnect exit code 2 = auth failure. The plugin clears the cached cookie so the next `nmcli connection up` will trigger fresh browser authentication.

1. Check for auth failures:
   ```bash
   journalctl -u NetworkManager --since "15 minutes ago" | grep -i "auth.fail"
   ```
2. If the browser opens repeatedly but auth keeps failing:
   - The DSID cookie may be rejected by the server
   - Try clearing the browser profile: `rm -rf ~/.cache/pulse-browser-auth`
   - Check if the identity provider (Okta, etc.) is blocking the browser
3. If the browser never opens:
   - Check systemd-run launch errors in logs
   - Verify DISPLAY or WAYLAND_DISPLAY is set in the user session

### Auth times out with the browser sitting on the portal (already signed in)

**Signature:** the auth window runs its full 300 s and the proxy log shows
`Total DSID candidates seen: 0`, but the browser is visibly fine — the tab is
on `pcs.flxvpn.net/dana/user/#` showing the Ivanti portal, already
authenticated. Auth retries up to 10 times and every attempt looks identical.

**Cause:** `browser-auth/proxy.py` can only capture the cookie from a
`Set-Cookie: DSID=` header in a *response*. If the browser still holds a live
portal session from earlier, the gateway considers the request authenticated,
serves the portal directly, and never re-issues the cookie. There is nothing
on the wire to capture, so waiting out the timeout cannot help — and neither
can retrying the same URL, which reproduces it exactly.

Note the trap: this looks like a *browser* or *transport* problem and is
neither. Check before chasing either:

```bash
# Has openconnect even been launched? 0 = never got that far.
journalctl --since "15 minutes ago" | grep -c "openconnect started with PID"

# Is the gateway reachable right now? (bypasses /etc/hosts via the IP)
openssl s_client -connect <gw-ip>:443 -servername pcs.flxvpn.net </dev/null 2>&1 | grep 'Verify return'
```

If openconnect never started, nothing is wrong at the tunnel layer — it is
never reached. The proxy also re-fetches the gateway cert at the top of every
attempt (`gwcert: sha256:…` in its log), which is itself proof the transport
is healthy.

**Handled automatically** (proxy exit code 5):

- The proxy watches *request* `Cookie:` headers. A real-looking `DSID` from
  the client, seen before the gateway has issued any `Set-Cookie: DSID`, means
  the session predates this attempt.
- After `--preauth-grace` (default 10 s) with **zero** `Set-Cookie: DSID` of
  any kind, it exits 5 instead of burning the remaining ~290 s.
- The guard is *zero candidates*, not zero committable ones, on purpose: a
  genuine sign-in starts by **clearing** the stale cookie (`DSID=1`), which
  lands as a candidate and proves the gateway is actively managing the
  session. That flow must never be aborted.
- The service escalates **once**, relaunching the dialog with `--logout-first`
  so it opens `/dana-na/auth/logout.cgi` instead of the gateway. That drops
  the portal session, the next load runs the full sign-in, and the gateway
  mints a fresh DSID.
- If an attempt exits 5 *again* after the logout round-trip, the service stops
  retrying and notifies the user to sign out manually. Escalating on a loop
  would silently burn the attempt budget.

**Manual fix** if it ever reaches you: in the portal tab, click **Sign Out**
(or clear site data for the gateway host), then reconnect.

### OpenConnect crashes (non-auth exit codes)

1. Check the exit code:
   ```bash
   journalctl -u NetworkManager --since "15 minutes ago" | grep "exited with code"
   ```
2. Exit code 2 = auth failure — plugin clears cookie
3. Other exit codes: plugin retains cookie and stays alive for 5 minutes; the external `vpn-auto-reconnect.service` handles reconnection via `nmcli connection up`
4. After 5 consecutive non-auth failures, the plugin treats the cookie as stale/IP-bound and automatically triggers re-authentication (look for "cookie likely invalid, triggering re-authentication" in logs)
5. If crashes are persistent:
   - Check DTLS config: `cat /etc/nm-pulse-sso/config`
   - Try disabling DTLS in NixOS config (`enableDtls = false`) to rule out UDP/ESP issues
   - Check kernel logs: `dmesg | tail -50`

## DTLS vs Non-DTLS Behavior

Configuration in `/etc/nm-pulse-sso/config`:
- `ENABLE_DTLS=true`: openconnect uses UDP/ESP tunnel (better performance)
- `ENABLE_DTLS=false`: openconnect uses `--no-dtls` (TCP/SSL only)

DTLS is the default and generally more stable. Reconnection in both modes is handled externally by `vpn-auto-reconnect.service` via `nmcli connection up`.

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/nm-pulse-sso/config` | Runtime settings (DTLS, TCP keepalive) |
| `/etc/NetworkManager/VPN/nm-pulse-sso-service.name` | NM plugin descriptor |
| `/etc/NetworkManager/dispatcher.d/90-vpn-reconnect` | Interface change handler |
| `/etc/vpnc/post-connect.d/` | Scripts run after VPN connects (incl. auto-reconnect flag) |
| `/etc/vpnc/reconnect.d/` | Scripts run after VPN reconnects |
| `/run/vpn-auto-reconnect` | Flag file: VPN should be connected (created on connect, removed on user disconnect) |
| `/run/vpn-reconnect-last-kill` | Dispatcher cooldown: timestamp:gateway:device of last openconnect kill |
| `~/.cache/pulse-browser-auth/` | CEF browser profile, cookies, extensions |

## Key Source Files

When deeper investigation into the code is needed:

| File | What to look for |
|------|-----------------|
| `vpn-service/nm-pulse-sso-service.py` | D-Bus service logic, openconnect spawn, cookie retention, idle timeout, stale route cleanup, consecutive failure counting, NM-cooperative re-activation |
| `vpn-service/nm-pulse-sso-helper` | IP config reporting, DNS setup, route parsing |
| `auth-dialog/pulse-sso-auth-dialog` | Auth-dialog protocol, CEF launch, cookie extraction |
| `cef-auth/main.cc` | CEF browser behavior, UA switching, cookie monitoring, extensions |
| `scripts/vpn-auto-reconnect.sh` | External reconnect service (nmcli, retries, backoff, notifications) |
| `scripts/vpn-reconnect.sh` | Post-resume handler (kill openconnect, trigger auto-reconnect) |
| `scripts/nm-dispatcher.sh` | Network change detection (kill openconnect or re-trigger reconnect) |
| `scripts/vpnc/post-connect-auto-reconnect-flag.sh` | Creates /run/vpn-auto-reconnect flag on VPN connect |
| `scripts/diagnose.sh` | What the diagnostic script checks |
| `module.nix` | NixOS module options and what gets installed |

## Editing the shell scripts: `@placeholder@` substitution is strict

Everything under `scripts/` is a **template**, not a runnable script. `module.nix`
passes each one through `pkgs.replaceVars` with an attrset of store paths, which
replaces `@name@` with the corresponding package. The substitution is strict in
one direction and silent in the other, and both bite:

- **A declared variable that no longer appears in the file is a build error.**
  Removing the last use of a command breaks the build:

  ```
  substituteStream() in derivation nm-dispatcher.sh: ERROR: pattern
  @networkmanager@ doesn't match anything in file '/nix/store/...-nm-dispatcher.sh'
  ```

  The error names only the pattern, never the fact that you deleted its last
  call site, and it surfaces at rebuild time rather than when you edit. Hit on
  2026-10-02 after dropping the dispatcher's only `nmcli` invocation — the fix
  was to remove `networkmanager` from that derivation's `inherit (pkgs) ...`
  list, since the script genuinely no longer needed it.

- **A variable used in the file but *not* declared is left literal, silently.**
  Nothing fails at build time; the installed script just contains
  `@networkmanager@/bin/nmcli` and dies at runtime with `not found`. This is the
  more dangerous direction, because a dispatcher hook failing this way is nearly
  invisible — it only runs on network events.

So whenever you add or remove a command invocation, update that script's
`replaceVars` attrset in `module.nix` **in the same edit**.

Check every script against its derivation, both directions, from the repo root:

```bash
python3 - <<'EOF'
import re, pathlib
mod = pathlib.Path("module.nix").read_text()
pat = re.compile(r"pkgs\.replaceVars\s+\./([^\s]+)\s*\{(.*?)\n\s*\}\}", re.S)
problems = 0
for m in pat.finditer(mod):
    path, body = m.group(1), m.group(2)
    f = pathlib.Path(path)
    if not f.exists():
        print(f"!! {path}: missing"); problems += 1; continue
    declared = set()
    for inh in re.finditer(r"inherit\s*\(pkgs\)\s*([^;]+);", body):
        declared |= set(inh.group(1).split())
    for asg in re.finditer(r"^\s*([a-zA-Z0-9_-]+)\s*=", body, re.M):
        declared.add(asg.group(1))
    used = set(re.findall(r"@([a-zA-Z0-9_-]+)@", f.read_text()))
    missing, extra = sorted(declared - used), sorted(used - declared)
    print(f"[{'PROBLEM' if missing or extra else 'ok':7}] {path}")
    if missing: print(f"            declared but NOT in file (build fails): {missing}")
    if extra:   print(f"            in file but NOT declared (left literal): {extra}")
    problems += bool(missing or extra)
print(f"\n{problems} problem(s)")
EOF
```

To prove one script substitutes cleanly without running a full rebuild — build
just that derivation, mirroring its `replaceVars` call, then confirm nothing was
left behind:

```bash
OUT=$(nix build --no-link --print-out-paths --impure --expr '
  let pkgs = import <nixpkgs> {}; in
  pkgs.replaceVars ./scripts/nm-dispatcher.sh {
    inherit (pkgs) procps coreutils iproute2 gawk systemd libnotify;
    sudo = pkgs.sudo;
  }')
grep -o '@[a-zA-Z0-9_-]*@' "$OUT" || echo "clean — every placeholder substituted"
```

## Auth-Dialog / Proxy Exit Codes

Distinct from openconnect's. The auth-dialog passes the proxy's code through,
and the service branches on it instead of cycling launch strategies.

| Code | Meaning | Service behavior |
|------|---------|-----------------|
| 0 | DSID captured | Proceed to openconnect |
| 1 | Auth failed / no usable DSID | Normal retry, cycles launch strategies |
| 3 | Gateway returned HTTP 5xx | Server-side outage: notify once, back off 30 s |
| 4 | Browser never engaged (dead or unopened tab) | Retry in 3 s with a fresh tab |
| 5 | Browser already signed in; no fresh cookie issued | Escalate once to the portal logout URL; if it recurs, notify the user |

## OpenConnect Exit Codes

| Code | Meaning | Plugin behavior |
|------|---------|-----------------|
| 0 | Clean exit | Normal shutdown |
| 2 | Auth failure | Clears cached cookie; next reconnect will trigger browser auth |
| Other | Connection failure | Retains cookie, stays alive 5 min; external service handles reconnect via nmcli. After 5 consecutive failures, treats cookie as stale and triggers re-auth |

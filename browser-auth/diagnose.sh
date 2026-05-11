#!/usr/bin/env bash
# Diagnostic dump for the nm-pulse-sso browser-auth backend.
#
# Captures everything needed to debug a failed VPN auth: module state,
# /etc/hosts override, iptables NAT redirect, local CA trust, proxy package
# layout (catches the wrapGAppsHook .py-wrapping bug), live port state, and
# recent NetworkManager journal entries.
#
# Substituted at build time:
#   @HOSTNAME@    — VPN gateway hostname (e.g. pcs.flxvpn.net)
#   @PROXY_PORT@  — local proxy listen port (e.g. 8443)
#   @PKG@         — store path of the browser-auth package
#   @CA_CERT@     — store path of the local CA cert (for verify check)

set -u

HOSTNAME="@HOSTNAME@"
PROXY_PORT="@PROXY_PORT@"
PKG="@PKG@"
CA_CERT="@CA_CERT@"
CERTUTIL="@CERTUTIL@"
NICK="Pulse Browser Auth Local CA"

# Pretty section header.
section() {
    printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"
}

ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$1"; }
err()  { printf '  \033[1;31m✗\033[0m %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }

section "Configuration"
info "Hostname: $HOSTNAME"
info "Proxy port: $PROXY_PORT"
info "Package: $PKG"
info "CA cert: $CA_CERT"

section "Module state"
if grep -q "enableDesktopBrowserAuth" /etc/NetworkManager/VPN/nm-pulse-sso-service.name 2>/dev/null; then
    : # not actually expected to be there, just a placeholder
fi
NAME_FILE=$(readlink -f /etc/NetworkManager/VPN/nm-pulse-sso-service.name 2>/dev/null)
if [[ "$NAME_FILE" == *browser-auth* ]]; then
    ok "NM plugin is browser-auth: $NAME_FILE"
else
    err "NM plugin is NOT browser-auth (current: $NAME_FILE)"
    info "→ enableDesktopBrowserAuth may be off, or you haven't rebuilt+switched"
fi

section "/etc/hosts override"
HOSTS_LINE=$(getent hosts "$HOSTNAME" 2>/dev/null)
if [[ "$HOSTS_LINE" == 127.0.0.1* ]]; then
    ok "$HOSTNAME → 127.0.0.1"
    info "$HOSTS_LINE"
else
    err "$HOSTNAME does NOT resolve to 127.0.0.1"
    info "Current: ${HOSTS_LINE:-<no result>}"
    info "→ networking.extraHosts may not have applied; check /etc/hosts"
fi
grep -E "\b$HOSTNAME\b" /etc/hosts 2>/dev/null | sed 's/^/    /' || true

section "iptables NAT redirect (443 → $PROXY_PORT)"
if command -v iptables >/dev/null; then
    NAT_RULES=$(iptables -t nat -S OUTPUT 2>&1)
    if echo "$NAT_RULES" | grep -qE "\-\-dport 443 .*REDIRECT.*--to-ports $PROXY_PORT"; then
        ok "REDIRECT rule present"
        echo "$NAT_RULES" | grep -E "443|$PROXY_PORT" | sed 's/^/    /'
    else
        err "REDIRECT rule missing"
        info "→ systemctl status nm-pulse-sso-browser-auth-redirect"
    fi
    echo
    info "OUTPUT nat chain:"
    iptables -t nat -L OUTPUT -n -v 2>&1 | sed 's/^/    /'
else
    warn "iptables binary not found"
fi

section "Redirect service status"
systemctl status nm-pulse-sso-browser-auth-redirect.service --no-pager 2>&1 \
    | head -20 | sed 's/^/    /'

section "Local CA in system trust store"
if [[ -r "$CA_CERT" ]]; then
    CA_SUBJECT=$(openssl x509 -in "$CA_CERT" -noout -subject 2>/dev/null)
    CA_FP=$(openssl x509 -in "$CA_CERT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    info "Source: $CA_SUBJECT"
    info "SHA-256: $CA_FP"
    if [[ -r /etc/ssl/certs/ca-certificates.crt ]]; then
        if grep -q "$NICK" /etc/ssl/certs/ca-certificates.crt; then
            ok "Local CA found in /etc/ssl/certs/ca-certificates.crt"
        else
            err "Local CA NOT in /etc/ssl/certs/ca-certificates.crt"
            info "→ security.pki.certificateFiles may not have applied"
        fi
    fi
else
    warn "CA cert not readable: $CA_CERT"
fi

section "Local CA trust in browser NSS DBs"
# Chrome on Linux uses ~/.pki/nssdb — NOT the system trust store. The user
# must run `pulse-browser-auth-trust install` after each rebuild (and after
# any CA rotation) for HTTPS to work AND for HSTS to be bypassed.
check_nss() {
    local db="$1"
    if "$CERTUTIL" -L -d "sql:$db" -n "$NICK" >/dev/null 2>&1; then
        ok "trusted in $db"
    else
        err "NOT trusted in $db"
        info "→ run: pulse-browser-auth-trust install"
    fi
}
CHROMIUM_DB="$HOME/.pki/nssdb"
if [[ -f "$CHROMIUM_DB/cert9.db" ]]; then
    check_nss "$CHROMIUM_DB"
else
    err "Chromium NSS DB does not exist yet: $CHROMIUM_DB"
    info "→ run: pulse-browser-auth-trust install   (creates DB if missing)"
fi
shopt -s nullglob
for profile in "$HOME"/.mozilla/firefox/*/; do
    [[ -f "$profile/cert9.db" ]] || continue
    check_nss "${profile%/}"
done
shopt -u nullglob

section "Browser-auth package layout"
if [[ -d "$PKG/libexec" ]]; then
    ls -la "$PKG/libexec/" 2>&1 | sed 's/^/    /'
    echo
    # Critical check: proxy.py must NOT have been wrapped into an ELF binary
    for py in "$PKG"/libexec/*.py "$PKG"/share/nm-pulse-sso-browser-auth/*.py; do
        [[ -e "$py" ]] || continue
        TYPE=$(file -b "$py" 2>/dev/null)
        if [[ "$TYPE" == *ELF* ]]; then
            err "$py is an ELF BINARY (should be Python source!)"
            info "→ wrapGAppsHook regression; reinstall .py outside libexec/"
        elif [[ "$TYPE" == Python* ]] || [[ "$TYPE" == *text* ]]; then
            ok "$(basename "$py") is plain Python text"
        else
            warn "$py: $TYPE"
        fi
    done
else
    err "Package libexec missing: $PKG/libexec"
fi

section "Proxy listen test"
if ss -ltn "sport = :$PROXY_PORT" 2>/dev/null | grep -q ":$PROXY_PORT"; then
    ok "Something is listening on :$PROXY_PORT"
    ss -ltnp "sport = :$PROXY_PORT" 2>/dev/null | sed 's/^/    /'
else
    info "Nothing listening on :$PROXY_PORT (expected — proxy only runs during auth)"
fi

section "End-to-end cert test (only useful while proxy is running)"
if timeout 2 bash -c "</dev/tcp/127.0.0.1/$PROXY_PORT" 2>/dev/null; then
    ok "TCP connect to 127.0.0.1:$PROXY_PORT succeeded"
    PROXY_CERT=$(echo | openssl s_client -connect "127.0.0.1:$PROXY_PORT" \
        -servername "$HOSTNAME" 2>/dev/null \
        | sed -n '/BEGIN CERT/,/END CERT/p')
    if [[ -n "$PROXY_CERT" ]]; then
        info "Cert presented by proxy:"
        echo "$PROXY_CERT" | openssl x509 -noout -subject -issuer 2>&1 | sed 's/^/    /'
        if echo "$PROXY_CERT" | openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt 2>&1 \
            | grep -q "OK"; then
            ok "Proxy cert verifies against system trust store"
        else
            warn "Proxy cert does NOT verify against system trust"
        fi
    fi
else
    info "Proxy not listening — skipping cert handshake test"
fi

section "Most recent proxy log"
# The auth-dialog writes per-attempt proxy logs to /tmp/pulse-dsid-*.log
# (see browser-auth/auth-dialog). These are the structured forensics for the
# DSID-capture flow — status codes, request paths, Set-Cookie headers.
shopt -s nullglob
proxy_logs=( /tmp/pulse-dsid-*.log )
shopt -u nullglob
if (( ${#proxy_logs[@]} == 0 )); then
    info "no proxy logs in /tmp (no auth attempt has run yet)"
else
    # Pick the most recently modified.
    latest_log=$(ls -t /tmp/pulse-dsid-*.log 2>/dev/null | head -1)
    info "latest: $latest_log"
    info "($(wc -l <"$latest_log") lines, mtime $(stat -c %y "$latest_log" 2>/dev/null))"
    echo
    # Tail just the interesting parts: DSID candidates and the final summary.
    grep -E 'DSID candidate|SELECTED|Total DSID|DSID captured|No usable DSID|Set-Cookie:' "$latest_log" \
        | tail -40 \
        | sed 's/^/    /'
    if (( $(wc -l <"$latest_log") > 40 )); then
        info "(showing summary lines only — full log at $latest_log)"
    fi
fi

section "Recent NetworkManager browser-auth log entries (last 60s)"
journalctl -u NetworkManager --since "60 seconds ago" --no-pager 2>&1 \
    | grep -iE "nm-pulse-sso|proxy|auth-dialog|browser-auth|dsid|null bytes|SyntaxError" \
    | tail -40 \
    | sed 's/^/    /'
if [[ -z "$(journalctl -u NetworkManager --since "60 seconds ago" 2>/dev/null | head -1)" ]]; then
    info "(no recent NM activity)"
fi

section "Last failed auth attempt (anywhere in journal)"
LAST_ERR=$(journalctl -u NetworkManager --no-pager 2>&1 \
    | grep -iE "browser-auth.*ERROR|null bytes|SyntaxError|Proxy failed" \
    | tail -10)
if [[ -n "$LAST_ERR" ]]; then
    echo "$LAST_ERR" | sed 's/^/    /'
else
    info "(no errors found)"
fi

section "Summary hints"
cat <<EOF
    To test live, in two terminals:
      1)  journalctl -fu NetworkManager
      2)  nmcli connection up "Netflix VPN"

    Manually run the proxy outside NM (drops into foreground; Ctrl-C to stop):
      $PKG/bin/pulse-browser-proxy \\
        --hostname $HOSTNAME \\
        --cert <cert-path> --key <key-path> \\
        --port $PROXY_PORT --output /tmp/dsid.json

    Re-run this script after each rebuild:
      diagnose-pulse-browser-auth
EOF

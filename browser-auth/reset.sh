#!/usr/bin/env bash
# Wipe all runtime state for the nm-pulse-sso browser-auth backend so the
# next auth attempt starts truly fresh.
#
# What it touches (most → least obtrusive):
#   1. Kills any stray proxy processes (pulse-browser-proxy / proxy.py).
#   2. Removes /tmp/pulse-dsid-*.json result files.
#   3. Removes the iptables NAT redirect (if still installed at runtime).
#   4. Clears the cookie/gwcert cached on the NetworkManager VPN connection
#      so the next Connect triggers a fresh auth-dialog run.
#   5. Removes the local CA from the user's Chromium-family + Firefox NSS DBs
#      (delegates to pulse-browser-auth-trust uninstall).
#   6. Clears any Chrome / Chromium / Brave / Edge HSTS pin for the gateway
#      hostname (closes the browser if needed, edits TransportSecurity, then
#      tells the user to restart it).
#   7. Does NOT modify /etc/hosts (managed by Nix; goes away automatically
#      when enableDesktopBrowserAuth = false + nixos-rebuild switch).
#   8. Does NOT delete the generated CA itself (lives in /nix/store; it's
#      regenerated on every rebuild anyway).
#
# Substituted at build time:
#   @HOSTNAME@         — VPN gateway hostname (e.g. pcs.flxvpn.net)
#   @PROXY_PORT@       — local proxy listen port (e.g. 8443)
#   @NM_CONNECTION@    — NetworkManager VPN connection ID (e.g. "Netflix VPN")
#   @TRUST_BIN@        — path to pulse-browser-auth-trust binary
#   @IPTABLES@         — path to iptables
#   @NMCLI@            — path to nmcli
#   @JQ@               — path to jq (optional; HSTS scrub is skipped if missing)

set -u

HOSTNAME="@HOSTNAME@"
PROXY_PORT="@PROXY_PORT@"
NM_CONNECTION="@NM_CONNECTION@"
TRUST_BIN="@TRUST_BIN@"
IPTABLES="@IPTABLES@"
NMCLI="@NMCLI@"
JQ="@JQ@"

# Get root once up front. The iptables-NAT cleanup and the daemon kill both
# need it, and asking the user to type the password three times is annoying.
# If the script is already root, this is a no-op.
if (( EUID != 0 )); then
    if ! sudo -v 2>/dev/null; then
        printf '\033[1;33m! sudo authentication failed or was cancelled — \
some steps will be skipped\033[0m\n'
    fi
fi

# --- pretty -----------------------------------------------------------------

section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
ok()      { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
warn()    { printf '  \033[1;33m!\033[0m %s\n' "$1"; }
err()     { printf '  \033[1;31m✗\033[0m %s\n' "$1" >&2; }
info()    { printf '    %s\n' "$1"; }

# --- 1. stray proxy processes ----------------------------------------------

section "Stray proxy processes"
# Match either the bin wrapper name or the underlying script. We want to be
# precise — DON'T match anything else with "proxy" in the name (sbn-dev-agent
# has its own mtls-proxy, NetworkManager has DNS proxies, etc.).
mapfile -t pids < <(pgrep -fa 'pulse-browser-proxy|browser-auth/proxy\.py|nm-pulse-sso-browser-auth.*proxy' 2>/dev/null | awk '{print $1}')
if (( ${#pids[@]} == 0 )); then
    ok "no stray proxy processes"
else
    for p in "${pids[@]}"; do
        if kill "$p" 2>/dev/null; then
            ok "killed PID $p"
        else
            warn "could not kill PID $p (maybe owned by root?)"
        fi
    done
    # Brief grace period, then SIGKILL anything that didn't go.
    sleep 0.3
    for p in "${pids[@]}"; do
        if kill -0 "$p" 2>/dev/null; then
            kill -9 "$p" 2>/dev/null && warn "SIGKILL'd PID $p"
        fi
    done
fi

# Also catch a port-bound zombie that lost its pgrep signature.
if command -v ss >/dev/null 2>&1; then
    bound=$(ss -tlnp 2>/dev/null | grep ":${PROXY_PORT} " || true)
    if [[ -n "$bound" ]]; then
        warn "something is still bound to :${PROXY_PORT}"
        info "$bound"
    fi
fi

# --- 1b. nm-pulse-sso D-Bus daemon ----------------------------------------

section "nm-pulse-sso D-Bus daemon"
# The service is a long-lived child of NetworkManager. It caches the last
# valid cookie in self.cookie, so even after we wipe NM's stored secrets it
# will happily reuse the bad cookie on the next Connect, causing an instant
# 'openconnect exited with code 1' death spiral. Kill it; NM will respawn it
# via D-Bus activation on the next Connect call, with empty state.
mapfile -t svc_pids < <(pgrep -f 'nm-pulse-sso-service' 2>/dev/null || true)
if (( ${#svc_pids[@]} == 0 )); then
    ok "daemon not running (will start fresh on next Connect)"
else
    for p in "${svc_pids[@]}"; do
        # Owned by root, so SIGTERM needs sudo.
        if sudo -n kill "$p" 2>/dev/null; then
            ok "sent SIGTERM to nm-pulse-sso-service PID $p"
        elif kill "$p" 2>/dev/null; then
            ok "sent SIGTERM to nm-pulse-sso-service PID $p (no sudo needed)"
        else
            warn "could not signal PID $p — daemon may keep stale cookie cached"
            info "workaround: sudo systemctl restart NetworkManager"
        fi
    done
fi

# --- 2. temp DSID files ----------------------------------------------------

section "Temp DSID result + log files"
shopt -s nullglob
tmp_files=( /tmp/pulse-dsid-*.json /tmp/pulse-dsid-*.log )
shopt -u nullglob
if (( ${#tmp_files[@]} == 0 )); then
    ok "none present"
else
    for f in "${tmp_files[@]}"; do
        rm -f "$f" && ok "removed $f"
    done
fi

# --- 3. iptables NAT redirect ----------------------------------------------

section "NAT redirect for browser-auth proxy"
# The redirect rule is owned by the systemd oneshot
# nm-pulse-sso-browser-auth-redirect.service. Manually 'iptables -D'ing the
# rule out from under it leaves systemd thinking the unit is still active
# while the rule is gone — the browser then gets ECONNREFUSED on its first
# request and the whole flow stalls. We instead just RESTART the unit,
# which runs ExecStop (delete) + ExecStart (re-add) cleanly.
#
# When browser-auth is disabled, the unit won't exist; in that case fall
# back to stripping any leftover rule by hand (rare — only if a previous
# rebuild left junk behind).
UNIT="nm-pulse-sso-browser-auth-redirect.service"
if systemctl cat "$UNIT" >/dev/null 2>&1; then
    # Unit exists — browser-auth is enabled in the current generation.
    if systemctl is-active --quiet "$UNIT"; then
        if sudo -n systemctl restart "$UNIT" 2>/dev/null \
               || sudo systemctl restart "$UNIT"; then
            ok "restarted $UNIT (rule freshly re-applied)"
        else
            warn "could not restart $UNIT — redirect may be stale"
        fi
    else
        if sudo -n systemctl start "$UNIT" 2>/dev/null \
               || sudo systemctl start "$UNIT"; then
            ok "started $UNIT"
        else
            warn "could not start $UNIT"
        fi
    fi
elif [[ -x "$IPTABLES" ]]; then
    # No systemd unit — browser-auth is disabled. Strip any leftover rule
    # so we don't poison the loopback path for the CEF flow.
    if ! sudo -n true 2>/dev/null && (( EUID != 0 )); then
        sudo -v 2>/dev/null || true
    fi
    if sudo -n true 2>/dev/null || (( EUID == 0 )); then
        removed=0
        while sudo -n "$IPTABLES" -t nat -C OUTPUT -d 127.0.0.1/32 -p tcp \
            --dport 443 -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null; do
            sudo -n "$IPTABLES" -t nat -D OUTPUT -d 127.0.0.1/32 -p tcp \
                --dport 443 -j REDIRECT --to-ports "$PROXY_PORT"
            removed=$((removed + 1))
        done
        if (( removed > 0 )); then
            ok "removed $removed leftover rule(s) from a previous build"
        else
            ok "no leftover rules"
        fi
    else
        warn "no sudo — skipping leftover-rule check"
    fi
else
    warn "iptables not available — skipping"
fi

# --- 4. cached cookie on the NM VPN connection -----------------------------

section "Active VPN session"
# If the connection is currently up (or stuck "Activating"), tear it down
# so the death-spiral retry loop in the service exits cleanly. Without this
# the next Connect from the user gets D-Bus-merged with a pending request
# and re-uses the same in-memory state we just killed.
if [[ -x "$NMCLI" ]]; then
    active=$("$NMCLI" -t -f NAME connection show --active 2>/dev/null \
             | grep -Fx "$NM_CONNECTION" || true)
    if [[ -n "$active" ]]; then
        if "$NMCLI" connection down "$NM_CONNECTION" >/dev/null 2>&1; then
            ok "brought down active '$NM_CONNECTION' session"
        else
            warn "could not deactivate '$NM_CONNECTION' — may already be down"
        fi
    else
        ok "no active '$NM_CONNECTION' session"
    fi
fi

section "NetworkManager cached cookie"
if [[ -x "$NMCLI" ]] && "$NMCLI" -t -f NAME connection show 2>/dev/null \
    | grep -Fxq "$NM_CONNECTION"; then
    # nmcli writes secrets to a root-owned keyring file. We don't need sudo
    # to clear them — the modify operates via D-Bus and we own the connection
    # if we created it (which is the common case on a developer machine).
    if "$NMCLI" connection modify "$NM_CONNECTION" \
        -vpn.secrets cookie -vpn.secrets gwcert -vpn.secrets resolve 2>/dev/null; then
        ok "cleared cached vpn.secrets (cookie, gwcert, resolve) on '$NM_CONNECTION'"
    else
        # Some NM versions don't support the -vpn.secrets remove syntax; fall
        # back to setting the secrets to empty strings.
        if "$NMCLI" connection modify "$NM_CONNECTION" \
            vpn.secrets cookie='' vpn.secrets gwcert='' vpn.secrets resolve='' 2>/dev/null; then
            ok "blanked vpn.secrets on '$NM_CONNECTION'"
        else
            warn "could not clear cached vpn.secrets — try via nm-connection-editor"
        fi
    fi
else
    warn "NM connection '$NM_CONNECTION' not found — skipping"
fi

# --- 5. CA trust uninstall -------------------------------------------------

section "CA trust"
if [[ -x "$TRUST_BIN" ]]; then
    "$TRUST_BIN" uninstall || warn "trust uninstall returned non-zero"
else
    warn "trust binary not on PATH ($TRUST_BIN)"
    info "is enableDesktopBrowserAuth = true in your config?"
fi

# --- 6. Chrome HSTS scrub --------------------------------------------------

section "Browser HSTS pin"
# HSTS is stored per-profile in TransportSecurity (a JSON file in each
# Chromium-family profile). We can't programmatically clear just one host on
# a running browser — the file is rewritten when Chrome shuts down. So:
#   * If browser process is running → tell the user, do nothing destructive.
#   * Else, parse-and-rewrite the JSON to drop the gateway entry.
#
# Hostname is stored hashed (HMAC-SHA-256 with a zero-byte key, base64'd) so
# we have to enumerate every entry and compare against the precomputed hash.

if [[ -z "$JQ" || ! -x "$JQ" ]]; then
    warn "jq not available — skipping HSTS file scrub"
    info "to clear manually: open chrome://net-internals/#hsts → Delete domain security policies → $HOSTNAME"
else
    # Compute the hashed host the way Chromium stores it.
    HASHED_HOST=$(printf '%s' "$HOSTNAME" \
        | openssl dgst -sha256 -binary 2>/dev/null \
        | openssl base64 2>/dev/null \
        | tr -d '\n' || true)

    # Chromium variants we know about. Add more as needed.
    profile_globs=(
        "$HOME/.config/google-chrome/*/TransportSecurity"
        "$HOME/.config/chromium/*/TransportSecurity"
        "$HOME/.config/BraveSoftware/Brave-Browser/*/TransportSecurity"
        "$HOME/.config/microsoft-edge/*/TransportSecurity"
        "$HOME/.config/vivaldi/*/TransportSecurity"
    )

    scrubbed=0
    skipped_running=0
    for glob in "${profile_globs[@]}"; do
        # shellcheck disable=SC2206
        files=( $glob )
        for f in "${files[@]}"; do
            [[ -f "$f" ]] || continue
            browser_dir=$(dirname "$(dirname "$f")")
            browser_name=$(basename "$browser_dir")
            # If the browser owning this profile is running, skip — Chromium
            # rewrites the file on shutdown and would clobber our edit.
            if pgrep -f "$browser_dir" >/dev/null 2>&1; then
                warn "$browser_name is running — close it, then re-run this script"
                skipped_running=$((skipped_running + 1))
                continue
            fi
            # The file may not have our exact hashed_host as a key. Only
            # rewrite if it does, to keep mtime stable in the common case.
            if "$JQ" -e --arg h "$HASHED_HOST" 'has("sts") and (.sts | has($h))' \
                "$f" >/dev/null 2>&1; then
                tmp=$(mktemp)
                "$JQ" --arg h "$HASHED_HOST" 'del(.sts[$h])' "$f" >"$tmp" \
                    && mv "$tmp" "$f" \
                    && { ok "scrubbed $f"; scrubbed=$((scrubbed + 1)); } \
                    || { rm -f "$tmp"; err "failed to scrub $f"; }
            fi
        done
    done

    if (( scrubbed == 0 && skipped_running == 0 )); then
        ok "no profile contained an HSTS pin for $HOSTNAME"
    fi
fi

# --- 7. /etc/hosts note ----------------------------------------------------

section "/etc/hosts"
if grep -qE "^[[:space:]]*127\.0\.0\.1[[:space:]]+(\S+\s+)*${HOSTNAME}(\s|$)" /etc/hosts; then
    warn "/etc/hosts still maps $HOSTNAME → 127.0.0.1"
    info "this is managed by networking.extraHosts (enableDesktopBrowserAuth = true)"
    info "to remove: set enableDesktopBrowserAuth = false and 'sudo nixos-rebuild switch'"
else
    ok "no $HOSTNAME override present"
fi

# --- summary ---------------------------------------------------------------

echo
section "Done"
info "If anything reported warnings above, address it before retrying auth."
info ""
info "On NixOS, the local CA from security.pki.certificateFiles is exposed"
info "to Chromium/Chrome through p11-kit, so an explicit per-user trust"
info "install is usually NOT required. Run pulse-browser-auth-trust install"
info "only if you hit either of these in your browser:"
info "  * NET::ERR_CERT_AUTHORITY_INVALID with no 'Advanced' bypass option"
info "  * An HSTS-pinned domain refusing to let you click through"
info "Restart the browser (full quit) after any trust change."

log_dir_msg=""
shopt -s nullglob
any_logs=( /tmp/pulse-dsid-*.log )
shopt -u nullglob
if (( ${#any_logs[@]} > 0 )); then
    log_dir_msg=" (and inspect /tmp/pulse-dsid-*.log for the wire trace)"
fi
info ""
info "After re-attempting auth, run diagnose-pulse-browser-auth${log_dir_msg}."

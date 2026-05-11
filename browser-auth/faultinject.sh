#!/usr/bin/env bash
# Fault-injection harness for the nm-pulse-sso browser-auth backend.
#
# Each subcommand simulates a real-world failure so we can validate the
# recovery / reconnect logic without waiting for the real event to occur
# (server-side cookie expiry, laptop suspend, network flap, etc.).
#
# Intentionally narrates everything it does and points at the right journal
# stream to watch — the goal is observability of automated tests, not silent
# automation.
#
# Substituted at build time:
#   @NMCLI@         — path to nmcli
#   @JOURNALCTL@    — path to journalctl
#   @NM_CONNECTION@ — NetworkManager VPN connection id
#   @VPN_RECONNECT_UNIT@ — systemd unit fired on resume (vpn-reconnect.service)

set -u

NMCLI="@NMCLI@"
JOURNALCTL="@JOURNALCTL@"
NM_CONNECTION="@NM_CONNECTION@"
VPN_RECONNECT_UNIT="@VPN_RECONNECT_UNIT@"

# --- pretty -----------------------------------------------------------------

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
say()   { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()    { printf '  \033[1;32m\u2713\033[0m %s\n' "$*"; }
warn()  { printf '  \033[1;33m!\033[0m %s\n' "$*"; }
err()   { printf '  \033[1;31m\u2717\033[0m %s\n' "$*" >&2; }
hint()  { printf '    %s\n' "$*"; }

# --- helpers ----------------------------------------------------------------

require_sudo() {
    if (( EUID != 0 )) && ! sudo -n true 2>/dev/null; then
        sudo -v 2>/dev/null || {
            err "sudo required for this subcommand"
            exit 1
        }
    fi
}

journal_tip() {
    hint "watch with:  $JOURNALCTL -fu NetworkManager | grep -iE 'nm-pulse-sso|openconnect|browser-auth|proxy' | grep -v DSLastAccess"
}

current_state() {
    local state
    state=$("$NMCLI" -t -f NAME,STATE connection show --active 2>/dev/null \
            | awk -F: -v c="$NM_CONNECTION" '$1==c {print $2}')
    printf '%s' "${state:-inactive}"
}

# --- subcommands ------------------------------------------------------------

cmd_help() {
    cat <<EOF
$(bold "pulse-browser-auth-faultinject") — fault-injection harness

Simulates failure modes for the browser-auth backend so reconnect logic
can be exercised without waiting for real-world events. Run alongside:

  $JOURNALCTL -fu NetworkManager

$(bold "Subcommands")
  kill-openconnect       SIGKILL openconnect; simulates ungraceful tunnel death.
                         Expect: nm-pulse-sso schedules re-activation with the
                         cached cookie; succeeds within ~10s.
  kill-proxy             SIGKILL the MITM proxy mid-auth (run while auth-dialog
                         is open). Expect: auth-dialog reports failure, NM
                         re-launches it on the next attempt.
  kill-daemon            SIGTERM the nm-pulse-sso-service D-Bus daemon.
                         Expect: NM re-activates it on the next Connect with
                         empty in-memory state. Useful to repro the cached-
                         cookie death-spiral bug we just fixed.
  invalidate-cookie      Drop the NM-stored cookie AND kill the daemon, forcing
                         a fresh auth-dialog on the next Connect. Simulates a
                         server-side DSID expiry.
  expire-now             nmcli connection down + invalidate-cookie + up,
                         end-to-end re-auth round-trip in one command.
  simulate-resume        Fire \$VPN_RECONNECT_UNIT (the dispatcher path that
                         runs after the laptop wakes from suspend) WITHOUT
                         actually suspending. Validates that post-resume
                         tunnel rebuild works.
  flap-tunnel            Bring VPN down via nmcli; bring it back up after 5s.
                         Tests fast disconnect/reconnect race conditions.
  soak [N=3]             Run N expire-now cycles back-to-back. Catches state
                         leaks (eg the self.cookie / self.resolve caches that
                         caused the death-spiral). Reports cycle outcomes.
  status                 Print current VPN + backend state, running processes,
                         and iptables/hosts plumbing.
  watch                  Tail relevant journal lines (Ctrl-C to exit).
  help                   This message.

$(bold "Examples")
  # Terminal 1 \u2014 watch what happens
  pulse-browser-auth-faultinject watch

  # Terminal 2 \u2014 trigger faults
  pulse-browser-auth-faultinject kill-openconnect
  pulse-browser-auth-faultinject expire-now
  pulse-browser-auth-faultinject soak 5
EOF
}

cmd_kill_openconnect() {
    local pid
    pid=$(pgrep -x openconnect 2>/dev/null | head -1)
    if [[ -z "$pid" ]]; then
        warn "no openconnect process running"
        hint "bring VPN up first:  nmcli connection up '$NM_CONNECTION'"
        return 1
    fi
    say "current VPN state: $(current_state)"
    say "SIGKILL openconnect PID $pid"
    require_sudo
    sudo kill -9 "$pid"
    ok "killed"
    say "expected next: 'openconnect exited with code -9' \u2192 schedule re-activation \u2192 reconnect with cached cookie"
    journal_tip
}

cmd_kill_proxy() {
    mapfile -t pids < <(pgrep -fa 'pulse-browser-proxy|browser-auth/proxy\.py' 2>/dev/null | awk '{print $1}')
    if (( ${#pids[@]} == 0 )); then
        warn "no proxy process running"
        hint "the proxy only runs DURING an auth flow \u2014 trigger one with:"
        hint "  $NMCLI connection up '$NM_CONNECTION'"
        hint "then run this subcommand within ~30s while the browser is open"
        return 1
    fi
    say "SIGKILL proxy PIDs: ${pids[*]}"
    for p in "${pids[@]}"; do
        kill -9 "$p" 2>/dev/null && ok "killed $p"
    done
    say "expected next: auth-dialog exits with error \u2192 NM retries / surfaces failure"
    journal_tip
}

cmd_kill_daemon() {
    mapfile -t pids < <(pgrep -f nm-pulse-sso-service 2>/dev/null)
    if (( ${#pids[@]} == 0 )); then
        warn "daemon not running (will spawn fresh on next Connect)"
        return 0
    fi
    say "SIGTERM nm-pulse-sso-service PIDs: ${pids[*]}"
    require_sudo
    for p in "${pids[@]}"; do
        sudo kill "$p" 2>/dev/null && ok "killed $p"
    done
    say "expected next: NM respawns daemon via D-Bus activation on next Connect"
    hint "trigger with:  $NMCLI connection up '$NM_CONNECTION'"
    journal_tip
}

cmd_invalidate_cookie() {
    say "clearing NM-stored vpn.secrets on '$NM_CONNECTION'"
    if "$NMCLI" connection modify "$NM_CONNECTION" \
            -vpn.secrets cookie -vpn.secrets gwcert -vpn.secrets resolve \
            2>/dev/null; then
        ok "cookie / gwcert / resolve cleared"
    else
        "$NMCLI" connection modify "$NM_CONNECTION" \
            vpn.secrets cookie='' vpn.secrets gwcert='' vpn.secrets resolve='' \
            2>/dev/null \
            && ok "blanked secrets (fallback)" \
            || warn "could not clear secrets"
    fi
    cmd_kill_daemon || true
    say "expected next Connect: full auth-dialog run, browser will open"
}

cmd_expire_now() {
    say "phase 1: bring '$NM_CONNECTION' down (if active)"
    if [[ "$(current_state)" == "activated" ]]; then
        "$NMCLI" connection down "$NM_CONNECTION" >/dev/null 2>&1 \
            && ok "down" || warn "could not deactivate"
    else
        ok "already inactive"
    fi
    say "phase 2: invalidate"
    cmd_invalidate_cookie
    say "phase 3: bring back up"
    if "$NMCLI" connection up "$NM_CONNECTION"; then
        ok "VPN re-activated (state: $(current_state))"
    else
        err "re-activation failed"
        return 1
    fi
}

cmd_simulate_resume() {
    if ! systemctl cat "$VPN_RECONNECT_UNIT" >/dev/null 2>&1; then
        err "$VPN_RECONNECT_UNIT not found on this system"
        hint "this hook is only configured when the vpn-reconnect unit is enabled"
        return 1
    fi
    say "firing $VPN_RECONNECT_UNIT (no actual suspend)"
    require_sudo
    if sudo systemctl start "$VPN_RECONNECT_UNIT"; then
        ok "unit fired"
    else
        err "systemctl start failed"
        return 1
    fi
    say "expected: post-resume reconnect path executes; openconnect rebuilds tunnel"
    journal_tip
}

cmd_flap_tunnel() {
    if [[ "$(current_state)" != "activated" ]]; then
        warn "VPN is not active \u2014 bring it up first"
        return 1
    fi
    say "down '$NM_CONNECTION'"
    "$NMCLI" connection down "$NM_CONNECTION" >/dev/null 2>&1 \
        && ok "down" || warn "down failed"
    say "sleeping 5s"
    sleep 5
    say "up '$NM_CONNECTION'"
    if "$NMCLI" connection up "$NM_CONNECTION"; then
        ok "up (state: $(current_state))"
    else
        err "up failed"
        return 1
    fi
}

cmd_soak() {
    local n="${1:-3}"
    local pass=0 fail=0
    say "soak test: $n expire-now cycles"
    for i in $(seq 1 "$n"); do
        printf '\n\033[1;35m\u2014\u2014\u2014 cycle %d/%d \u2014\u2014\u2014\033[0m\n' "$i" "$n"
        if cmd_expire_now; then
            pass=$((pass + 1))
            ok "cycle $i: pass"
        else
            fail=$((fail + 1))
            err "cycle $i: FAIL"
        fi
        sleep 3
    done
    echo
    bold "Soak summary"
    printf '  passed: %d / %d\n  failed: %d / %d\n' "$pass" "$n" "$fail" "$n"
    (( fail == 0 ))
}

cmd_status() {
    bold "VPN connection state"
    "$NMCLI" -t -f NAME,STATE,TYPE connection show --active 2>/dev/null \
        | awk -F: -v c="$NM_CONNECTION" '$1==c {printf "  %-20s %s (%s)\n", $1, $2, $3}' \
        || printf '  %s: inactive\n' "$NM_CONNECTION"
    echo
    bold "Running processes"
    for pat in 'openconnect' 'nm-pulse-sso-service' 'pulse-browser-proxy|browser-auth/proxy\.py'; do
        mapfile -t hits < <(pgrep -fa "$pat" 2>/dev/null)
        if (( ${#hits[@]} == 0 )); then
            printf '  %-30s (none)\n' "$pat"
        else
            for h in "${hits[@]}"; do
                printf '  %-30s %s\n' "$pat" "$h"
            done
        fi
    done
    echo
    bold "browser-auth plumbing"
    if systemctl is-active --quiet nm-pulse-sso-browser-auth-redirect.service 2>/dev/null; then
        ok "NAT redirect unit is active"
    else
        warn "NAT redirect unit is not active (browser-auth backend not enabled?)"
    fi
    if grep -qE '127\.0\.0\.1.*pcs\.flxvpn' /etc/hosts 2>/dev/null; then
        ok "/etc/hosts has pcs.flxvpn.net \u2192 127.0.0.1 override"
    else
        warn "/etc/hosts has no pcs.flxvpn.net override"
    fi
    echo
    bold "Daemon in-memory cookie?"
    # We can't directly inspect the daemon's memory, but we CAN see whether NM
    # has a secret cached for the connection. That's our best proxy.
    if "$NMCLI" -t -f vpn.secrets connection show "$NM_CONNECTION" 2>/dev/null \
            | grep -q 'cookie'; then
        ok "NM has cached cookie for $NM_CONNECTION"
    else
        warn "NM has no cached cookie \u2014 next Connect will trigger fresh auth"
    fi
}

cmd_watch() {
    say "tailing NM journal (Ctrl-C to exit)"
    exec "$JOURNALCTL" -fu NetworkManager \
        | grep --line-buffered -iE 'nm-pulse-sso|openconnect|browser-auth|proxy|auth-dialog' \
        | grep --line-buffered -vE 'DSLastAccess|dbus\.Struct|dbus\.Dictionary'
}

# --- dispatch ---------------------------------------------------------------

sub="${1:-help}"; shift || true
case "$sub" in
    kill-openconnect)   cmd_kill_openconnect   "$@";;
    kill-proxy)         cmd_kill_proxy         "$@";;
    kill-daemon)        cmd_kill_daemon        "$@";;
    invalidate-cookie)  cmd_invalidate_cookie  "$@";;
    expire-now)         cmd_expire_now         "$@";;
    simulate-resume)    cmd_simulate_resume    "$@";;
    flap-tunnel)        cmd_flap_tunnel        "$@";;
    soak)               cmd_soak               "$@";;
    status)             cmd_status             "$@";;
    watch)              cmd_watch              "$@";;
    help|-h|--help)     cmd_help;;
    *)                  err "unknown subcommand: $sub"; echo; cmd_help; exit 2;;
esac

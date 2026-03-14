#!/bin/sh
#
# VPN Resume Handler for nm-openconnect-pulse-sso
#
# Called by systemd after system resume (post-resume.target).
# Kills stale openconnect process and triggers auto-reconnect service.
#
# After suspend, the VPN tunnel is dead but the openconnect process may
# still be running. We kill it and let the external auto-reconnect service
# handle re-establishing the VPN via nmcli.

# Kill stale openconnect (tunnel is dead after suspend anyway)
if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
    echo "Killing stale openconnect after resume"
    @procps@/bin/pkill -x openconnect || true
    sleep 2
    # SIGKILL fallback — openconnect in DTLS/ESP mode may ignore SIGTERM
    if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
        echo "openconnect did not respond to SIGTERM, sending SIGKILL"
        @procps@/bin/pkill -9 -x openconnect 2>/dev/null || true
    fi
fi

# Trigger auto-reconnect service (runs asynchronously with retries)
@systemd@/bin/systemctl start --no-block vpn-auto-reconnect.service 2>/dev/null || true

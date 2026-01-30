#!/bin/sh
#
# VPN Reconnect Script for nm-openconnect-pulse-sso
#
# Called by systemd after system resume (post-resume.target).
# Properly cycles the VPN connection through NetworkManager to ensure
# fresh routes are used after network changes.

# Wait for network to be actually online (not just carrier)
# After resume, WiFi may take several seconds to fully reconnect and get DHCP
MAX_WAIT=30
WAITED=0
echo "Waiting for network connectivity..."
while [ $WAITED -lt $MAX_WAIT ]; do
    # Check if we can resolve DNS (network is really working)
    if @dnsutils@/bin/dig +short +timeout=1 google.com >/dev/null 2>&1; then
        echo "Network is online after ${WAITED}s"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "Network not online after ${MAX_WAIT}s, proceeding anyway"
fi

# Get the active VPN connection UUID (more reliable than name which may have duplicates)
VPN_INFO=$(@networkmanager@/bin/nmcli -t -f NAME,UUID,TYPE connection show --active 2>/dev/null | @gnugrep@/bin/grep ':vpn$')
VPN_NAME=$(echo "$VPN_INFO" | @coreutils@/bin/cut -d: -f1)
VPN_UUID=$(echo "$VPN_INFO" | @coreutils@/bin/cut -d: -f2)

if [ -n "$VPN_UUID" ]; then
    echo "Cycling VPN connection: $VPN_NAME ($VPN_UUID)"

    # Disconnect VPN - this clears NM's cached routes
    @networkmanager@/bin/nmcli connection down uuid "$VPN_UUID" 2>/dev/null || true
    echo "VPN disconnected"

    sleep 2

    # Reconnect VPN using UUID to avoid ambiguity with duplicate names
    # Don't run in background - wait for result so we can log errors
    if @networkmanager@/bin/nmcli connection up uuid "$VPN_UUID" 2>&1; then
        echo "VPN reconnection successful"
    else
        echo "VPN reconnection failed"
    fi
else
    echo "No active VPN connection found, nothing to do"
fi

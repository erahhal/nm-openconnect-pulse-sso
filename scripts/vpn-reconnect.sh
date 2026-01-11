#!/bin/sh
#
# VPN Reconnect Script for nm-openconnect-pulse-sso
#
# Called by systemd after system resume (post-resume.target).
# Fixes routes and triggers openconnect reconnection.
#
# With DTLS disabled: Uses SIGUSR2 for graceful reconnection
# With DTLS enabled: Uses SIGTERM for full restart (ESP reconnect is broken upstream)

# Read DTLS configuration
ENABLE_DTLS="true"
if [ -f /etc/nm-pulse-sso/config ]; then
    . /etc/nm-pulse-sso/config 2>/dev/null || true
fi

# Wait for network to stabilize after resume
sleep 3

# Fix route to VPN server when network interface changes
# The VPN server must be reachable via physical interface, not tun0
# Get VPN server IP from openconnect's command line
VPN_SERVER=$(@procps@/bin/ps aux | grep '[o]penconnect' | grep -oP 'https://\K[^/]+' | head -1)
if [ -n "$VPN_SERVER" ]; then
    # Resolve VPN server IP - filter dig output to only accept valid IPv4 addresses
    VPN_IP=$(@dnsutils@/bin/dig +short +timeout=2 "$VPN_SERVER" 2>&1 | @gnugrep@/bin/grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -n "$VPN_IP" ]; then
        # Find a physical interface that has carrier (is actually connected)
        # Check each non-tun default route's interface for carrier
        FOUND_ROUTE=0
        for route_line in $(@iproute2@/bin/ip route show default | grep -v tun); do
            DEV=$(echo "$route_line" | @gawk@/bin/awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
            GW=$(echo "$route_line" | @gawk@/bin/awk '{print $3}')

            # Check if interface has carrier (cable plugged in / wifi connected)
            if [ -f "/sys/class/net/$DEV/carrier" ]; then
                CARRIER=$(cat "/sys/class/net/$DEV/carrier" 2>/dev/null || echo "0")
                if [ "$CARRIER" = "1" ]; then
                    echo "Found active interface $DEV with gateway $GW"
                    # Remove old routes and add new one via active interface
                    @iproute2@/bin/ip route del "$VPN_IP" 2>/dev/null || true
                    @iproute2@/bin/ip route add "$VPN_IP" via "$GW" dev "$DEV" 2>/dev/null || true
                    echo "Updated route to VPN server $VPN_IP via $GW dev $DEV"
                    FOUND_ROUTE=1
                    break
                fi
            fi
        done

        if [ "$FOUND_ROUTE" = "0" ]; then
            echo "No active physical interface found for VPN route"
        fi
    fi
fi

# Find openconnect PID and trigger reconnection
OPENCONNECT_PID=$(@procps@/bin/pgrep -x openconnect)

if [ -n "$OPENCONNECT_PID" ]; then
    if [ "$ENABLE_DTLS" = "true" ]; then
        # DTLS enabled: Use SIGTERM for full restart (ESP reconnect is broken upstream)
        # The VPN service will auto-restart with the existing cookie
        # Note: openconnect in DTLS/ESP mode may ignore SIGTERM, so we escalate to SIGKILL
        echo "Sending SIGTERM to openconnect (PID: $OPENCONNECT_PID) for full restart (DTLS mode)"
        kill -TERM "$OPENCONNECT_PID"
        # Wait up to 5 seconds for graceful exit, then force kill
        for i in 1 2 3 4 5; do
            sleep 1
            if ! kill -0 "$OPENCONNECT_PID" 2>/dev/null; then
                echo "openconnect exited after SIGTERM"
                break
            fi
            if [ "$i" = "5" ]; then
                echo "openconnect did not respond to SIGTERM, sending SIGKILL"
                kill -9 "$OPENCONNECT_PID" 2>/dev/null || true
            fi
        done
    else
        # DTLS disabled: Use SIGUSR2 for graceful reconnection (SSL-only mode)
        echo "Sending SIGUSR2 to openconnect (PID: $OPENCONNECT_PID) to force reconnection"
        kill -USR2 "$OPENCONNECT_PID"
    fi
else
    echo "No openconnect process found, skipping reconnection"
fi

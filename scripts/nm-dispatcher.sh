#!/bin/sh
#
# NetworkManager Dispatcher Script (90-vpn-reconnect)
#
# Fixes VPN route and triggers reconnection when network interface changes.
# Handles connectivity-change and down events for physical interfaces.

# Read DTLS configuration
ENABLE_DTLS="true"
if [ -f /etc/nm-pulse-sso/config ]; then
    . /etc/nm-pulse-sso/config 2>/dev/null || true
fi

# Act on interface events for physical interfaces
IFACE="$1"
ACTION="$2"

case "$ACTION" in
    connectivity-change|down)
        ;;
    *)
        exit 0
        ;;
esac

# Skip connectivity-change events with no interface (typically VPN establishment)
# These fire when the VPN tunnel comes up, which would kill openconnect right after connecting
if [ -z "$IFACE" ] && [ "$ACTION" = "connectivity-change" ]; then
    exit 0
fi

case "$IFACE" in
    tun*|tap*|lo|docker*|br-*|veth*)
        exit 0
        ;;
esac

# Check if openconnect is running
OPENCONNECT_PID=$(@procps@/bin/pgrep -x openconnect)
if [ -z "$OPENCONNECT_PID" ]; then
    exit 0
fi

echo "NetworkManager: Interface $IFACE action $ACTION - checking VPN route"

# Get VPN server from openconnect command line
VPN_SERVER=$(@procps@/bin/ps aux | grep '[o]penconnect' | grep -oP 'https://\K[^/]+' | head -1)
if [ -z "$VPN_SERVER" ]; then
    exit 0
fi

# Resolve VPN server IP via DNS with retry
VPN_IP=""
for i in $(@coreutils@/bin/seq 1 30); do
    VPN_IP=$(@dnsutils@/bin/dig +short +timeout=2 "$VPN_SERVER" 2>&1 | @gnugrep@/bin/grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -n "$VPN_IP" ]; then
        echo "Resolved VPN server $VPN_SERVER to $VPN_IP after $i attempt(s)"
        break
    fi
    echo "DNS resolution failed for $VPN_SERVER, retrying... ($i/30)"
    sleep 1
done

if [ -z "$VPN_IP" ]; then
    echo "Failed to determine VPN server IP - giving up"
    exit 0
fi

# Find interface with carrier that has a default route
if [ "$ACTION" = "down" ] || [ "$ACTION" = "connectivity-change" ] || [ -z "$IFACE" ]; then
    TARGET_DEV=""
    TARGET_GW=""
    for dev in $(ls /sys/class/net/ | grep -v -E "^(lo|tun|tap|docker|br-|veth)"); do
        if [ -f "/sys/class/net/$dev/carrier" ]; then
            CARRIER=$(cat "/sys/class/net/$dev/carrier" 2>/dev/null || echo "0")
            if [ "$CARRIER" = "1" ] && [ "$dev" != "$IFACE" ]; then
                for i in $(@coreutils@/bin/seq 1 30); do
                    GW=$(@iproute2@/bin/ip route show default dev "$dev" 2>/dev/null | @gawk@/bin/awk '{print $3}' | head -1)
                    if [ -n "$GW" ]; then
                        TARGET_DEV="$dev"
                        TARGET_GW="$GW"
                        echo "Found active interface $TARGET_DEV with gateway $TARGET_GW after $i second(s)"
                        break 2
                    fi
                    echo "Waiting for gateway on $dev... ($i/30)"
                    sleep 1
                done
            fi
        fi
    done
else
    TARGET_DEV="$IFACE"
    TARGET_GW=""
    for i in $(@coreutils@/bin/seq 1 30); do
        TARGET_GW=$(@iproute2@/bin/ip route show default dev "$IFACE" 2>/dev/null | @gawk@/bin/awk '{print $3}' | head -1)
        if [ -n "$TARGET_GW" ]; then
            echo "Found gateway $TARGET_GW for $IFACE after $i second(s)"
            break
        fi
        echo "Waiting for gateway on $IFACE... ($i/30)"
        sleep 1
    done
fi

if [ -n "$TARGET_GW" ] && [ -n "$TARGET_DEV" ]; then
    @iproute2@/bin/ip route del "$VPN_IP" 2>/dev/null || true
    echo "Updating route to VPN server $VPN_IP via $TARGET_GW dev $TARGET_DEV"
    @iproute2@/bin/ip route add "$VPN_IP" via "$TARGET_GW" dev "$TARGET_DEV" 2>/dev/null || true

    sleep 1
    if [ "$ENABLE_DTLS" = "true" ]; then
        echo "Sending SIGTERM to openconnect (PID: $OPENCONNECT_PID) for full restart (DTLS mode)"
        kill -TERM "$OPENCONNECT_PID"
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
        echo "Sending SIGUSR2 to openconnect (PID: $OPENCONNECT_PID) to force reconnection"
        kill -USR2 "$OPENCONNECT_PID"
    fi
else
    echo "No suitable gateway/interface found"
fi

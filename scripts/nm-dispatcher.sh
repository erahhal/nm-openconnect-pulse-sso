#!/bin/sh
#
# NetworkManager Dispatcher Script (90-vpn-reconnect)
#
# Fixes VPN route and triggers reconnection when network interface changes.
# Handles connectivity-change and down events for physical interfaces.

# Log to both stdout and syslog for debugging
log_msg() {
    echo "$1"
    logger -t "90-vpn-reconnect" "$1"
}

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

log_msg "Interface $IFACE action $ACTION - checking VPN route"

# Get VPN server from openconnect command line
VPN_SERVER=$(@procps@/bin/ps aux | grep '[o]penconnect' | grep -oP 'https://\K[^/]+' | head -1)
if [ -z "$VPN_SERVER" ]; then
    exit 0
fi

# Find interface with carrier that has a default route
# We need the gateway first to use it as DNS server for resolving the VPN hostname
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
                        log_msg "Found active interface $TARGET_DEV with gateway $TARGET_GW after $i second(s)"
                        break 2
                    fi
                    log_msg "Waiting for gateway on $dev... ($i/30)"
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
            log_msg "Found gateway $TARGET_GW for $IFACE after $i second(s)"
            break
        fi
        log_msg "Waiting for gateway on $IFACE... ($i/30)"
        sleep 1
    done
fi

if [ -z "$TARGET_GW" ] || [ -z "$TARGET_DEV" ]; then
    log_msg "No suitable gateway/interface found"
    exit 0
fi

# Resolve VPN server IP via DNS with retry
# Use the gateway as DNS server to avoid unreachable VPN DNS servers in /etc/resolv.conf
VPN_IP=""
for i in $(@coreutils@/bin/seq 1 30); do
    VPN_IP=$(@dnsutils@/bin/dig @"$TARGET_GW" +short +timeout=2 "$VPN_SERVER" 2>&1 | @gnugrep@/bin/grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -n "$VPN_IP" ]; then
        log_msg "Resolved VPN server $VPN_SERVER to $VPN_IP via $TARGET_GW after $i attempt(s)"
        break
    fi
    log_msg "DNS resolution failed for $VPN_SERVER via $TARGET_GW, retrying... ($i/30)"
    sleep 1
done

if [ -z "$VPN_IP" ]; then
    log_msg "Failed to determine VPN server IP - giving up"
    exit 0
fi

# Log current state for debugging
TUN_STATE=$(@iproute2@/bin/ip -br addr show dev tun0 2>/dev/null || echo "tun0: NOT_FOUND")
CURRENT_VPN_ROUTE=$(@iproute2@/bin/ip route show "$VPN_IP" 2>/dev/null || echo "no route")
NM_STATE=$(@networkmanager@/bin/nmcli -t general status 2>/dev/null | head -1 || echo "unknown")
log_msg "STATE: tun=[$TUN_STATE] vpn_route=[$CURRENT_VPN_ROUTE] nm=[$NM_STATE]"

@iproute2@/bin/ip route del "$VPN_IP" 2>/dev/null || true
log_msg "Updating route to VPN server $VPN_IP via $TARGET_GW dev $TARGET_DEV"
@iproute2@/bin/ip route add "$VPN_IP" via "$TARGET_GW" dev "$TARGET_DEV" 2>/dev/null || true

sleep 1
if [ "$ENABLE_DTLS" = "true" ]; then
    log_msg "Sending SIGTERM to openconnect (PID: $OPENCONNECT_PID) for full restart (DTLS mode)"
    kill -TERM "$OPENCONNECT_PID"
    for i in 1 2 3 4 5; do
        sleep 1
        if ! kill -0 "$OPENCONNECT_PID" 2>/dev/null; then
            log_msg "openconnect exited after SIGTERM"
            break
        fi
        if [ "$i" = "5" ]; then
            log_msg "openconnect did not respond to SIGTERM, sending SIGKILL"
            kill -9 "$OPENCONNECT_PID" 2>/dev/null || true
        fi
    done
else
    log_msg "Sending SIGUSR2 to openconnect (PID: $OPENCONNECT_PID) to force reconnection"
    kill -USR2 "$OPENCONNECT_PID"
fi

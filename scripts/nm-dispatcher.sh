#!/bin/sh
#
# NetworkManager Dispatcher Script (90-vpn-reconnect)
#
# Cycles VPN connection when switching to a new network.
# Only acts on "up" events - when a new connection is fully established.
#
# This ensures we don't interfere during network transitions (when old WiFi
# goes down but new WiFi isn't ready yet).

log_msg() {
    echo "$1"
    logger -t "90-vpn-reconnect" "$1"
}

IFACE="$1"
ACTION="$2"

# Only act on "up" events - when new connection is fully established
# Do NOT act on "down" or "connectivity-change" during transitions
if [ "$ACTION" != "up" ]; then
    exit 0
fi

# Skip virtual interfaces
case "$IFACE" in
    tun*|tap*|lo|docker*|br-*|veth*)
        exit 0
        ;;
esac

# Get the active VPN connection UUID
VPN_INFO=$(@networkmanager@/bin/nmcli -t -f NAME,UUID,TYPE connection show --active 2>/dev/null | @gnugrep@/bin/grep ':vpn$')
VPN_NAME=$(echo "$VPN_INFO" | @coreutils@/bin/cut -d: -f1)
VPN_UUID=$(echo "$VPN_INFO" | @coreutils@/bin/cut -d: -f2)

if [ -z "$VPN_UUID" ]; then
    # No VPN active, nothing to do
    exit 0
fi

log_msg "New connection on $IFACE - checking VPN routes"

# Wait for DNS to work (network fully ready)
# Some networks have slow DHCP/DNS allocation
MAX_WAIT=30
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if @dnsutils@/bin/dig +short +timeout=1 google.com >/dev/null 2>&1; then
        log_msg "Network ready after ${WAITED}s"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    log_msg "Network not ready after ${MAX_WAIT}s, proceeding anyway"
fi

# Get current gateway for this interface
CURRENT_GW=$(@iproute2@/bin/ip route show default dev "$IFACE" 2>/dev/null | @gawk@/bin/awk '{print $3}' | head -1)

if [ -z "$CURRENT_GW" ]; then
    log_msg "No gateway on $IFACE, skipping"
    exit 0
fi

# Get VPN server route (IP with metric 50)
VPN_SERVER_IP=$(@iproute2@/bin/ip route show | @gnugrep@/bin/grep "metric 50" | @gnugrep@/bin/grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)

if [ -z "$VPN_SERVER_IP" ]; then
    log_msg "No VPN route with metric 50 found, VPN may need cycling"
    # VPN is active but no routes - definitely need to cycle
else
    # Check if VPN route uses current gateway
    VPN_ROUTE_GW=$(@iproute2@/bin/ip route show "$VPN_SERVER_IP" 2>/dev/null | @gnugrep@/bin/grep -oP 'via \K[0-9.]+' | head -1)

    if [ "$VPN_ROUTE_GW" = "$CURRENT_GW" ]; then
        log_msg "VPN route uses correct gateway ($CURRENT_GW), no action needed"
        exit 0
    fi
    log_msg "VPN route uses $VPN_ROUTE_GW but current gateway is $CURRENT_GW"
fi

log_msg "Cycling VPN: $VPN_NAME ($VPN_UUID)"

# Disconnect VPN
@networkmanager@/bin/nmcli connection down uuid "$VPN_UUID" 2>/dev/null || true
log_msg "VPN disconnected"

sleep 2

# Reconnect VPN in background to avoid blocking WiFi transitions
# nmcli connection up can block for 90+ seconds even after VPN is connected
@networkmanager@/bin/nmcli connection up uuid "$VPN_UUID" >/dev/null 2>&1 &
log_msg "VPN reconnection initiated"

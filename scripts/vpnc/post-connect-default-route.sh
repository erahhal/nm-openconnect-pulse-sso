#!/bin/sh
#
# vpnc post-connect hook: Add default route through VPN
#
# Called after initial VPN connection is established.
# Adds default route via the VPN tunnel.

if [ -n "$INTERNAL_IP4_ADDRESS" ] && [ -n "$TUNDEV" ]; then
    @iproute2@/bin/ip route add default via "$INTERNAL_IP4_ADDRESS" dev "$TUNDEV" 2>/dev/null || \
    @iproute2@/bin/ip route replace default via "$INTERNAL_IP4_ADDRESS" dev "$TUNDEV" 2>/dev/null
    echo "Added default route via $INTERNAL_IP4_ADDRESS on $TUNDEV"
fi

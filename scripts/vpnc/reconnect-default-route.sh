#!/bin/sh
#
# vpnc reconnect hook: Restore default route through VPN
#
# Called after VPN reconnection.
# Re-adds default route via the VPN tunnel.

if [ -n "$INTERNAL_IP4_ADDRESS" ]; then
    @iproute2@/bin/ip route replace default via "$INTERNAL_IP4_ADDRESS" dev "$TUNDEV" 2>/dev/null
    echo "Restored default route via $INTERNAL_IP4_ADDRESS on $TUNDEV"
fi

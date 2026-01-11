#!/bin/sh
#
# vpnc post-connect hook: Narrow VPN route for Docker compatibility
#
# VPN pushes 172.16.0.0/12 which blocks Docker's address pool (172.17-172.31).
# This script replaces it with 172.16.0.0/16 to free up Docker's range.

if @iproute2@/bin/ip route show | @gnugrep@/bin/grep -q "172.16.0.0/12.*dev.*tun"; then
    echo "Narrowing 172.16.0.0/12 to 172.16.0.0/16 for Docker compatibility"
    @iproute2@/bin/ip route del 172.16.0.0/12 dev "$TUNDEV" 2>/dev/null || true
    @iproute2@/bin/ip route add 172.16.0.0/16 dev "$TUNDEV" 2>/dev/null || true
fi

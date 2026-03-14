#!/bin/sh
# Create auto-reconnect flag file on successful VPN connection.
# The external vpn-auto-reconnect service checks for this flag
# before attempting reconnection.
touch /run/vpn-auto-reconnect
echo "Auto-reconnect flag set"

#!/usr/bin/env bash
#
# VPN Diagnostic Script for nm-openconnect-pulse-sso
#
# Collects logs and system state for debugging VPN connection issues.
# Run this after experiencing a problem (e.g., VPN not connecting after resume).
#
# Usage: diagnose-nm-pulse-vpn [minutes]
#   minutes: How far back to look in logs (default: 15)
#
# Output is saved to /tmp/vpn-diagnose-TIMESTAMP.log

set -euo pipefail

MINUTES="${1:-15}"
TIMESTAMP=$(@coreutils@/bin/date +%Y%m%d-%H%M%S)
OUTPUT_FILE="/tmp/vpn-diagnose-${TIMESTAMP}.log"

section() {
    echo ""
    echo "================================================================================"
    echo "== $1"
    echo "================================================================================"
    echo ""
}

run_cmd() {
    local desc="$1"
    shift
    echo "--- $desc ---"
    echo "\$ $*"
    "$@" 2>&1 || echo "(command failed or produced no output)"
    echo ""
}

{
    echo "VPN Diagnostic Report"
    echo "Generated: $(@coreutils@/bin/date)"
    echo "Looking back: ${MINUTES} minutes"
    echo "Hostname: $(@nettools@/bin/hostname)"
    echo "Kernel: $(@coreutils@/bin/uname -r)"
    echo ""

    section "1. OPENCONNECT PROCESS STATE"

    run_cmd "OpenConnect processes" @procps@/bin/ps aux | @gnugrep@/bin/grep -E "[o]penconnect" || echo "No openconnect process running"

    run_cmd "nm-pulse-sso-service processes" @procps@/bin/ps aux | @gnugrep@/bin/grep -E "[n]m-pulse-sso" || echo "No nm-pulse-sso-service running"

    section "2. NETWORK INTERFACE STATE"

    run_cmd "All interfaces" @iproute2@/bin/ip -br link show

    run_cmd "TUN device details" @iproute2@/bin/ip addr show dev tun0 || echo "tun0 does not exist"

    run_cmd "TUN device statistics" @iproute2@/bin/ip -s link show dev tun0 || echo "tun0 does not exist"

    run_cmd "Physical interfaces with carrier" bash -c 'for dev in $(ls /sys/class/net/ | grep -v -E "^(lo|tun|tap|docker|br-|veth)"); do carrier=$(cat /sys/class/net/$dev/carrier 2>/dev/null || echo "?"); echo "$dev: carrier=$carrier"; done'

    section "3. ROUTING TABLE"

    run_cmd "IPv4 routes" @iproute2@/bin/ip -4 route show

    run_cmd "IPv6 routes" @iproute2@/bin/ip -6 route show

    run_cmd "Default routes" @iproute2@/bin/ip route show default

    section "4. DNS CONFIGURATION"

    run_cmd "resolv.conf" @coreutils@/bin/cat /etc/resolv.conf

    run_cmd "resolvectl status" @systemd@/bin/resolvectl status || echo "resolvectl not available"

    section "5. NETWORKMANAGER STATE"

    run_cmd "NM general status" @networkmanager@/bin/nmcli general status

    run_cmd "NM device status" @networkmanager@/bin/nmcli device status

    run_cmd "NM connections" @networkmanager@/bin/nmcli connection show

    run_cmd "Active VPN connections" @networkmanager@/bin/nmcli connection show --active | @gnugrep@/bin/grep -i vpn || echo "No active VPN connections"

    # Try to find and show VPN connection details
    VPN_CONN=$(@networkmanager@/bin/nmcli connection show | @gnugrep@/bin/grep -i pulse | @gawk@/bin/awk '{print $1}' | head -1)
    if [ -n "$VPN_CONN" ]; then
        run_cmd "VPN connection details: $VPN_CONN" @networkmanager@/bin/nmcli connection show "$VPN_CONN"
    fi

    section "6. JOURNAL LOGS (last ${MINUTES} minutes)"

    run_cmd "VPN service logs" @systemd@/bin/journalctl --since "${MINUTES} minutes ago" --no-pager -o short-precise | @gnugrep@/bin/grep -iE "(pulse|openconnect)" | head -200 || echo "No matching logs"

    run_cmd "VPN reconnect service logs" @systemd@/bin/journalctl --since "${MINUTES} minutes ago" --no-pager -o short-precise | @gnugrep@/bin/grep -iE "vpn-reconnect" | head -50 || echo "No matching logs"

    run_cmd "NetworkManager dispatcher logs" @systemd@/bin/journalctl --since "${MINUTES} minutes ago" --no-pager -o short-precise | @gnugrep@/bin/grep -iE "nm-dispatcher.*90-vpn" | head -50 || echo "No matching logs"

    run_cmd "Suspend/resume events" @systemd@/bin/journalctl --since "${MINUTES} minutes ago" --no-pager -o short-precise | @gnugrep@/bin/grep -iE "(suspend|resume|sleep)" | head -30 || echo "No matching logs"

    run_cmd "NetworkManager state changes" @systemd@/bin/journalctl --since "${MINUTES} minutes ago" --no-pager -o short-precise -u NetworkManager | @gnugrep@/bin/grep -iE "(state|vpn|pulse|connect)" | head -50 || echo "No matching logs"

    section "7. CONFIGURATION"

    run_cmd "DTLS config" @coreutils@/bin/cat /etc/nm-pulse-sso/config 2>/dev/null || echo "Config file not found"

    run_cmd "VPN dispatcher script exists" ls -la /etc/NetworkManager/dispatcher.d/90-vpn-reconnect 2>/dev/null || echo "Dispatcher script not found"

    section "8. CONNECTIVITY TEST"

    run_cmd "Can reach VPN server?" bash -c 'VPN_SERVER=$(@procps@/bin/ps aux | @gnugrep@/bin/grep "[o]penconnect" | @gnugrep@/bin/grep -oP "https://\K[^/]+" | head -1); if [ -n "$VPN_SERVER" ]; then echo "Testing: $VPN_SERVER"; @iputils@/bin/ping -c 2 -W 2 "$VPN_SERVER" || echo "Cannot ping VPN server"; else echo "No VPN server found in openconnect command"; fi'

    run_cmd "External connectivity" @iputils@/bin/ping -c 2 -W 2 8.8.8.8 || echo "Cannot reach 8.8.8.8"

    run_cmd "DNS resolution" @dnsutils@/bin/dig +short +timeout=2 google.com || echo "DNS resolution failed"

    section "END OF REPORT"

} 2>&1 | @coreutils@/bin/tee "$OUTPUT_FILE"

echo ""
echo "Diagnostic report saved to: $OUTPUT_FILE"
echo ""
echo "To share this report:"
echo "  cat $OUTPUT_FILE | nc termbin.com 9999"
echo "  # or"
echo "  curl -F 'file=@$OUTPUT_FILE' https://0x0.st"
echo ""

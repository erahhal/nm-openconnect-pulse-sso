#!/bin/sh
#
# NetworkManager Dispatcher Script (90-vpn-reconnect)
#
# Kills openconnect on significant network changes and triggers
# auto-reconnect via the external vpn-auto-reconnect service.

# Log to both stdout and syslog for debugging
log_msg() {
    echo "$1"
    logger -t "90-vpn-reconnect" "$1"
}

# Prevent concurrent execution (rapid WiFi state changes spawn multiple instances)
exec 9>/run/vpn-reconnect.lock
flock -n 9 || { log_msg "Another instance already running, exiting"; exit 0; }

# Act on interface events for physical interfaces
IFACE="$1"
ACTION="$2"

case "$ACTION" in
    connectivity-change|down|up)
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

# Check VPN state: is openconnect running? Should VPN be up?
OPENCONNECT_PID=$(@procps@/bin/pgrep -x openconnect)
VPN_SHOULD_BE_UP=""
if [ -f "/run/vpn-auto-reconnect" ]; then
    VPN_SHOULD_BE_UP="1"
fi

# If openconnect not running and VPN not supposed to be up — nothing to do
if [ -z "$OPENCONNECT_PID" ] && [ -z "$VPN_SHOULD_BE_UP" ]; then
    exit 0
fi

# If openconnect not running but VPN should be up — just trigger reconnect.
# This handles: WiFi comes UP after ethernet went DOWN and killed openconnect.
if [ -z "$OPENCONNECT_PID" ] && [ -n "$VPN_SHOULD_BE_UP" ]; then
    log_msg "Interface $IFACE action $ACTION — VPN should be up, triggering reconnect"
    @systemd@/bin/resolvectl flush-caches 2>/dev/null || true
    @systemd@/bin/resolvectl reset-server-features 2>/dev/null || true
    @systemd@/bin/systemctl restart --no-block vpn-auto-reconnect.service 2>/dev/null || true
    exit 0
fi

# openconnect IS running — proceed with kill + reconnect logic
log_msg "Interface $IFACE action $ACTION - checking VPN"

# Flush DNS caches immediately now that the new interface is ready
@systemd@/bin/resolvectl flush-caches 2>/dev/null || true
@systemd@/bin/resolvectl reset-server-features 2>/dev/null || true
log_msg "Flushed DNS caches and reset server features"

# Find active gateway for cooldown comparison
TARGET_GW=""
TARGET_DEV=""
if [ "$ACTION" = "down" ] || [ "$ACTION" = "connectivity-change" ] || [ -z "$IFACE" ]; then
    for dev in $(ls /sys/class/net/ | grep -v -E "^(lo|tun|tap|docker|br-|veth)"); do
        if [ -f "/sys/class/net/$dev/carrier" ]; then
            CARRIER=$(cat "/sys/class/net/$dev/carrier" 2>/dev/null || echo "0")
            if [ "$CARRIER" = "1" ] && [ "$dev" != "$IFACE" ]; then
                GW=$(@iproute2@/bin/ip route show default dev "$dev" 2>/dev/null | @gawk@/bin/awk '{print $3}' | head -1)
                if [ -n "$GW" ]; then
                    TARGET_DEV="$dev"
                    TARGET_GW="$GW"
                    break
                fi
            fi
        fi
    done
else
    TARGET_DEV="$IFACE"
    TARGET_GW=$(@iproute2@/bin/ip route show default dev "$IFACE" 2>/dev/null | @gawk@/bin/awk '{print $3}' | head -1)
fi

if [ -z "$TARGET_GW" ] || [ -z "$TARGET_DEV" ]; then
    log_msg "No suitable gateway/interface found"
    exit 0
fi

# Cooldown: don't kill openconnect if we killed it recently on the same network.
# Transient WiFi glitches cause rapid down/up cycles that would otherwise
# create a destructive restart loop.
COOLDOWN_FILE="/run/vpn-reconnect-last-kill"
COOLDOWN_SECONDS=120
SKIP_KILL=false

if [ -f "$COOLDOWN_FILE" ]; then
    COOLDOWN_DATA=$(cat "$COOLDOWN_FILE" 2>/dev/null || echo "0::")
    LAST_KILL=$(echo "$COOLDOWN_DATA" | cut -d: -f1)
    LAST_GW=$(echo "$COOLDOWN_DATA" | cut -d: -f2)
    LAST_DEV=$(echo "$COOLDOWN_DATA" | cut -d: -f3)
    NOW=$(@coreutils@/bin/date +%s)
    ELAPSED=$((NOW - LAST_KILL))
    if [ "$ELAPSED" -lt "$COOLDOWN_SECONDS" ]; then
        if [ "$LAST_GW" = "$TARGET_GW" ] && [ "$LAST_DEV" = "$TARGET_DEV" ]; then
            log_msg "Skipping kill: last restart was ${ELAPSED}s ago (cooldown: ${COOLDOWN_SECONDS}s), same network ($TARGET_DEV/$TARGET_GW)"
            SKIP_KILL=true
        else
            log_msg "Network changed ($LAST_DEV/$LAST_GW -> $TARGET_DEV/$TARGET_GW), bypassing cooldown"
        fi
    fi
fi

if [ "$SKIP_KILL" = "false" ]; then
    sleep 1
    log_msg "Sending SIGTERM to openconnect (PID: $OPENCONNECT_PID)"
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

    # Record kill timestamp and network info for cooldown
    echo "$(@coreutils@/bin/date +%s):${TARGET_GW}:${TARGET_DEV}" > "$COOLDOWN_FILE"

    # Trigger auto-reconnect service (handles waiting for NM, retries, etc.)
    @systemd@/bin/systemctl start --no-block vpn-auto-reconnect.service 2>/dev/null || true
fi

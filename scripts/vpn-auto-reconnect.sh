#!/bin/sh
#
# External VPN auto-reconnect service
#
# Triggered by: vpn-reconnect (post-resume), nm-dispatcher (network change)
# Uses nmcli (same as a user would) — avoids all NM plugin state machine conflicts.
#
# VPN_NAME is substituted at build time via @vpnName@

VPN_NAME="@vpnName@"
FLAG="/run/vpn-auto-reconnect"
LOCK="/run/vpn-auto-reconnect.lock"

# Only reconnect if flag file exists (VPN was connected and not user-disconnected)
if [ ! -f "$FLAG" ]; then
    echo "Auto-reconnect not enabled (no flag file), skipping"
    exit 0
fi

# Check if VPN is already connected or activating (auth-dialog may already be open)
if @networkmanager@/bin/nmcli -t -f TYPE,STATE connection show --active 2>/dev/null | grep -q "^vpn:activated$"; then
    echo "VPN already connected"
    exit 0
fi
if @networkmanager@/bin/nmcli -t -f TYPE,STATE connection show --active 2>/dev/null | grep -q "^vpn:activating$"; then
    echo "VPN already activating (auth dialog running), skipping duplicate attempt"
    exit 0
fi

# Lock to prevent concurrent reconnect attempts
exec 200>"$LOCK"
@util-linux@/bin/flock -n 200 || { echo "Another reconnect attempt in progress"; exit 0; }

# Kill any lingering openconnect processes (e.g., stale after resume)
# Only wait if openconnect is actually running — avoids 2s delay in the common
# interface-change case where the service already killed it.
if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
    @procps@/bin/pkill -x openconnect 2>/dev/null || true
    sleep 2
    if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
        @procps@/bin/pkill -9 -x openconnect 2>/dev/null || true
        sleep 1
    fi
fi

# Wait for network connectivity (up to 20s)
# Track whether NM was already connected on first check (no wait needed).
nm_was_ready="no"
for i in $(@coreutils@/bin/seq 1 10); do
    if @networkmanager@/bin/nmcli -t -f STATE general status 2>/dev/null | grep -q "connected"; then
        if [ "$i" -eq 1 ]; then nm_was_ready="yes"; fi
        break
    fi
    echo "Waiting for network connectivity... ($i/10)"
    sleep 2
done

# Only pause to let NM settle if we had to wait for connectivity.
# When NM was already connected (common interface-change case), this is pure waste.
if [ "$nm_was_ready" != "yes" ]; then
    sleep 3
fi

# Flush DNS caches (stale after resume)
@systemd@/bin/resolvectl flush-caches 2>/dev/null || true
@systemd@/bin/resolvectl reset-server-features 2>/dev/null || true

# Attempt reconnect with increasing backoff
for attempt in 1 2 3 4 5; do
    echo "VPN reconnect attempt $attempt..."

    # Check flag still exists (user may have disconnected during our wait)
    if [ ! -f "$FLAG" ]; then
        echo "Flag file removed during reconnect — user disconnected"
        exit 0
    fi

    # Check if VPN was already reconnected (e.g., by NM re-activation path)
    if @networkmanager@/bin/nmcli -t -f TYPE,STATE connection show --active 2>/dev/null | grep -q "^vpn:activated$"; then
        echo "VPN already reconnected (by another path)"
        for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
            RUNTIME_DIR="/run/user/$uid"
            if [ -S "$RUNTIME_DIR/bus" ]; then
                @sudo@/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                    @libnotify@/bin/notify-send -i network-vpn "VPN Reconnected" \
                    "VPN auto-reconnected successfully" 2>/dev/null || true
            fi
        done
        exit 0
    fi

    if @networkmanager@/bin/nmcli connection up "$VPN_NAME" 2>&1; then
        echo "VPN reconnected successfully"

        # Notify user
        for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
            RUNTIME_DIR="/run/user/$uid"
            if [ -S "$RUNTIME_DIR/bus" ]; then
                @sudo@/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                    @libnotify@/bin/notify-send -i network-vpn "VPN Reconnected" \
                    "VPN auto-reconnected successfully" 2>/dev/null || true
            fi
        done
        exit 0
    fi

    DELAY=$((attempt * 3))
    echo "Attempt $attempt failed, retrying in ${DELAY}s..."
    sleep "$DELAY"
done

echo "VPN reconnect failed after 5 attempts"
# Notify user of failure
for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
    RUNTIME_DIR="/run/user/$uid"
    if [ -S "$RUNTIME_DIR/bus" ]; then
        @sudo@/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
            @libnotify@/bin/notify-send -i dialog-warning "VPN Reconnect Failed" \
            "Auto-reconnect failed after 5 attempts. Please reconnect manually." 2>/dev/null || true
    fi
done
exit 1

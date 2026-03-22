#!/bin/sh
#
# Service Restart Script for nm-openconnect-pulse-sso
#
# Called when the nm-pulse-sso package is updated.
# Kills old service processes and reconnects VPN if it was active.
#
# VPN_NAME is substituted at build time via @vpnName@

VPN_NAME="@vpnName@"

# Clean up stale VPN connections that don't match the current ensureProfiles config.
# When the gateway changes, ensureProfiles creates a new connection in /run/ but
# old internalized copies persist in /etc/NetworkManager/system-connections/.
# NM loads both, causing duplicate VPN entries with different gateways.
echo "Cleaning up stale VPN connections..."

# Wait for NM to be ready (connections loaded) — may not be fully up yet at boot
for _i in 1 2 3 4 5; do
    if @networkmanager@/bin/nmcli -t -f NAME connection show 2>/dev/null | grep -qF "$VPN_NAME"; then
        break
    fi
    echo "  Waiting for NetworkManager to load connections..."
    sleep 1
done

# Get all connections with their filenames in one shot.
# nmcli -t uses : as separator. FILENAME field works in list-all mode
# but NOT in per-connection queries (exit code 2).
# Output example:
#   Netflix VPN:3da9c86d-...:/var/run/NetworkManager/system-connections/pulse-sso-vpn.nmconnection
#   Netflix VPN:081842c9-...:/etc/NetworkManager/system-connections/Netflix VPN.nmconnection
@networkmanager@/bin/nmcli -t -f NAME,UUID,FILENAME connection show 2>/dev/null \
    | while IFS=: read -r CONN_NAME CONN_UUID CONN_FILE; do
    if [ "$CONN_NAME" = "$VPN_NAME" ]; then
        case "$CONN_FILE" in
            /run/*|/var/run/*)
                echo "  Keeping ensureProfiles connection: $CONN_UUID ($CONN_FILE)"
                ;;
            *)
                echo "  Removing stale connection: $CONN_UUID ($CONN_FILE)"
                @networkmanager@/bin/nmcli connection delete "$CONN_UUID" 2>/dev/null || true
                ;;
        esac
    fi
done

# Check if VPN was connected by looking for openconnect process
VPN_WAS_ACTIVE=""
if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
    VPN_WAS_ACTIVE="1"
    echo "VPN was active (openconnect running), will reconnect after restart"
fi

# Disconnect VPN via NetworkManager first (ensures clean state)
@networkmanager@/bin/nmcli connection down "$VPN_NAME" 2>/dev/null || true

# Kill old service (ignore if not running)
@procps@/bin/pkill -f nm-pulse-sso-service || true

# Kill openconnect - use SIGKILL fallback since DTLS mode ignores SIGTERM
@procps@/bin/pkill -x openconnect || true
sleep 2
if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
    echo "openconnect did not respond to SIGTERM, sending SIGKILL"
    @procps@/bin/pkill -9 -x openconnect || true
fi

# Write cooldown file so the NM dispatcher doesn't kill openconnect
# again when interface events fire during NM restart
TARGET_GW=$(@iproute2@/bin/ip route show default 2>/dev/null | @gawk@/bin/awk '/via/ {print $3; exit}')
TARGET_DEV=$(@iproute2@/bin/ip route show default 2>/dev/null | @gawk@/bin/awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
if [ -n "$TARGET_GW" ] && [ -n "$TARGET_DEV" ]; then
    echo "$(@coreutils@/bin/date +%s):${TARGET_GW}:${TARGET_DEV}" > /run/vpn-reconnect-last-kill
fi

# Reconnect if VPN was active
if [ -n "$VPN_WAS_ACTIVE" ]; then
    echo "Reconnecting VPN..."
    # Restart nm-applet for all logged-in users
    for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
        RUNTIME_DIR="/run/user/$uid"
        if [ -S "$RUNTIME_DIR/bus" ]; then
            echo "Restarting nm-applet for user $uid..."
            @sudo@/bin/sudo -u "#$uid" \
                XDG_RUNTIME_DIR="$RUNTIME_DIR" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                @systemd@/bin/systemctl --user restart network-manager-applet.service 2>/dev/null || true

            @sudo@/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                @libnotify@/bin/notify-send -i network-vpn "VPN Reconnecting" \
                "NixOS rebuild updated VPN service. Reconnecting..." 2>/dev/null || true
        fi
    done

    # Synchronous reconnect — blocks until VPN is back or timeout.
    # This ensures systemd services ordered After=nm-pulse-sso-restart.service
    # (e.g., home-manager) don't start until VPN is available.
    sleep 3
    RECONNECTED=""
    for attempt in 1 2 3 4 5; do
        # Check if VPN connected (e.g. from a previous attempt's auth completing)
        if @procps@/bin/pgrep -x openconnect >/dev/null 2>&1; then
            echo "VPN is connected (openconnect running)"
            RECONNECTED="1"
            break
        fi

        echo "VPN reconnect attempt $attempt..."
        OUTPUT=$(@networkmanager@/bin/nmcli connection up "$VPN_NAME" 2>&1) && {
            echo "VPN reconnected successfully"
            RECONNECTED="1"
            break
        }

        # "already active" means VPN is connecting or connected — treat as success
        if echo "$OUTPUT" | grep -q "already active"; then
            echo "VPN is already activating/active"
            RECONNECTED="1"
            break
        fi

        echo "Attempt $attempt failed ($OUTPUT), retrying in 5s..."
        sleep 5
    done

    if [ -n "$RECONNECTED" ]; then
        for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
            RUNTIME_DIR="/run/user/$uid"
            if [ -S "$RUNTIME_DIR/bus" ]; then
                @sudo@/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                    @libnotify@/bin/notify-send -i network-vpn "VPN Reconnected" \
                    "VPN reconnected after NixOS rebuild" 2>/dev/null || true
            fi
        done
    else
        echo "VPN reconnect failed after 5 attempts"
        for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
            RUNTIME_DIR="/run/user/$uid"
            if [ -S "$RUNTIME_DIR/bus" ]; then
                @sudo@/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                    @libnotify@/bin/notify-send -i dialog-warning "VPN Reconnect Failed" \
                    "Auto-reconnect failed after NixOS rebuild. Please reconnect manually." 2>/dev/null || true
            fi
        done
    fi
fi

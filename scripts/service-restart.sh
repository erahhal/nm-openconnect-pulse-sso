#!/bin/sh
#
# Service Restart Script for nm-openconnect-pulse-sso
#
# Called when the nm-pulse-sso package is updated.
# Kills old service processes and reconnects VPN if it was active.
#
# VPN_NAME is substituted at build time via @vpnName@

VPN_NAME="@vpnName@"

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

    # Background reconnect with retry loop
    (
        sleep 3
        for attempt in 1 2 3 4 5; do
            echo "VPN reconnect attempt $attempt..."
            for uid in $(@systemd@/bin/loginctl list-users --no-legend | @gawk@/bin/awk '{print $1}'); do
                RUNTIME_DIR="/run/user/$uid"
                if [ -S "$RUNTIME_DIR/bus" ]; then
                    if @sudo@/bin/sudo -u "#$uid" \
                        XDG_RUNTIME_DIR="$RUNTIME_DIR" \
                        DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                        @networkmanager@/bin/nmcli connection up "$VPN_NAME" 2>&1; then
                        echo "VPN reconnected successfully"
                        exit 0
                    fi
                fi
            done
            echo "Attempt $attempt failed, retrying..."
            sleep 5
        done
        echo "VPN reconnect failed after 5 attempts"
    ) &
fi

{
  description = "NetworkManager VPN plugin for Pulse with CEF-based SSO authentication";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Build the CEF authentication binary
        pulse-browser-auth = pkgs.callPackage ./cef-auth/default.nix { };
      in
      {
        packages = {
          inherit pulse-browser-auth;
          default = pkgs.callPackage ./default.nix { cef-pulse-auth = pulse-browser-auth; };
          nm-pulse-sso = pkgs.callPackage ./default.nix { cef-pulse-auth = pulse-browser-auth; };
          nm-pulse-sso-selenium = pkgs.callPackage ./default-selenium.nix { };
        };

        # Development shell for testing
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            (python312.withPackages (ps: with ps; [
              dbus-python
              pygobject3
            ]))
            openconnect
            dbus
            gtk3
            pulse-browser-auth
          ];
        };
      }
    ) // {
      # Overlay for easy integration into other flakes
      overlays.default = final: prev: {
        pulse-browser-auth = final.callPackage ./cef-auth/default.nix { };
        nm-pulse-sso = final.callPackage ./default.nix {
          cef-pulse-auth = final.pulse-browser-auth;
        };
        nm-pulse-sso-selenium = final.callPackage ./default-selenium.nix { };
      };

      # Plasma-nm overlay for KDE integration
      overlays.plasma-nm = import ./plasma-nm-overlay.nix {
        plasma-plugin-src = ./plasma-plugin;
      };

      # NixOS module for easy integration
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.nm-pulse-sso;

          # CEF-based authentication browser
          pulse-browser-auth = pkgs.callPackage ./cef-auth/default.nix { };

          # Select implementation based on enableSelenium option
          nm-pulse-sso = if cfg.enableSelenium
            then pkgs.callPackage ./default-selenium.nix { }
            else pkgs.callPackage ./default.nix {
              cef-pulse-auth = pulse-browser-auth;
            };

          # Browser setup tool for installing extensions, configuring settings, etc.
          pulse-browser-setup = pkgs.writeShellScriptBin "pulse-browser-setup" ''
            echo "Launching browser for configuration..."
            echo ""
            echo "Use this to install extensions (like Bitwarden), configure settings, etc."
            echo "Extensions can be installed from the Chrome Web Store."
            echo ""
            echo "Close the browser when done. Settings persist in ~/.cache/pulse-browser-auth"
            exec ${pulse-browser-auth}/bin/pulse-browser-auth \
              --url "https://chromewebstore.google.com" \
              --timeout 3600
          '';

          # Script to narrow VPN route for Docker compatibility
          # VPN pushes 172.16.0.0/12 which blocks Docker's address pool (172.17-172.31)
          # Replace with 172.16.0.0/16 to free up Docker's range
          narrow-docker-route-script = ''
            #!/bin/sh
            # Replace broad /12 route with narrow /16 to free Docker's address space
            if ${pkgs.iproute2}/bin/ip route show | ${pkgs.gnugrep}/bin/grep -q "172.16.0.0/12.*dev.*tun"; then
              echo "Narrowing 172.16.0.0/12 to 172.16.0.0/16 for Docker compatibility"
              ${pkgs.iproute2}/bin/ip route del 172.16.0.0/12 dev "$TUNDEV" 2>/dev/null || true
              ${pkgs.iproute2}/bin/ip route add 172.16.0.0/16 dev "$TUNDEV" 2>/dev/null || true
            fi
          '';

          # Script to reconnect VPN after system resume
          # With DTLS disabled: Uses SIGUSR2 for graceful reconnection
          # With DTLS enabled: Uses SIGTERM for full restart (ESP reconnect is broken upstream)
          vpn-reconnect-script = pkgs.writeShellScript "vpn-reconnect" ''
            # Wait for network to stabilize after resume
            sleep 3

            # Fix route to VPN server when network interface changes
            # The VPN server must be reachable via physical interface, not tun0
            # Get VPN server IP from openconnect's command line
            VPN_SERVER=$(${pkgs.procps}/bin/ps aux | grep '[o]penconnect' | grep -oP 'https://\K[^/]+' | head -1)
            if [ -n "$VPN_SERVER" ]; then
              # Resolve VPN server IP - filter dig output to only accept valid IPv4 addresses
              VPN_IP=$(${pkgs.dnsutils}/bin/dig +short +timeout=2 "$VPN_SERVER" 2>&1 | ${pkgs.gnugrep}/bin/grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
              if [ -n "$VPN_IP" ]; then
                # Find a physical interface that has carrier (is actually connected)
                # Check each non-tun default route's interface for carrier
                FOUND_ROUTE=0
                for route_line in $(${pkgs.iproute2}/bin/ip route show default | grep -v tun); do
                  DEV=$(echo "$route_line" | ${pkgs.gawk}/bin/awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
                  GW=$(echo "$route_line" | ${pkgs.gawk}/bin/awk '{print $3}')

                  # Check if interface has carrier (cable plugged in / wifi connected)
                  if [ -f "/sys/class/net/$DEV/carrier" ]; then
                    CARRIER=$(cat "/sys/class/net/$DEV/carrier" 2>/dev/null || echo "0")
                    if [ "$CARRIER" = "1" ]; then
                      echo "Found active interface $DEV with gateway $GW"
                      # Remove old routes and add new one via active interface
                      ${pkgs.iproute2}/bin/ip route del "$VPN_IP" 2>/dev/null || true
                      ${pkgs.iproute2}/bin/ip route add "$VPN_IP" via "$GW" dev "$DEV" 2>/dev/null || true
                      echo "Updated route to VPN server $VPN_IP via $GW dev $DEV"
                      FOUND_ROUTE=1
                      break
                    fi
                  fi
                done

                if [ "$FOUND_ROUTE" = "0" ]; then
                  echo "No active physical interface found for VPN route"
                fi
              fi
            fi

            # Find openconnect PID and trigger reconnection
            OPENCONNECT_PID=$(${pkgs.procps}/bin/pgrep -x openconnect)

            if [ -n "$OPENCONNECT_PID" ]; then
              ${if cfg.enableDtls then ''
              # DTLS enabled: Use SIGTERM for full restart (ESP reconnect is broken upstream)
              # The VPN service will auto-restart with the existing cookie
              # Note: openconnect in DTLS/ESP mode may ignore SIGTERM, so we escalate to SIGKILL
              echo "Sending SIGTERM to openconnect (PID: $OPENCONNECT_PID) for full restart (DTLS mode)"
              kill -TERM "$OPENCONNECT_PID"
              # Wait up to 5 seconds for graceful exit, then force kill
              for i in 1 2 3 4 5; do
                sleep 1
                if ! kill -0 "$OPENCONNECT_PID" 2>/dev/null; then
                  echo "openconnect exited after SIGTERM"
                  break
                fi
                if [ "$i" = "5" ]; then
                  echo "openconnect did not respond to SIGTERM, sending SIGKILL"
                  kill -9 "$OPENCONNECT_PID" 2>/dev/null || true
                fi
              done
              '' else ''
              # DTLS disabled: Use SIGUSR2 for graceful reconnection (SSL-only mode)
              echo "Sending SIGUSR2 to openconnect (PID: $OPENCONNECT_PID) to force reconnection"
              kill -USR2 "$OPENCONNECT_PID"
              ''}
            else
              echo "No openconnect process found, skipping reconnection"
            fi
          '';
        in
        {
          options.services.nm-pulse-sso = {
            enable = lib.mkEnableOption "NetworkManager Pulse SSO VPN plugin";

            vpnName = lib.mkOption {
              type = lib.types.str;
              default = "Pulse VPN";
              description = "Name of the VPN connection";
            };

            gateway = lib.mkOption {
              type = lib.types.str;
              example = "https://vpn.example.com/saml";
              description = "VPN gateway URL";
            };

            enableDtls = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Enable DTLS/ESP for better VPN performance (UDP instead of TCP).
                When enabled, uses full restart instead of SIGUSR2 for reconnection
                after suspend/resume or network changes. If the cookie is invalidated,
                the browser will open for re-authentication.
                When disabled, uses --no-dtls for reliable SIGUSR2 reconnection.

                DTLS is generally more stable and recommended.
              '';
            };

            enableRecovery = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Enable VPN recovery scripts for automatic reconnection after
                suspend/resume or network changes. Also sets rpfilter to "loose"
                mode which is required for reliable reconnection.
              '';
            };

            enableSelenium = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Use Selenium WebDriver for VPN authentication browser.
                When enabled, uses Selenium with undetected-chromedriver.
                When disabled (default), uses CEF (Chromium Embedded Framework).

                CEF advantages (default):
                - Native WebAuthn/FIDO2 support for hardware keys (Yubikey)
                - Faster startup
                - More reliable UA switching for Okta bypass

                Selenium advantages:
                - More mature and tested implementation
                - Easier debugging (standard Chrome)
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            # Apply plasma-nm overlay for KDE integration
            nixpkgs.overlays = [
              (import ./plasma-nm-overlay.nix {
                plasma-plugin-src = ./plasma-plugin;
              })
            ];

            # Install the VPN plugin
            networking.networkmanager.plugins = [
              nm-pulse-sso
              pkgs.networkmanager-openconnect  # Keep standard openconnect available
            ];

            # Make browser binaries available system-wide
            environment.systemPackages = [
              pkgs.openconnect
              nm-pulse-sso
            ] ++ lib.optionals (!cfg.enableSelenium) [
              pulse-browser-auth
              pulse-browser-setup
            ];

            # D-Bus policy is installed by the package
            services.dbus.packages = [ nm-pulse-sso ];

            # Restart NetworkManager when the VPN plugin changes
            systemd.services.NetworkManager.restartTriggers = [ nm-pulse-sso ];

            # Declaratively create the VPN connection
            networking.networkmanager.ensureProfiles.profiles = {
              "pulse-sso-vpn" = {
                connection = {
                  id = cfg.vpnName;
                  type = "vpn";
                  autoconnect = "false";
                };
                vpn = {
                  service-type = "org.freedesktop.NetworkManager.pulse-sso";
                  gateway = cfg.gateway;
                  persistent = "true";  # Keep VPN alive across suspend/resume
                };
                ipv4.method = "auto";
                ipv6.method = "auto";
              };
            };

            # Systemd service to reconnect VPN after system resume
            systemd.services.vpn-reconnect = lib.mkIf cfg.enableRecovery {
              description = "Reconnect VPN after system resume";
              wantedBy = [ "post-resume.target" ];
              after = [ "post-resume.target" "network-online.target" ];

              serviceConfig = {
                Type = "oneshot";
                ExecStart = vpn-reconnect-script;
              };
            };

            # Kill old nm-pulse-sso-service when the package changes and reconnect VPN
            systemd.services.nm-pulse-sso-restart = {
              description = "Restart nm-pulse-sso-service on package update";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];
              restartTriggers = [ nm-pulse-sso cfg.enableDtls ];

              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                ExecStart = pkgs.writeShellScript "nm-pulse-sso-restart" ''
                  # Check if VPN was connected by looking for openconnect process
                  VPN_WAS_ACTIVE=""
                  if ${pkgs.procps}/bin/pgrep -x openconnect >/dev/null 2>&1; then
                    VPN_WAS_ACTIVE="1"
                    echo "VPN was active (openconnect running), will reconnect after restart"
                  fi

                  # Disconnect VPN via NetworkManager first (ensures clean state)
                  ${pkgs.networkmanager}/bin/nmcli connection down "${cfg.vpnName}" 2>/dev/null || true

                  # Kill old service (ignore if not running)
                  ${pkgs.procps}/bin/pkill -f nm-pulse-sso-service || true

                  # Kill openconnect - use SIGKILL fallback since DTLS mode ignores SIGTERM
                  ${pkgs.procps}/bin/pkill -x openconnect || true
                  sleep 2
                  if ${pkgs.procps}/bin/pgrep -x openconnect >/dev/null 2>&1; then
                    echo "openconnect did not respond to SIGTERM, sending SIGKILL"
                    ${pkgs.procps}/bin/pkill -9 -x openconnect || true
                  fi

                  # Reconnect if VPN was active
                  if [ -n "$VPN_WAS_ACTIVE" ]; then
                    echo "Reconnecting VPN..."
                    # Restart nm-applet for all logged-in users
                    for uid in $(${pkgs.systemd}/bin/loginctl list-users --no-legend | ${pkgs.gawk}/bin/awk '{print $1}'); do
                      RUNTIME_DIR="/run/user/$uid"
                      if [ -S "$RUNTIME_DIR/bus" ]; then
                        echo "Restarting nm-applet for user $uid..."
                        ${pkgs.sudo}/bin/sudo -u "#$uid" \
                          XDG_RUNTIME_DIR="$RUNTIME_DIR" \
                          DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                          ${pkgs.systemd}/bin/systemctl --user restart network-manager-applet.service 2>/dev/null || true

                        ${pkgs.sudo}/bin/sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                          ${pkgs.libnotify}/bin/notify-send -i network-vpn "VPN Reconnecting" \
                          "NixOS rebuild updated VPN service. Reconnecting..." 2>/dev/null || true
                      fi
                    done

                    # Background reconnect with retry loop
                    (
                      sleep 3
                      for attempt in 1 2 3 4 5; do
                        echo "VPN reconnect attempt $attempt..."
                        for uid in $(${pkgs.systemd}/bin/loginctl list-users --no-legend | ${pkgs.gawk}/bin/awk '{print $1}'); do
                          RUNTIME_DIR="/run/user/$uid"
                          if [ -S "$RUNTIME_DIR/bus" ]; then
                            if ${pkgs.sudo}/bin/sudo -u "#$uid" \
                              XDG_RUNTIME_DIR="$RUNTIME_DIR" \
                              DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
                              ${pkgs.networkmanager}/bin/nmcli connection up "${cfg.vpnName}" 2>&1; then
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
                '';
              };
            };

            # vpnc hook to add default route after initial VPN connection
            environment.etc."vpnc/post-connect.d/add-default-route" = lib.mkIf cfg.enableRecovery {
              mode = "0755";
              text = ''
                #!/bin/sh
                # Add default route through VPN after connection
                if [ -n "$INTERNAL_IP4_ADDRESS" ] && [ -n "$TUNDEV" ]; then
                  ${pkgs.iproute2}/bin/ip route add default via "$INTERNAL_IP4_ADDRESS" dev "$TUNDEV" 2>/dev/null || \
                  ${pkgs.iproute2}/bin/ip route replace default via "$INTERNAL_IP4_ADDRESS" dev "$TUNDEV" 2>/dev/null
                  echo "Added default route via $INTERNAL_IP4_ADDRESS on $TUNDEV"
                fi
              '';
            };

            # vpnc hook to narrow VPN route for Docker compatibility
            environment.etc."vpnc/post-connect.d/narrow-docker-route" = lib.mkIf cfg.enableRecovery {
              mode = "0755";
              text = narrow-docker-route-script;
            };

            # vpnc hook to re-apply default route after VPN reconnection
            environment.etc."vpnc/reconnect.d/fix-default-route" = lib.mkIf cfg.enableRecovery {
              mode = "0755";
              text = ''
                #!/bin/sh
                # Re-add default route through VPN after reconnection
                if [ -n "$INTERNAL_IP4_ADDRESS" ]; then
                  ${pkgs.iproute2}/bin/ip route replace default via "$INTERNAL_IP4_ADDRESS" dev "$TUNDEV" 2>/dev/null
                  echo "Restored default route via $INTERNAL_IP4_ADDRESS on $TUNDEV"
                fi
              '';
            };

            # vpnc hook to narrow VPN route after reconnection for Docker compatibility
            environment.etc."vpnc/reconnect.d/narrow-docker-route" = lib.mkIf cfg.enableRecovery {
              mode = "0755";
              text = narrow-docker-route-script;
            };

            # NetworkManager dispatcher to fix VPN route and trigger reconnection when interface changes
            environment.etc."NetworkManager/dispatcher.d/90-vpn-reconnect" = lib.mkIf cfg.enableRecovery {
              mode = "0755";
              text = ''
                #!/bin/sh
                # Act on interface events for physical interfaces
                IFACE="$1"
                ACTION="$2"

                case "$ACTION" in
                  up|connectivity-change|down)
                    ;;
                  *)
                    exit 0
                    ;;
                esac

                case "$IFACE" in
                  tun*|tap*|lo|docker*|br-*|veth*)
                    exit 0
                    ;;
                esac

                # Check if openconnect is running
                OPENCONNECT_PID=$(${pkgs.procps}/bin/pgrep -x openconnect)
                if [ -z "$OPENCONNECT_PID" ]; then
                  exit 0
                fi

                echo "NetworkManager: Interface $IFACE action $ACTION - checking VPN route"

                # Get VPN server from openconnect command line
                VPN_SERVER=$(${pkgs.procps}/bin/ps aux | grep '[o]penconnect' | grep -oP 'https://\K[^/]+' | head -1)
                if [ -z "$VPN_SERVER" ]; then
                  exit 0
                fi

                # Resolve VPN server IP via DNS with retry
                VPN_IP=""
                for i in $(${pkgs.coreutils}/bin/seq 1 30); do
                  VPN_IP=$(${pkgs.dnsutils}/bin/dig +short +timeout=2 "$VPN_SERVER" 2>&1 | ${pkgs.gnugrep}/bin/grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
                  if [ -n "$VPN_IP" ]; then
                    echo "Resolved VPN server $VPN_SERVER to $VPN_IP after $i attempt(s)"
                    break
                  fi
                  echo "DNS resolution failed for $VPN_SERVER, retrying... ($i/30)"
                  sleep 1
                done

                if [ -z "$VPN_IP" ]; then
                  echo "Failed to determine VPN server IP - giving up"
                  exit 0
                fi

                # Find interface with carrier that has a default route
                if [ "$ACTION" = "down" ] || [ "$ACTION" = "connectivity-change" ] || [ -z "$IFACE" ]; then
                  TARGET_DEV=""
                  TARGET_GW=""
                  for dev in $(ls /sys/class/net/ | grep -v -E "^(lo|tun|tap|docker|br-|veth)"); do
                    if [ -f "/sys/class/net/$dev/carrier" ]; then
                      CARRIER=$(cat "/sys/class/net/$dev/carrier" 2>/dev/null || echo "0")
                      if [ "$CARRIER" = "1" ] && [ "$dev" != "$IFACE" ]; then
                        for i in $(${pkgs.coreutils}/bin/seq 1 30); do
                          GW=$(${pkgs.iproute2}/bin/ip route show default dev "$dev" 2>/dev/null | ${pkgs.gawk}/bin/awk '{print $3}' | head -1)
                          if [ -n "$GW" ]; then
                            TARGET_DEV="$dev"
                            TARGET_GW="$GW"
                            echo "Found active interface $TARGET_DEV with gateway $TARGET_GW after $i second(s)"
                            break 2
                          fi
                          echo "Waiting for gateway on $dev... ($i/30)"
                          sleep 1
                        done
                      fi
                    fi
                  done
                else
                  TARGET_DEV="$IFACE"
                  TARGET_GW=""
                  for i in $(${pkgs.coreutils}/bin/seq 1 30); do
                    TARGET_GW=$(${pkgs.iproute2}/bin/ip route show default dev "$IFACE" 2>/dev/null | ${pkgs.gawk}/bin/awk '{print $3}' | head -1)
                    if [ -n "$TARGET_GW" ]; then
                      echo "Found gateway $TARGET_GW for $IFACE after $i second(s)"
                      break
                    fi
                    echo "Waiting for gateway on $IFACE... ($i/30)"
                    sleep 1
                  done
                fi

                if [ -n "$TARGET_GW" ] && [ -n "$TARGET_DEV" ]; then
                  ${pkgs.iproute2}/bin/ip route del "$VPN_IP" 2>/dev/null || true
                  echo "Updating route to VPN server $VPN_IP via $TARGET_GW dev $TARGET_DEV"
                  ${pkgs.iproute2}/bin/ip route add "$VPN_IP" via "$TARGET_GW" dev "$TARGET_DEV" 2>/dev/null || true

                  sleep 1
                  ${if cfg.enableDtls then ''
                  echo "Sending SIGTERM to openconnect (PID: $OPENCONNECT_PID) for full restart (DTLS mode)"
                  kill -TERM "$OPENCONNECT_PID"
                  for i in 1 2 3 4 5; do
                    sleep 1
                    if ! kill -0 "$OPENCONNECT_PID" 2>/dev/null; then
                      echo "openconnect exited after SIGTERM"
                      break
                    fi
                    if [ "$i" = "5" ]; then
                      echo "openconnect did not respond to SIGTERM, sending SIGKILL"
                      kill -9 "$OPENCONNECT_PID" 2>/dev/null || true
                    fi
                  done
                  '' else ''
                  echo "Sending SIGUSR2 to openconnect (PID: $OPENCONNECT_PID) to force reconnection"
                  kill -USR2 "$OPENCONNECT_PID"
                  ''}
                else
                  echo "No suitable gateway/interface found"
                fi
              '';
            };

            # Configuration file for nm-pulse-sso-service to read DTLS setting
            environment.etc."nm-pulse-sso/config" = {
              text = ''
                # Auto-generated by NixOS - do not edit manually
                ENABLE_DTLS=${if cfg.enableDtls then "true" else "false"}
              '';
            };

            # Disable rpfilter for reliable VPN reconnection after suspend/resume
            networking.firewall.checkReversePath =
              if cfg.enableRecovery
              then "loose"
              else true;
          };
        };
    };
}

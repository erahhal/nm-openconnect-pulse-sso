# NixOS module for nm-openconnect-pulse-sso
#
# Provides NetworkManager VPN plugin for Pulse Secure with browser-based SSO authentication.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.nm-pulse-sso;

  # CEF-based authentication browser
  pulse-browser-auth-base = pkgs.callPackage ./cef-auth/default.nix { };

  # Extract extension IDs from packages that provide passthru.extensionId
  extensionIds = lib.filter (id: id != null)
    (map (ext: ext.extensionId or null) cfg.extensions);

  # Script to pin extensions to the CEF toolbar before launch
  pinExtensionsScript = pkgs.writeShellScript "pin-extensions" ''
    PROFILE_DIR="$HOME/.cache/pulse-browser-auth/Default"
    PREFS_FILE="$PROFILE_DIR/Preferences"
    SECURE_PREFS="$PROFILE_DIR/Secure Preferences"
    PINNED_IDS='${builtins.toJSON extensionIds}'

    ${pkgs.coreutils}/bin/mkdir -p "$PROFILE_DIR"

    if [ -f "$PREFS_FILE" ]; then
      # Check if all desired extensions are already pinned (subset check).
      # Extra user-pinned extensions are preserved.
      MISSING=$(${pkgs.jq}/bin/jq --argjson desired "$PINNED_IDS" \
        '[($desired[] | select(. as $d | (.extensions.pinned_extensions // []) | index($d) | not))]' \
        "$PREFS_FILE" 2>/dev/null || echo "$PINNED_IDS")
      if [ "$MISSING" != "[]" ]; then
        # Merge desired into existing pinned list, preserving user-added extensions
        MERGED=$(${pkgs.jq}/bin/jq --argjson desired "$PINNED_IDS" \
          '((.extensions.pinned_extensions // []) + $desired) | unique' \
          "$PREFS_FILE" 2>/dev/null || echo "$PINNED_IDS")
        # Delete both Preferences and Secure Preferences together so Chrome recreates
        # them consistently on startup. Modifying Preferences without updating Secure
        # Preferences causes Chrome 142 (CEF_RUNTIME_STYLE_CHROME) to detect profile
        # tampering and crash before showing the browser window.
        ${pkgs.coreutils}/bin/rm -f "$PREFS_FILE"
        ${pkgs.coreutils}/bin/rm -f "$SECURE_PREFS"
        echo "{\"extensions\":{\"pinned_extensions\":$MERGED}}" | ${pkgs.jq}/bin/jq . > "$PREFS_FILE"
      fi
    fi
    if [ ! -f "$PREFS_FILE" ]; then
      # Create fresh Preferences with pinned extensions.
      # Chrome will create a matching Secure Preferences on startup.
      echo "{\"extensions\":{\"pinned_extensions\":$PINNED_IDS}}" | ${pkgs.jq}/bin/jq . > "$PREFS_FILE"
    fi
  '';

  # Wrap browser to load extensions if configured
  pulse-browser-auth = if cfg.extensions == [] then pulse-browser-auth-base
    else pkgs.symlinkJoin {
      name = "pulse-browser-auth-with-extensions";
      paths = [ pulse-browser-auth-base ];
      nativeBuildInputs = [ pkgs.makeWrapper ];
      postBuild = ''
        wrapProgram $out/bin/pulse-browser-auth \
          --add-flags "--extension ${lib.concatStringsSep "," cfg.extensions}" \
          ${lib.optionalString cfg.pinExtensions "--run ${pinExtensionsScript}"}
      '';
    };

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

  # Reset tool to clear the browser profile
  pulse-browser-reset = pkgs.writeShellScriptBin "pulse-browser-reset" ''
    PROFILE_DIR="$HOME/.cache/pulse-browser-auth"
    if [ ! -d "$PROFILE_DIR" ]; then
      echo "No browser profile found at $PROFILE_DIR"
      exit 0
    fi
    echo "This will delete the browser profile at:"
    echo "  $PROFILE_DIR"
    echo ""
    printf "Continue? [y/N] "
    read -r answer
    case "$answer" in
      [yY]|[yY][eE][sS]) ;;
      *) echo "Aborted."; exit 0 ;;
    esac
    rm -rf "$PROFILE_DIR"
    echo "Browser profile removed. Extensions will be re-installed on next VPN auth."
  '';

  # Diagnostic script with substituted paths
  diagnose-nm-pulse-vpn = pkgs.runCommand "diagnose-nm-pulse-vpn" { } ''
    mkdir -p $out/bin
    install -m755 ${pkgs.replaceVars ./scripts/diagnose.sh {
      inherit (pkgs) coreutils procps iproute2 gnugrep systemd networkmanager dnsutils iputils nettools;
    }} $out/bin/diagnose-nm-pulse-vpn
  '';

  # VPN reconnect script (for post-resume.target) — kills stale openconnect, triggers auto-reconnect
  vpn-reconnect-script = pkgs.runCommand "vpn-reconnect" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpn-reconnect.sh {
      inherit (pkgs) procps;
    }} $out
  '';

  # VPN auto-reconnect script — uses nmcli to re-establish VPN with retries
  vpn-auto-reconnect-script = pkgs.runCommand "vpn-auto-reconnect" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpn-auto-reconnect.sh {
      inherit (pkgs) procps coreutils networkmanager systemd gawk libnotify util-linux iproute2;
      sudo = pkgs.sudo;
      vpnName = cfg.vpnName;
    }} $out
  '';

  # Service restart script
  service-restart-script = pkgs.runCommand "service-restart" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/service-restart.sh {
      inherit (pkgs) procps networkmanager systemd gawk libnotify iproute2 coreutils;
      sudo = pkgs.sudo;
      vpnName = cfg.vpnName;
    }} $out
  '';

  # NetworkManager dispatcher script
  nm-dispatcher-script = pkgs.runCommand "nm-dispatcher" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/nm-dispatcher.sh {
      inherit (pkgs) procps coreutils iproute2 gawk systemd libnotify networkmanager;
      sudo = pkgs.sudo;
    }} $out
  '';

  # vpnc hook to set auto-reconnect flag on VPN connection
  vpnc-post-connect-auto-reconnect-flag = pkgs.runCommand "vpnc-post-connect-auto-reconnect-flag" { } ''
    install -Dm755 ${./scripts/vpnc/post-connect-auto-reconnect-flag.sh} $out
  '';

  # vpnc hook scripts
  vpnc-post-connect-default-route = pkgs.runCommand "vpnc-post-connect-default-route" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpnc/post-connect-default-route.sh {
      inherit (pkgs) iproute2;
    }} $out
  '';

  vpnc-post-connect-narrow-docker = pkgs.runCommand "vpnc-post-connect-narrow-docker" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpnc/post-connect-narrow-docker.sh {
      inherit (pkgs) iproute2 gnugrep;
    }} $out
  '';

  vpnc-reconnect-default-route = pkgs.runCommand "vpnc-reconnect-default-route" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpnc/reconnect-default-route.sh {
      inherit (pkgs) iproute2;
    }} $out
  '';

  vpnc-reconnect-narrow-docker = pkgs.runCommand "vpnc-reconnect-narrow-docker" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpnc/reconnect-narrow-docker.sh {
      inherit (pkgs) iproute2 gnugrep;
    }} $out
  '';

  vpnc-post-connect-flush-dns = pkgs.runCommand "vpnc-post-connect-flush-dns" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpnc/post-connect-flush-dns.sh {
      inherit (pkgs) systemd;
    }} $out
  '';

  vpnc-reconnect-flush-dns = pkgs.runCommand "vpnc-reconnect-flush-dns" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpnc/reconnect-flush-dns.sh {
      inherit (pkgs) systemd;
    }} $out
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
        Reconnection after suspend/resume or network changes is handled
        externally by the vpn-auto-reconnect service via nmcli.

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

    enableTcpKeepalive = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable TCP keepalive on the openconnect TLS channel.
        Prevents VPN disconnections when stateful firewalls consider
        idle TCP sessions as closed (common when DTLS/ESP carries most traffic).
        When enabled, applies the TCP keepalive patch to openconnect and
        passes --keepalive to the openconnect command.
      '';
    };

    tcpKeepaliveInterval = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = 120;
      description = ''
        TCP keepalive idle interval in seconds. Only used when
        enableTcpKeepalive is true. When null, uses system defaults.
      '';
    };

    mtu = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = 1300;
      description = ''
        MTU for the VPN tunnel interface. Passed as --mtu to openconnect
        and enforced as a ceiling on INTERNAL_IP4_MTU in the helper script.

        Default 1300 is a universal safe value: outer ESP packets reach
        ~1385 bytes (1300 + 85 worst-case overhead), fitting within path
        MTUs as low as 1385 — covering hotels, airports, mobile hotspots,
        and VPN-over-VPN setups with ~7% throughput overhead on standard
        networks.

        Set to null to use the server-provided MTU (typically 1400) for
        maximum throughput on known-good networks. Decrease further for
        extremely constrained paths (e.g. 1280 for IPv6-minimum safety).
      '';
    };

    extensions = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      description = ''
        List of unpacked Chrome extension directories to load in the
        CEF authentication browser. Each entry should be a derivation
        whose output is an unpacked extension directory containing a
        manifest.json. Derivations may include passthru.extensionId
        for toolbar pinning support.
      '';
    };

    pinExtensions = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Pin loaded extensions to the CEF browser toolbar so they are
        always visible. Requires extensions to have passthru.extensionId.
        Only effective when extensions are configured.
      '';
    };

    restartBeforeServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Systemd services that should wait for VPN restart to complete
        before starting. Use this when other services (e.g., home-manager)
        need VPN access during NixOS rebuild.
      '';
      example = [ "home-manager-erahhal.service" ];
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
    # Apply plasma-nm overlay for KDE integration, and optionally patch openconnect
    nixpkgs.overlays = [
      (import ./plasma-nm-overlay.nix {
        plasma-plugin-src = ./plasma-plugin;
      })
    ] ++ lib.optionals cfg.enableTcpKeepalive [
      (final: prev: {
        openconnect = prev.openconnect.overrideAttrs (oldAttrs: {
          patches = (oldAttrs.patches or []) ++ [
            ./patches/openconnect-tcp-keepalive.patch
          ];
        });
      })
    ];

    # Install the VPN plugin
    networking.networkmanager.plugins = [
      nm-pulse-sso
      pkgs.networkmanager-openconnect  # Keep standard openconnect available
    ];

    # Make browser binaries and diagnostic tools available system-wide
    environment.systemPackages = [
      pkgs.openconnect
      nm-pulse-sso
      diagnose-nm-pulse-vpn
    ] ++ lib.optionals (!cfg.enableSelenium) [
      pulse-browser-auth
      pulse-browser-setup
      pulse-browser-reset
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

    # Systemd service to kill stale openconnect after resume and trigger auto-reconnect
    systemd.services.vpn-reconnect = lib.mkIf cfg.enableRecovery {
      description = "Kill stale VPN after resume and trigger auto-reconnect";
      wantedBy = [ "post-resume.target" ];
      after = [ "post-resume.target" ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = vpn-reconnect-script;
      };
    };

    # External VPN auto-reconnect service — uses nmcli (same as a user would)
    # Triggered by: vpn-reconnect (post-resume), nm-dispatcher (network change)
    systemd.services.vpn-auto-reconnect = lib.mkIf cfg.enableRecovery {
      description = "Auto-reconnect VPN via nmcli";
      after = [ "network-online.target" "NetworkManager.service" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = vpn-auto-reconnect-script;
        TimeoutStartSec = 120;
      };
    };

    # Kill old nm-pulse-sso-service when the package changes and reconnect VPN
    systemd.services.nm-pulse-sso-restart = {
      description = "Restart nm-pulse-sso-service on package update";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "NetworkManager.service" ];
      before = cfg.restartBeforeServices;
      restartTriggers = [ nm-pulse-sso cfg.enableDtls cfg.enableTcpKeepalive cfg.tcpKeepaliveInterval ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = service-restart-script;
        TimeoutStartSec = 120;
      };
    };

    # vpnc hook to add default route after initial VPN connection
    environment.etc."vpnc/post-connect.d/add-default-route" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = vpnc-post-connect-default-route;
    };

    # vpnc hook to narrow VPN route for Docker compatibility
    environment.etc."vpnc/post-connect.d/narrow-docker-route" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = vpnc-post-connect-narrow-docker;
    };

    # vpnc hook to re-apply default route after VPN reconnection
    environment.etc."vpnc/reconnect.d/fix-default-route" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = vpnc-reconnect-default-route;
    };

    # vpnc hook to narrow VPN route after reconnection for Docker compatibility
    environment.etc."vpnc/reconnect.d/narrow-docker-route" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = vpnc-reconnect-narrow-docker;
    };

    # vpnc hook to set auto-reconnect flag on VPN connection
    environment.etc."vpnc/post-connect.d/00-auto-reconnect-flag" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = vpnc-post-connect-auto-reconnect-flag;
    };

    # vpnc hook to flush DNS caches after VPN connection
    environment.etc."vpnc/post-connect.d/flush-dns" = {
      mode = "0755";
      source = vpnc-post-connect-flush-dns;
    };

    # vpnc hook to flush DNS caches after VPN reconnection
    environment.etc."vpnc/reconnect.d/flush-dns" = {
      mode = "0755";
      source = vpnc-reconnect-flush-dns;
    };

    # NetworkManager dispatcher to fix VPN route and trigger reconnection when interface changes
    environment.etc."NetworkManager/dispatcher.d/90-vpn-reconnect" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = nm-dispatcher-script;
    };

    # Configuration file for nm-pulse-sso-service to read runtime settings
    environment.etc."nm-pulse-sso/config" = {
      text = ''
        # Auto-generated by NixOS - do not edit manually
        ENABLE_DTLS=${if cfg.enableDtls then "true" else "false"}
        ENABLE_TCP_KEEPALIVE=${if cfg.enableTcpKeepalive then "true" else "false"}
        TCP_KEEPALIVE_INTERVAL=${if cfg.tcpKeepaliveInterval != null then toString cfg.tcpKeepaliveInterval else ""}
        ${lib.optionalString (cfg.mtu != null) "VPN_MTU=${toString cfg.mtu}"}
      '';
    };

    # Disable rpfilter for reliable VPN reconnection after suspend/resume
    networking.firewall.checkReversePath =
      if cfg.enableRecovery
      then "loose"
      else true;
  };
}

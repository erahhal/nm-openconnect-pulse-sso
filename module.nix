# NixOS module for nm-openconnect-pulse-sso
#
# Provides NetworkManager VPN plugin for Pulse Secure with browser-based SSO authentication.

{ config, lib, pkgs, ... }:

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

  # Diagnostic script with substituted paths
  diagnose-nm-pulse-vpn = pkgs.runCommand "diagnose-nm-pulse-vpn" { } ''
    mkdir -p $out/bin
    install -m755 ${pkgs.replaceVars ./scripts/diagnose.sh {
      inherit (pkgs) coreutils procps iproute2 gnugrep systemd networkmanager dnsutils iputils nettools;
    }} $out/bin/diagnose-nm-pulse-vpn
  '';

  # VPN reconnect script (for post-resume.target)
  vpn-reconnect-script = pkgs.runCommand "vpn-reconnect" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/vpn-reconnect.sh {
      inherit (pkgs) coreutils dnsutils gnugrep networkmanager;
    }} $out
  '';

  # Service restart script
  service-restart-script = pkgs.runCommand "service-restart" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/service-restart.sh {
      inherit (pkgs) procps networkmanager systemd gawk libnotify;
      sudo = pkgs.sudo;
      vpnName = cfg.vpnName;
    }} $out
  '';

  # NetworkManager dispatcher script
  nm-dispatcher-script = pkgs.runCommand "nm-dispatcher" { } ''
    install -Dm755 ${pkgs.replaceVars ./scripts/nm-dispatcher.sh {
      inherit (pkgs) coreutils dnsutils gnugrep gawk iproute2 networkmanager;
    }} $out
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

    # Make browser binaries and diagnostic tools available system-wide
    environment.systemPackages = [
      pkgs.openconnect
      nm-pulse-sso
      diagnose-nm-pulse-vpn
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
      wants = [ "network-online.target" ];
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
        ExecStart = service-restart-script;
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

    # NetworkManager dispatcher to fix VPN route and trigger reconnection when interface changes
    environment.etc."NetworkManager/dispatcher.d/90-vpn-reconnect" = lib.mkIf cfg.enableRecovery {
      mode = "0755";
      source = nm-dispatcher-script;
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
}

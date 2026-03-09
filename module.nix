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
      inherit (pkgs) procps dnsutils gnugrep iproute2 gawk;
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
      inherit (pkgs) procps coreutils dnsutils gnugrep iproute2 gawk networkmanager;
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
      restartTriggers = [ nm-pulse-sso cfg.enableDtls cfg.enableTcpKeepalive cfg.tcpKeepaliveInterval ];

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
      '';
    };

    # Disable rpfilter for reliable VPN reconnection after suspend/resume
    networking.firewall.checkReversePath =
      if cfg.enableRecovery
      then "loose"
      else true;
  };
}

# nm-openconnect-pulse-sso

NetworkManager VPN plugin for Pulse Secure / OpenConnect with browser-based SSO/SAML authentication.

## Overview

This plugin provides full NetworkManager integration for Pulse Secure VPNs that require browser-based SAML/SSO authentication. It appears in system tray apps (gnome-shell, KDE Plasma, nm-applet) as a standard VPN connection type.

Key features:
- CEF (Chromium Embedded Framework) browser with WebAuthn/FIDO2 support (hardware keys like YubiKey)
- Custom D-Bus VPN service with automatic reconnection after suspend/resume and network changes
- DTLS/ESP mode for better VPN performance
- Browser extension support (e.g., Bitwarden password manager)
- User-agent switching for Okta compatibility
- KDE Plasma integration plugin
- NixOS module with declarative configuration
- Selenium WebDriver as an alternative auth engine

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        User Space (runs as user)                     │
│  ┌──────────────┐                                                    │
│  │ NM Frontend  │  gnome-shell / KDE Plasma / nm-applet              │
│  └──────┬───────┘                                                    │
│         │                                                            │
│  ┌──────▼──────────────────────┐    ┌────────────────────────────┐   │
│  │ pulse-sso-auth-dialog       │───▶│ pulse-browser-auth (CEF)   │   │
│  │ (NM auth-dialog protocol)   │    │ Chromium browser window    │   │
│  │ Reads stdin, outputs cookie │    │ Monitors for DSID cookie   │   │
│  └─────────────────────────────┘    │ WebAuthn/FIDO2, extensions │   │
│                                     └────────────────────────────┘   │
├──────────────────────────────────────────────────────────────────────┤
│                        Root Space (runs as root)                     │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ nm-pulse-sso-service.py (custom D-Bus VPN plugin)              │  │
│  │ - Implements org.freedesktop.NetworkManager.VPN.Plugin         │  │
│  │ - Spawns openconnect with -C <cookie> --protocol=pulse         │  │
│  │ - Auth failure retry (up to 3 attempts, re-launches browser)   │  │
│  │ - Reconnection via SIGUSR2 (SSL) or SIGTERM (DTLS)             │  │
│  │                                                                │  │
│  │   ┌────────────────────────────────────┐                       │  │
│  │   │ nm-pulse-sso-helper                │                       │  │
│  │   │ Called by openconnect via --script │                       │  │
│  │   │ Configures TUN, routes, DNS        │                       │  │
│  │   │ Reports IP config back via D-Bus   │                       │  │
│  │   └────────────────────────────────────┘                       │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  Recovery layer (systemd + NM dispatcher):                           │
│  - vpn-reconnect.sh: post-resume.target service                      │
│  - nm-dispatcher.sh: interface change handler                        │
│  - vpnc hooks: default route fixup, Docker route narrowing           │
└──────────────────────────────────────────────────────────────────────┘
```

## Components

### pulse-browser-auth (CEF Browser)

C++ application using Chromium Embedded Framework. Navigates to the VPN URL, opens a browser window for SAML authentication, and monitors cookies. Outputs `DSID=<value>` on stdout when the authentication cookie is set.

Features:
- User-agent switching: starts with a Windows UA to bypass Okta's Linux blocking, then switches to Linux UA after the SAML page loads
- Browser extension loading via `--extension <path>` (comma-separated for multiple)
- WebAuthn/FIDO2 support for hardware security keys
- Popup blocking (single browser window)
- Profile/cache persisted at `~/.cache/pulse-browser-auth`
- 300-second default authentication timeout

### pulse-sso-auth-dialog (NM Auth Dialog)

Python script following NetworkManager's auth-dialog stdin/stdout protocol. Reads VPN settings from NM (`DATA_KEY`/`DATA_VAL` pairs), launches the CEF browser, and returns the DSID cookie and server certificate fingerprint to NetworkManager. No GUI of its own -- the CEF browser window is the user interface.

If an existing cookie is available and valid, it skips the browser entirely.

### nm-pulse-sso-service.py (D-Bus VPN Service)

Custom Python D-Bus service implementing `org.freedesktop.NetworkManager.VPN.Plugin`. This is **not** the standard nm-openconnect-service -- it is a purpose-built service for Pulse SSO.

Responsibilities:
- Receives `Connect()` / `ConnectInteractive()` calls from NetworkManager with credentials
- Spawns `openconnect --protocol=pulse -C <cookie>` with the helper script
- Reads runtime config from `/etc/nm-pulse-sso/config` (DTLS mode, TCP keepalive)
- Handles openconnect exit codes: auth failures (exit 2) trigger browser re-launch via `systemd-run`; other failures restart openconnect with the existing cookie
- Auth failure retry: up to 3 consecutive failures before giving up
- Reconnection retry: up to 10 attempts with 3-second intervals
- Uses multiple `systemd-run` launch strategies to propagate graphical session environment (Wayland/X11)

### nm-pulse-sso-helper (openconnect script)

Called by openconnect via `--script`. Reads openconnect environment variables (TUNDEV, INTERNAL_IP4_ADDRESS, DNS servers, split-tunnel routes, etc.), invokes `vpnc-script` for standard network setup, and reports IP configuration back to the D-Bus service.

DNS handling: prepends the local gateway IP to the DNS list and sets VPN DNS priority to 100 (fallback), so local DNS resolves quickly while VPN DNS provides access to internal domains.

### Recovery Scripts

- **vpn-reconnect.sh** -- systemd service on `post-resume.target`. Waits for network connectivity, fixes the VPN server route to the physical interface, sends SIGUSR2 (non-DTLS) or SIGTERM (DTLS) to openconnect
- **nm-dispatcher.sh** -- NM dispatcher (`90-vpn-reconnect`) for connectivity-change and interface-down events
- **vpnc hooks** -- default route fixup and Docker route narrowing on connect/reconnect
- **service-restart.sh** -- kills old service process on NixOS rebuild

### KDE Plasma Plugin

Qt/C++ plugin that registers the VPN type in KDE Plasma's network applet, allowing users to create and manage Pulse SSO VPN connections from KDE system settings.

### Diagnostic Script

`diagnose-nm-pulse-vpn [minutes]` collects logs, network state, routing tables, DNS config, process info, and connectivity tests. Output is saved to `/tmp/vpn-diagnose-<timestamp>.log`. Defaults to 15 minutes of log lookback.

## Usage

### Creating a VPN Connection

The plugin does not include an nm-connection-editor UI component, so connections should be created via `nmcli` or the NixOS module's declarative configuration. The KDE Plasma plugin does provide a settings UI.

**CLI (nmcli):**
```bash
nmcli connection add type vpn con-name "Pulse VPN" \
  vpn-type openconnect-pulse-sso \
  vpn.data "gateway=https://vpn.example.com/saml,protocol=pulse"
```

### Connecting

**GUI:** Click on the VPN in your system tray or network settings.

**CLI:**
```bash
nmcli connection up "Pulse VPN"
```

A CEF browser window opens for SAML/SSO authentication. If extensions are configured (e.g., Bitwarden), they are loaded in the browser. Once authentication completes and the DSID cookie is set, the browser closes automatically and the VPN connects.

### Browser Setup

Use `pulse-browser-setup` to launch the CEF browser pointed at the Chrome Web Store for installing extensions and configuring settings. Settings persist in `~/.cache/pulse-browser-auth`.

## NixOS Integration

Add this flake as an input and use the NixOS module:

```nix
{
  inputs.nm-openconnect-pulse-sso.url = "github:erahhal/nm-openconnect-pulse-sso";

  outputs = { self, nixpkgs, nm-openconnect-pulse-sso, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        nm-openconnect-pulse-sso.nixosModules.default
        {
          services.nm-pulse-sso = {
            enable = true;
            gateway = "https://vpn.example.com/saml";
          };
        }
      ];
    };
  };
}
```

### All Options

```nix
services.nm-pulse-sso = {
  enable = true;
  gateway = "https://vpn.example.com/saml";  # Required: VPN gateway URL
  vpnName = "Pulse VPN";              # Connection name (default: "Pulse VPN")
  enableDtls = true;                   # DTLS/ESP for better performance (default: true)
  enableRecovery = true;               # Auto-reconnect scripts (default: true)
  enableTcpKeepalive = false;          # TCP keepalive on TLS channel (default: false)
  tcpKeepaliveInterval = 120;          # Keepalive interval in seconds (default: 120)
  enableSelenium = false;              # Use Selenium instead of CEF (default: false)
  extensions = [];                     # Browser extension packages (default: [])
  pinExtensions = true;                # Pin extensions to toolbar (default: true)
};
```

### Browser Extensions

Extensions are unpacked Chrome extension directories loaded into the CEF browser:

```nix
services.nm-pulse-sso = {
  enable = true;
  gateway = "https://vpn.example.com/saml";
  extensions = [
    (pkgs.callPackage ./extensions/bitwarden.nix {})
  ];
};
```

### What the Module Configures

The module automatically:
- Installs the NM plugin, openconnect, and CEF browser
- Creates the VPN connection profile declaratively
- Sets up D-Bus policy for the VPN service
- Installs recovery scripts (vpn-reconnect systemd service, NM dispatcher, vpnc hooks)
- Applies KDE Plasma overlay for desktop integration
- Sets `rpfilter` to "loose" when recovery is enabled (required for reliable reconnection)
- Optionally patches openconnect for TCP keepalive
- Installs `diagnose-nm-pulse-vpn` and `pulse-browser-setup` system-wide

## Troubleshooting

### Browser does not open
- CEF mode (default): ensure `pulse-browser-auth` is available and `~/.cache/pulse-browser-auth` is writable
- Selenium mode: ensure `chromedriver` and `chromium` are in PATH
- Check `journalctl -u NetworkManager` for auth-dialog launch errors
- On Wayland, the service uses `systemd-run` with environment propagation; verify WAYLAND_DISPLAY is set

### Authentication times out
- Default timeout is 300 seconds
- Check `journalctl -u NetworkManager` for CEF/browser errors
- User-agent switching may need adjustment if the identity provider blocks requests

### VPN connects but cannot reach internal resources
- Run `diagnose-nm-pulse-vpn` to collect diagnostic info
- Check DNS configuration and routes in the diagnostic output
- If using Docker, the vpnc hooks automatically narrow routes to avoid conflicts

### Reconnection after suspend
- With `enableRecovery = true` (default), the module installs recovery scripts automatically
- DTLS mode uses full restart (SIGTERM); non-DTLS mode uses graceful reconnect (SIGUSR2)
- If the cookie has expired, a browser window opens for re-authentication (up to 3 attempts)
- `rpfilter` is automatically set to "loose" mode
- Check `journalctl -u vpn-reconnect` for post-resume logs

### Diagnostics
```bash
diagnose-nm-pulse-vpn        # Collect last 15 minutes of logs
diagnose-nm-pulse-vpn 30     # Collect last 30 minutes of logs
```
Output is saved to `/tmp/vpn-diagnose-<timestamp>.log`.

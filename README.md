# nm-openconnect-pulse-sso

NetworkManager VPN plugin for Pulse Secure / OpenConnect with browser-based SSO/SAML authentication.

## Overview

This plugin provides full NetworkManager integration for Pulse Secure VPNs that require browser-based SAML/SSO authentication. It appears in system tray apps (gnome-shell, KDE Plasma, nm-applet) as a standard VPN connection type.

Key features:
- CEF (Chromium Embedded Framework) browser with WebAuthn/FIDO2 support (hardware keys like YubiKey)
- Custom D-Bus VPN service with external auto-reconnect via systemd (survives suspend/resume and network changes)
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
│  │ - On crash: retains cookie, stays alive 5 min for reconnect    │  │
│  │ - Cleans up stale VPN routes; 5 failures → re-auth             │  │
│  │ - On user disconnect: removes flag file, clears state, quits   │  │
│  │                                                                │  │
│  │   ┌────────────────────────────────────┐                       │  │
│  │   │ nm-pulse-sso-helper                │                       │  │
│  │   │ Called by openconnect via --script │                       │  │
│  │   │ Configures TUN, routes, DNS        │                       │  │
│  │   │ Reports IP config back via D-Bus   │                       │  │
│  │   └────────────────────────────────────┘                       │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  Recovery layer (external systemd services + NM dispatcher):         │
│  - vpn-auto-reconnect.sh: reconnect via nmcli (retries, backoff)     │
│  - vpn-reconnect.sh: post-resume — kill stale openconnect, trigger   │
│  - nm-dispatcher.sh: interface change — kill or re-trigger reconnect │
│  - vpnc hooks: auto-reconnect flag, default route fixup, Docker      │
│  - Flag file: /run/vpn-auto-reconnect tracks desired VPN state       │
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
- On openconnect crash: retains cookie for reconnect, stays alive with 5-minute idle timeout
- Cleans up stale VPN server routes before starting openconnect (handles ungraceful exits where routes point to old gateways)
- After 5 consecutive restart failures, treats the cookie as stale/IP-bound and triggers re-authentication
- Cooperates with NM's reactive Disconnect() when openconnect dies externally: emits Stopped, then re-activates through NM's ActivateConnection D-Bus API
- Reuses internally-stored cookie when NM doesn't provide one in Connect()
- On user disconnect (via NM): removes `/run/vpn-auto-reconnect` flag, clears credentials, quits
- All primary reconnection is handled externally by `vpn-auto-reconnect.service` via `nmcli connection up`
- Uses multiple `systemd-run` launch strategies to propagate graphical session environment (Wayland/X11)

### nm-pulse-sso-helper (openconnect script)

Called by openconnect via `--script`. Reads openconnect environment variables (TUNDEV, INTERNAL_IP4_ADDRESS, DNS servers, split-tunnel routes, etc.), invokes `vpnc-script` for standard network setup, and reports IP configuration back to the D-Bus service.

DNS handling: prepends the local gateway IP to the DNS list and sets VPN DNS priority to 100 (fallback), so local DNS resolves quickly while VPN DNS provides access to internal domains.

### Recovery Scripts

All reconnection goes through `nmcli connection up` via the external auto-reconnect service, avoiding NM plugin state machine conflicts.

- **vpn-auto-reconnect.sh** -- external systemd oneshot service that reconnects VPN via `nmcli connection up`. Checks flag file, waits for network, retries 5 times with increasing backoff, sends desktop notifications
- **vpn-reconnect.sh** -- systemd service on `post-resume.target`. Kills stale openconnect and triggers `vpn-auto-reconnect.service`
- **nm-dispatcher.sh** -- NM dispatcher (`90-vpn-reconnect`) for connectivity-change, interface-down, and interface-up events. Kills openconnect first (before route update), uses 120-second cooldown to prevent flapping on transient WiFi glitches, updates VPN server route as best-effort (checks routing table first, falls back to DNS)
- **vpnc hooks** -- auto-reconnect flag file creation (`/run/vpn-auto-reconnect`), default route fixup, Docker route narrowing
- **service-restart.sh** -- kills old service process on NixOS rebuild

**Flag file pattern:** `/run/vpn-auto-reconnect` is created on successful VPN connection and removed on user-initiated disconnect. Recovery scripts check this flag to decide whether reconnection is desired.

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

### Reconnection after suspend or network change
- With `enableRecovery = true` (default), the module installs recovery scripts automatically
- After suspend/resume: stale openconnect is killed, `vpn-auto-reconnect.service` re-establishes the VPN via `nmcli`
- On network changes (ethernet→WiFi, interface down/up): same flow — kill openconnect if running, trigger auto-reconnect
- The plugin retains the authentication cookie for 5 minutes after a crash, so reconnects often succeed without re-authentication
- After 5 consecutive reconnect failures, the plugin treats the cookie as stale and automatically triggers re-authentication
- The dispatcher uses a 120-second cooldown to prevent rapid restart loops from transient WiFi glitches
- The service cleans up stale VPN server routes from previous ungraceful exits before reconnecting
- `rpfilter` is automatically set to "loose" mode
- Check `journalctl -u vpn-auto-reconnect` for reconnect logs
- Check `journalctl | grep 90-vpn-reconnect` for dispatcher logs

### Diagnostics
```bash
diagnose-nm-pulse-vpn        # Collect last 15 minutes of logs
diagnose-nm-pulse-vpn 30     # Collect last 30 minutes of logs
```
Output is saved to `/tmp/vpn-diagnose-<timestamp>.log`.

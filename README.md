# nm-openconnect-pulse-sso

NetworkManager VPN plugin for OpenConnect Pulse with browser-based SSO/SAML authentication.

## Overview

This plugin provides full NetworkManager integration for Pulse Secure VPNs that require browser-based SAML/SSO authentication. It appears in system tray apps (gnome-shell, KDE Plasma, nm-applet) as a standard VPN connection type.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        User Space                                    │
│  ┌──────────────┐                                                    │
│  │ NM Frontend  │  gnome-shell / KDE / nm-applet                     │
│  └──────┬───────┘                                                    │
│         │                                                            │
│  ┌──────▼───────────────────┐    ┌────────────────────────────┐      │
│  │ nm-pulse-sso-auth-dialog │───▶│ pulse-sso-auth (standalone)│      │
│  │ (GTK progress UI)        │    │ Selenium browser automation│      │
│  └──────────────────────────┘    │ Returns DSID cookie        │      │
│                                  └────────────────────────────┘      │
├──────────────────────────────────────────────────────────────────────┤
│                        Root Space                                    │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ nm-openconnect-service (reused from networkmanager-openconnect)│  │
│  │ - Spawns openconnect with -C <cookie> --protocol=pulse         │  │
│  │ - Manages TUN device lifecycle                                 │  │
│  │ - Reports IP config to NetworkManager                          │  │
│  │ - NM handles reconnection natively                             │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

## Components

### pulse-sso-auth (Standalone CLI)

Browser automation tool for retrieving DSID cookies from Pulse VPN with SAML/SSO.

```bash
# Get cookie in NetworkManager format
pulse-sso-auth --url https://vpn.example.com/emp --format nm

# Get cookie as JSON
pulse-sso-auth --url https://vpn.example.com/emp --format json
```

### nm-pulse-sso-auth-dialog

NetworkManager authentication dialog that:
1. Receives VPN settings from NetworkManager via stdin
2. Shows a GTK progress dialog
3. Launches `pulse-sso-auth` to handle browser authentication
4. Returns the cookie to NetworkManager via stdout

## Usage

### Creating a VPN Connection

After installing the plugin, you can create a connection via:

**GUI (nm-connection-editor):**
1. Add new VPN connection
2. Select "OpenConnect Pulse SSO" as the VPN type
3. Enter the gateway URL (e.g., `https://vpn.example.com/saml`)
4. Save

**CLI (nmcli):**
```bash
nmcli connection add type vpn con-name "Pulse VPN" \
  vpn-type openconnect-pulse-sso \
  vpn.data "gateway=https://vpn.example.com/saml,protocol=pulse"
```

### Connecting

**GUI:** Click on the VPN in your system tray or network settings

**CLI:**
```bash
nmcli connection up "Pulse VPN"
```

A browser window will open for SAML authentication. Once complete, the VPN connects automatically.

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

The module automatically:
- Installs the NM plugin
- Configures NetworkManager to use it
- Creates the VPN connection profile

## Troubleshooting

### Browser doesn't open
- Ensure `chromedriver` and `chromium` are in PATH
- Check that the Chrome profile directory is writable (`~/.config/pulse-sso-auth`)

### Authentication times out
- The default timeout is 300 seconds
- Use `--timeout` flag with `pulse-sso-auth` for longer timeouts

### VPN connects but can't reach internal resources
- Check that DNS is configured correctly
- Verify routes are being added (NetworkManager handles this automatically)

### Reconnection after suspend
- NetworkManager handles reconnection natively
- For reliable reconnection, set `net.ipv4.conf.all.rp_filter` to "loose" mode (value 2)

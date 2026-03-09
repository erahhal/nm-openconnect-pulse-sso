---
name: vpn-debug
description: |
  Debug nm-openconnect-pulse-sso VPN plugin issues.
  Activate when troubleshooting VPN connectivity, authentication, or reconnection problems.
  Keywords:
  - VPN, vpn, openconnect, pulse-sso, pulse sso
  - vpn disconnect, vpn won't connect, vpn drops
  - reconnect, resume, suspend, network change
  - auth failure, cookie, DSID, SAML, SSO
  - nm-pulse-sso, pulse-browser-auth, auth-dialog
  - tun0, route, DNS, openconnect exit
user-invocable: true
allowed_tools: Bash, Read, Grep, Glob
---

# nm-openconnect-pulse-sso Debugging Guide

## Architecture Quick Reference

```
NM Frontend (user clicks Connect)
  -> pulse-sso-auth-dialog    (runs as user, NM stdin/stdout protocol)
    -> pulse-browser-auth      (CEF browser, outputs DSID cookie)
  -> nm-pulse-sso-service.py   (D-Bus VPN plugin, runs as root)
    -> openconnect --protocol=pulse -C <cookie>
      -> nm-pulse-sso-helper   (--script callback, configures TUN/routes/DNS)

Recovery layer:
  - vpn-reconnect.sh          (systemd post-resume.target service)
  - 90-vpn-reconnect           (NM dispatcher for interface changes)
  - vpnc hooks                 (default route fixup, Docker route narrowing)
```

## First Steps

Always start by running the diagnostic script to collect system state:

```bash
diagnose-nm-pulse-vpn         # last 15 minutes of logs
diagnose-nm-pulse-vpn 30      # last 30 minutes
```

Output is saved to `/tmp/vpn-diagnose-<timestamp>.log`. Read this file first.

## Key Diagnostic Commands

### Process state
```bash
ps aux | grep -E '(openconnect|nm-pulse-sso)'
systemctl status nm-pulse-sso-service
```

### VPN service logs (most useful)
```bash
journalctl -u NetworkManager --since "15 minutes ago" | grep -iE '(pulse|openconnect|sso)'
```

### Post-resume / reconnect logs
```bash
journalctl -u vpn-reconnect --since "15 minutes ago"
journalctl --since "15 minutes ago" | grep "90-vpn-reconnect"
journalctl --since "15 minutes ago" | grep -iE '(suspend|resume|sleep)'
```

### Network state
```bash
nmcli connection show --active | grep vpn
nmcli device status
ip addr show dev tun0
ip -4 route show
ip route show default
resolvectl status
```

### Configuration
```bash
cat /etc/nm-pulse-sso/config
ls -la /etc/NetworkManager/dispatcher.d/90-vpn-reconnect
ls -la /etc/vpnc/post-connect.d/ /etc/vpnc/reconnect.d/
```

## Common Failure Scenarios

### VPN won't connect at all

1. Check if the D-Bus service started:
   ```bash
   journalctl -u NetworkManager --since "5 minutes ago" | grep -i pulse
   ```
2. Check if auth-dialog launched and the browser opened:
   - Look for "Starting openconnect" or "auth failure" in logs
   - If no logs at all: the NM plugin may not be installed (`ls /etc/NetworkManager/VPN/nm-pulse-sso-service.name`)
3. Check if the gateway is reachable:
   ```bash
   curl -sI https://<gateway-url> | head -5
   ```
4. Check if CEF browser is available:
   ```bash
   which pulse-browser-auth
   ```

### VPN disconnects after suspend/resume

1. Check if the vpn-reconnect service ran:
   ```bash
   journalctl -u vpn-reconnect --since "5 minutes ago"
   ```
2. Check if route to VPN server was fixed:
   - After resume, the route to the VPN server IP must go through the physical interface (e.g., wlan0, eth0), NOT through tun0
   ```bash
   ip route get <vpn-server-ip>
   ```
3. Check if openconnect received the reconnect signal:
   - Non-DTLS mode: SIGUSR2 (graceful SSL reconnect)
   - DTLS mode: SIGTERM (full restart, service re-launches openconnect)
4. Verify rpfilter is loose (required for reconnection):
   ```bash
   sysctl net.ipv4.conf.all.rp_filter   # should be 2
   ```

### VPN disconnects on network change (wifi switch, ethernet unplug)

1. Check dispatcher ran:
   ```bash
   journalctl --since "5 minutes ago" | grep "90-vpn-reconnect"
   ```
2. Check which event triggered it (look for `connectivity-change` or `down` action)
3. Verify route update succeeded

### Authentication failure loop

OpenConnect exit code 2 = auth failure. The service retries up to 3 times.

1. Check how many failures occurred:
   ```bash
   journalctl -u NetworkManager --since "15 minutes ago" | grep -i "auth.fail"
   ```
2. If the browser opens repeatedly but auth keeps failing:
   - The DSID cookie may be rejected by the server
   - Try clearing the browser profile: `rm -rf ~/.cache/pulse-browser-auth`
   - Check if the identity provider (Okta, etc.) is blocking the browser
3. If the browser never opens:
   - Check systemd-run launch errors in logs
   - Verify DISPLAY or WAYLAND_DISPLAY is set in the user session

### OpenConnect crashes (non-auth exit codes)

1. Check the exit code:
   ```bash
   journalctl -u NetworkManager --since "15 minutes ago" | grep "exited with code"
   ```
2. Exit code 2 = auth failure (handled specially, see above)
3. Other exit codes: service auto-restarts with the existing cookie after 2 seconds
4. If crashes are persistent:
   - Check DTLS config: `cat /etc/nm-pulse-sso/config`
   - Try disabling DTLS in NixOS config (`enableDtls = false`) to rule out UDP/ESP issues
   - Check kernel logs: `dmesg | tail -50`

## DTLS vs Non-DTLS Behavior

Configuration in `/etc/nm-pulse-sso/config`:
- `ENABLE_DTLS=true`: openconnect uses UDP/ESP tunnel (better performance). Reconnection sends SIGTERM (full restart). If cookie expired, browser opens for re-auth.
- `ENABLE_DTLS=false`: openconnect uses `--no-dtls` (TCP/SSL only). Reconnection sends SIGUSR2 (graceful reconnect without re-auth).

DTLS is the default and generally more stable.

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/nm-pulse-sso/config` | Runtime settings (DTLS, TCP keepalive) |
| `/etc/NetworkManager/VPN/nm-pulse-sso-service.name` | NM plugin descriptor |
| `/etc/NetworkManager/dispatcher.d/90-vpn-reconnect` | Interface change handler |
| `/etc/vpnc/post-connect.d/` | Scripts run after VPN connects |
| `/etc/vpnc/reconnect.d/` | Scripts run after VPN reconnects |
| `~/.cache/pulse-browser-auth/` | CEF browser profile, cookies, extensions |

## Key Source Files

When deeper investigation into the code is needed:

| File | What to look for |
|------|-----------------|
| `vpn-service/nm-pulse-sso-service.py` | D-Bus service logic, auth retry, openconnect spawn, signal handling |
| `vpn-service/nm-pulse-sso-helper` | IP config reporting, DNS setup, route parsing |
| `auth-dialog/pulse-sso-auth-dialog` | Auth-dialog protocol, CEF launch, cookie extraction |
| `cef-auth/main.cc` | CEF browser behavior, UA switching, cookie monitoring, extensions |
| `scripts/vpn-reconnect.sh` | Post-resume reconnection logic |
| `scripts/nm-dispatcher.sh` | Network change detection and handling |
| `scripts/diagnose.sh` | What the diagnostic script checks |
| `module.nix` | NixOS module options and what gets installed |

## OpenConnect Exit Codes

| Code | Meaning | Service behavior |
|------|---------|-----------------|
| 0 | Clean exit | Normal shutdown |
| 2 | Auth failure | Re-launches browser (up to 3 retries) |
| Other | Connection failure | Restarts with existing cookie after 2s delay |

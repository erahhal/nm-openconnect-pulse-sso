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

Recovery layer (reconnection primarily goes through nmcli; service also has
NM-cooperative re-activation via D-Bus when openconnect dies externally):
  - vpn-auto-reconnect.sh     (systemd oneshot: nmcli connection up, 5 retries)
  - vpn-reconnect.sh          (post-resume: kill stale openconnect, trigger above)
  - 90-vpn-reconnect           (NM dispatcher: kill-first, cooldown, best-effort route)
  - vpnc hooks                 (auto-reconnect flag, default route fixup, Docker routes)

Flag file: /run/vpn-auto-reconnect
  - Created on successful VPN connection (vpnc post-connect hook)
  - Removed on user-initiated disconnect (plugin Disconnect())
  - Checked by recovery scripts to decide if reconnection is desired

Cooldown file: /run/vpn-reconnect-last-kill
  - Written by dispatcher after killing openconnect (timestamp:gateway:device)
  - 120-second cooldown prevents restart loops from transient WiFi glitches
  - Bypassed when the network actually changed (different gateway or device)
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
journalctl -u vpn-auto-reconnect --since "15 minutes ago"
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

1. Check if the resume handler ran and killed stale openconnect:
   ```bash
   journalctl -u vpn-reconnect --since "5 minutes ago"
   ```
2. Check if the auto-reconnect service was triggered and succeeded:
   ```bash
   journalctl -u vpn-auto-reconnect --since "5 minutes ago"
   ```
3. Check that the flag file exists (should be present if VPN was connected):
   ```bash
   ls -la /run/vpn-auto-reconnect
   ```
4. Verify rpfilter is loose (required for reconnection):
   ```bash
   sysctl net.ipv4.conf.all.rp_filter   # should be 2
   ```

### VPN disconnects on network change (wifi switch, ethernet unplug)

1. Check dispatcher ran:
   ```bash
   journalctl --since "5 minutes ago" | grep "90-vpn-reconnect"
   ```
2. Check which event triggered it (look for `connectivity-change`, `down`, or `up` action)
3. Check if auto-reconnect was triggered:
   ```bash
   journalctl -u vpn-auto-reconnect --since "5 minutes ago"
   ```
4. For ethernet→WiFi switches: dispatcher should re-trigger auto-reconnect when WiFi comes UP
   - Look for "VPN should be up, triggering reconnect" in dispatcher logs
5. If reconnection seems to be skipped, check the cooldown:
   ```bash
   cat /run/vpn-reconnect-last-kill   # shows timestamp:gateway:device
   ```
   - The dispatcher skips kills for 120 seconds on the same network to prevent flapping
   - Look for "Skipping kill: last restart was" in dispatcher logs

### Authentication failure loop

OpenConnect exit code 2 = auth failure. The plugin clears the cached cookie so the next `nmcli connection up` will trigger fresh browser authentication.

1. Check for auth failures:
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
2. Exit code 2 = auth failure — plugin clears cookie
3. Other exit codes: plugin retains cookie and stays alive for 5 minutes; the external `vpn-auto-reconnect.service` handles reconnection via `nmcli connection up`
4. After 5 consecutive non-auth failures, the plugin treats the cookie as stale/IP-bound and automatically triggers re-authentication (look for "cookie likely invalid, triggering re-authentication" in logs)
5. If crashes are persistent:
   - Check DTLS config: `cat /etc/nm-pulse-sso/config`
   - Try disabling DTLS in NixOS config (`enableDtls = false`) to rule out UDP/ESP issues
   - Check kernel logs: `dmesg | tail -50`

## DTLS vs Non-DTLS Behavior

Configuration in `/etc/nm-pulse-sso/config`:
- `ENABLE_DTLS=true`: openconnect uses UDP/ESP tunnel (better performance)
- `ENABLE_DTLS=false`: openconnect uses `--no-dtls` (TCP/SSL only)

DTLS is the default and generally more stable. Reconnection in both modes is handled externally by `vpn-auto-reconnect.service` via `nmcli connection up`.

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/nm-pulse-sso/config` | Runtime settings (DTLS, TCP keepalive) |
| `/etc/NetworkManager/VPN/nm-pulse-sso-service.name` | NM plugin descriptor |
| `/etc/NetworkManager/dispatcher.d/90-vpn-reconnect` | Interface change handler |
| `/etc/vpnc/post-connect.d/` | Scripts run after VPN connects (incl. auto-reconnect flag) |
| `/etc/vpnc/reconnect.d/` | Scripts run after VPN reconnects |
| `/run/vpn-auto-reconnect` | Flag file: VPN should be connected (created on connect, removed on user disconnect) |
| `/run/vpn-reconnect-last-kill` | Dispatcher cooldown: timestamp:gateway:device of last openconnect kill |
| `~/.cache/pulse-browser-auth/` | CEF browser profile, cookies, extensions |

## Key Source Files

When deeper investigation into the code is needed:

| File | What to look for |
|------|-----------------|
| `vpn-service/nm-pulse-sso-service.py` | D-Bus service logic, openconnect spawn, cookie retention, idle timeout, stale route cleanup, consecutive failure counting, NM-cooperative re-activation |
| `vpn-service/nm-pulse-sso-helper` | IP config reporting, DNS setup, route parsing |
| `auth-dialog/pulse-sso-auth-dialog` | Auth-dialog protocol, CEF launch, cookie extraction |
| `cef-auth/main.cc` | CEF browser behavior, UA switching, cookie monitoring, extensions |
| `scripts/vpn-auto-reconnect.sh` | External reconnect service (nmcli, retries, backoff, notifications) |
| `scripts/vpn-reconnect.sh` | Post-resume handler (kill openconnect, trigger auto-reconnect) |
| `scripts/nm-dispatcher.sh` | Network change detection (kill openconnect or re-trigger reconnect) |
| `scripts/vpnc/post-connect-auto-reconnect-flag.sh` | Creates /run/vpn-auto-reconnect flag on VPN connect |
| `scripts/diagnose.sh` | What the diagnostic script checks |
| `module.nix` | NixOS module options and what gets installed |

## OpenConnect Exit Codes

| Code | Meaning | Plugin behavior |
|------|---------|-----------------|
| 0 | Clean exit | Normal shutdown |
| 2 | Auth failure | Clears cached cookie; next reconnect will trigger browser auth |
| Other | Connection failure | Retains cookie, stays alive 5 min; external service handles reconnect via nmcli. After 5 consecutive failures, treats cookie as stale and triggers re-auth |

#!/bin/sh
#
# vpnc reconnect hook: Flush DNS caches and reset server features
#
# During VPN transitions, systemd-resolved may cache stale DNS entries
# and mark DNS servers as degraded. This hook clears both to ensure
# immediate DNS resolution after VPN reconnects.

@systemd@/bin/resolvectl flush-caches 2>/dev/null || true
@systemd@/bin/resolvectl reset-server-features 2>/dev/null || true
echo "Flushed DNS caches and reset server features"

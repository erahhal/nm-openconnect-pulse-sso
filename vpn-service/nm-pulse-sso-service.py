#!/usr/bin/env python3
"""
NetworkManager VPN Plugin for Pulse SSO Authentication

This D-Bus service implements the org.freedesktop.NetworkManager.VPN.Plugin
interface. It is a PASSIVE service that:

1. Receives Connect() calls from NetworkManager WITH credentials already provided
   (credentials come from the auth-dialog which runs as the user)
2. Runs openconnect with the provided cookie
3. Reports IP configuration back to NetworkManager

IMPORTANT: This service does NOT launch browsers or user processes.
Browser authentication is handled by the auth-dialog (pulse-sso-auth-dialog)
which NetworkManager runs as the user BEFORE calling Connect().
"""

import logging
import os
import pwd
import signal
import socket
import subprocess
import sys

from argparse import ArgumentParser, Namespace
from enum import IntEnum
from functools import wraps
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Any, Optional
from urllib.parse import urlparse

import dbus
import dbus.mainloop.glib
import dbus.service
from dbus.service import method, signal as dbus_signal
from gi.repository import GLib

NM_DBUS_SERVICE = "org.freedesktop.NetworkManager.pulse-sso"
NM_DBUS_INTERFACE = "org.freedesktop.NetworkManager.VPN.Plugin"
NM_DBUS_PATH = "/org/freedesktop/NetworkManager/VPN/Plugin"

# Config file written by NixOS
CONFIG_PATH = Path("/etc/nm-pulse-sso/config")


def is_dtls_enabled() -> bool:
    """
    Check if DTLS/ESP is enabled by reading the NixOS config file.

    Returns True if DTLS is enabled (better performance, UDP/ESP tunnel).
    Returns False if DTLS is disabled (uses --no-dtls, TCP/SSL only).
    """
    try:
        if CONFIG_PATH.exists():
            content = CONFIG_PATH.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("ENABLE_DTLS="):
                    value = line.split("=", 1)[1].strip().lower()
                    return value == "true"
    except Exception as e:
        logger.warning("Failed to read config file %s: %s", CONFIG_PATH, e)
    # Default to DTLS disabled (current behavior)
    return False


def get_tcp_keepalive_config() -> tuple:
    """
    Read TCP keepalive settings from the NixOS config file.

    Returns (enabled: bool, interval: int or None).
    """
    enabled = False
    interval = None
    try:
        if CONFIG_PATH.exists():
            content = CONFIG_PATH.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("ENABLE_TCP_KEEPALIVE="):
                    value = line.split("=", 1)[1].strip().lower()
                    enabled = value == "true"
                elif line.startswith("TCP_KEEPALIVE_INTERVAL="):
                    val = line.split("=", 1)[1].strip()
                    if val:
                        interval = int(val)
    except Exception as e:
        logger.warning("Failed to read TCP keepalive config: %s", e)
    return enabled, interval


# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nm-pulse-sso")


def trace(fn):
    """Decorator to log method calls for debugging."""

    @wraps(fn)
    def traced(self, *args, **kwargs):
        logger.debug("%s(%s, %s)", fn.__name__, args, kwargs)
        return fn(self, *args, **kwargs)

    return traced


def convert_dbus_types(obj):
    """Convert D-Bus types to native Python types."""
    if isinstance(obj, dbus.Dictionary):
        return {str(k): convert_dbus_types(v) for k, v in obj.items()}
    elif isinstance(obj, dbus.Array):
        return [convert_dbus_types(el) for el in obj]
    elif isinstance(obj, dbus.String):
        return str(obj)
    elif isinstance(obj, (dbus.UInt16, dbus.UInt32, dbus.UInt64)):
        return int(obj)
    elif isinstance(obj, (dbus.Int16, dbus.Int32, dbus.Int64)):
        return int(obj)
    elif isinstance(obj, dbus.Boolean):
        return bool(obj)
    elif isinstance(obj, dbus.Byte):
        return int(obj)
    else:
        return obj


class ServiceState(IntEnum):
    """VPN service states as defined by NetworkManager."""

    Unknown = 0
    Init = 1
    Shutdown = 2
    Starting = 3
    Started = 4
    Stopping = 5
    Stopped = 6


class InteractiveNotSupportedError(dbus.DBusException):
    """Exception for unsupported interactive authentication."""

    _dbus_error_name = (
        "org.freedesktop.NetworkManager.VPN.Error.InteractiveNotSupported"
    )


class LaunchFailedError(dbus.DBusException):
    """Exception when VPN launch fails."""

    _dbus_error_name = "org.freedesktop.NetworkManager.VPN.Error.LaunchFailed"


class PulseSSOPlugin(dbus.service.Object):
    """
    NetworkManager VPN Plugin for Pulse SSO.

    Implements the org.freedesktop.NetworkManager.VPN.Plugin D-Bus interface.

    This is a PASSIVE service - it receives credentials from NetworkManager
    (which got them from the auth-dialog) and runs openconnect.
    """

    def __init__(self, loop, conn, object_path, bus_name, helper_script):
        super().__init__(conn=conn, object_path=object_path, bus_name=bus_name)
        self.loop = loop
        self.helper_script = helper_script

        self.proc: Optional[Popen] = None
        self.config = {}
        self.ip4config = {}

        # Connection parameters
        self.gateway: Optional[str] = None
        self.cookie: Optional[str] = None
        self.servercert: Optional[str] = None

        # Pending connection for interactive flow
        self.pending_connection: Optional[dict] = None

        # Track whether disconnect was requested (vs unexpected exit)
        self._disconnect_requested: bool = False

        # Child watch source ID for cleanup
        self._child_watch_id: Optional[int] = None

        # Pending NM re-activation timer (to cancel if user disconnects during delay)
        self._reactivation_timeout_id: Optional[int] = None

        # Count consecutive auth failures to prevent infinite loops
        self._auth_failure_count: int = 0

        # Flag to prevent Disconnect() from quitting when we're about to trigger
        # browser re-auth (prevents race with NM calling Disconnect after StateChanged)
        self._reconnection_pending: bool = False

        # Count consecutive non-auth restart failures to detect stale cookies
        # (openconnect returns code 1 instead of 2 when cookie is IP-bound/stale)
        self._consecutive_restart_failures: int = 0

        # Retry tracking for auth dialog attempts (nm-applet may not be ready after suspend)
        self._reconnection_retry_count: int = 0
        self._max_reconnection_retries: int = 10
        self._reconnection_retry_interval: int = 3000  # milliseconds

        # Track any pending direct-auth timer (GLib source ID) to prevent duplicates
        self._direct_auth_timeout_id: Optional[int] = None

        # Track the running auth-dialog subprocess for cancellation
        self._auth_dialog_proc: Optional[Popen] = None
        self._auth_dialog_child_watch_id: Optional[int] = None
        self._auth_dialog_timeout_id: Optional[int] = None

        # State for async auth-dialog launch fallback chain
        self._auth_launch_commands: list = []
        self._auth_launch_index: int = 0
        self._auth_input_data: bytes = b""

        # Idle quit timeout — quit service if no Connect() received within 5 minutes
        # after a reactive disconnect (keeps cookie alive for external reconnect)
        self._idle_quit_timeout_id: Optional[int] = None

    def _do_connect(self, connection: dict):
        """
        Actually establish the VPN connection with provided credentials.

        This is called from Connect(), ConnectInteractive(), or NewSecrets()
        once we have all required credentials.
        """
        try:
            # Extract VPN data (from connection config)
            vpn_data = connection.get("vpn", {}).get("data", {})
            gateway = vpn_data.get("gateway", "")

            # Extract secrets
            vpn_secrets = connection.get("vpn", {}).get("secrets", {})
            cookie = vpn_secrets.get("cookie", "")
            servercert = vpn_secrets.get("gwcert", "")

            if not gateway:
                raise LaunchFailedError("No gateway specified in VPN configuration")

            if not cookie:
                raise LaunchFailedError(
                    "No cookie provided - auth-dialog may have failed"
                )

            # Ensure gateway has https:// prefix (openconnect needs full URL)
            if not gateway.startswith("http://") and not gateway.startswith("https://"):
                gateway = f"https://{gateway}"

            logger.info("Starting openconnect for gateway: %s", gateway)
            self.StateChanged(ServiceState.Starting)

            self.gateway = gateway
            self.cookie = cookie
            self.servercert = servercert

            # Reset disconnect flag - we're starting a new connection
            self._disconnect_requested = False

            # Clear reconnection state - we're now actually connecting
            self._reconnection_pending = False
            self._reconnection_retry_count = 0
            self._consecutive_restart_failures = 0

            self._start_openconnect()

        except LaunchFailedError:
            raise
        except Exception as e:
            logger.exception("_do_connect failed")
            self.StateChanged(ServiceState.Stopped)
            raise LaunchFailedError(f"Connection failed: {e}")

    def _cleanup_stale_vpn_routes(self):
        """Remove stale static routes to the VPN server from previous connections.

        When openconnect dies without a graceful disconnect (crash, SIGKILL,
        network loss), vpnc-script's del_vpngateway_route() never runs,
        leaving static routes that point to an old gateway. These stale
        routes prevent reaching the VPN server on the new network.
        """
        if not self.gateway:
            return

        try:
            hostname = urlparse(self.gateway).hostname or self.gateway
        except Exception:
            hostname = self.gateway

        try:
            # Use a short timeout — after resume, DNS may be unavailable.
            # Route cleanup is best-effort; don't block for 20s on stale DNS.
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3)
            try:
                vpn_ip = socket.gethostbyname(hostname)
            finally:
                socket.setdefaulttimeout(old_timeout)
        except Exception as e:
            logger.debug("Cannot resolve %s for route cleanup: %s", hostname, e)
            return

        try:
            result = subprocess.run(
                ["ip", "route", "show", vpn_ip],
                capture_output=True, text=True, timeout=5,
            )
            if not result.stdout.strip():
                return

            def_result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            default_gw = None
            for line in def_result.stdout.strip().split("\n"):
                if "via" in line and "tun" not in line:
                    parts = line.split()
                    via_idx = parts.index("via")
                    default_gw = parts[via_idx + 1]
                    break

            if not default_gw:
                return

            for line in result.stdout.strip().split("\n"):
                if "proto static" in line and "via" in line:
                    parts = line.split()
                    via_idx = parts.index("via")
                    route_gw = parts[via_idx + 1]
                    if route_gw != default_gw:
                        logger.info(
                            "Removing stale VPN route: %s via %s "
                            "(current default gw: %s)",
                            vpn_ip, route_gw, default_gw,
                        )
                        subprocess.run(
                            ["ip", "route", "del", vpn_ip],
                            capture_output=True, timeout=5,
                        )
                        subprocess.run(
                            ["ip", "route", "del", route_gw],
                            capture_output=True, timeout=5,
                        )
                        break
        except Exception as e:
            logger.debug("Route cleanup failed (non-fatal): %s", e)

    def _start_openconnect(self):
        """
        Start openconnect with the current cookie.

        This is called both for initial connection and for restarts after
        unexpected exits (non-auth failures).
        """
        # Flush DNS caches — after suspend/resume, caches may contain stale
        # entries that cause immediate getaddrinfo failures for the VPN host.
        try:
            subprocess.run(
                ["resolvectl", "flush-caches"],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["resolvectl", "reset-server-features"],
                capture_output=True, timeout=5,
            )
            logger.debug("Flushed DNS caches before openconnect start")
        except Exception as e:
            logger.debug("DNS cache flush failed (non-fatal): %s", e)

        self._cleanup_stale_vpn_routes()
        # Build openconnect command based on working openconnect-pulse-launcher
        # Key differences from CLI version:
        # - No -b (background): we need to track the process for disconnect
        # - Using --script with helper that CALLS vpnc-script AND reports to D-Bus
        #
        # DTLS/ESP handling:
        # - With DTLS disabled: --no-dtls forces SSL-only mode (TCP only).
        # - With DTLS enabled: uses ESP/UDP for better performance.
        # Reconnection is handled externally by vpn-auto-reconnect service via nmcli.
        dtls_enabled = is_dtls_enabled()
        logger.info("DTLS/ESP mode: %s", "enabled" if dtls_enabled else "disabled")

        cmd = [
            "openconnect",
        ]

        # Only add --no-dtls if DTLS is disabled
        if not dtls_enabled:
            cmd.append("--no-dtls")

        # TCP keepalive handling
        keepalive_enabled, keepalive_interval = get_tcp_keepalive_config()
        if keepalive_enabled:
            if keepalive_interval is not None:
                cmd.append(f"--keepalive={keepalive_interval}")
            else:
                cmd.append("--keepalive")
            logger.info(
                "TCP keepalive: enabled (interval=%s)",
                keepalive_interval if keepalive_interval else "system default",
            )

        cmd.extend(
            [
                "-C",
                self.cookie,
                "--protocol=pulse",
                f"--script={self.helper_script}",
                self.gateway,
            ]
        )

        # Log command (but mask cookie value)
        safe_cmd = [
            c if i == 0 or cmd[i - 1] != "-C" else "***" for i, c in enumerate(cmd)
        ]
        logger.info("Executing: %s", " ".join(safe_cmd))

        # Set environment for helper script to find our D-Bus service
        env = os.environ.copy()
        env["NM_DBUS_SERVICE_PULSE_SSO"] = NM_DBUS_SERVICE

        # Redirect stdin to avoid blocking, but keep stderr for logging
        # stdout goes to devnull, stderr goes to our stderr (which goes to journal)
        import subprocess

        self.proc = Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,  # Inherit stderr so errors go to journal
        )

        logger.info("openconnect started with PID %d", self.proc.pid)

        # Monitor the process for unexpected exits
        # GLib.child_watch_add will call our callback when the process exits
        self._child_watch_id = GLib.child_watch_add(
            self.proc.pid, self._on_openconnect_exit
        )

    def _on_openconnect_exit(self, pid: int, status: int):
        """
        Called by GLib when openconnect process exits.

        Simplified: just emit Stopped and let external vpn-auto-reconnect
        service handle re-establishing the VPN via nmcli. No restart logic.
        """
        # Only handle exit for the process we're currently tracking
        if self.proc is None or self.proc.pid != pid:
            logger.debug(
                "Ignoring exit for old process PID %d (current: %s)",
                pid,
                self.proc.pid if self.proc else "None",
            )
            return

        # Convert wait status to exit code
        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            exit_code = -os.WTERMSIG(status)
        else:
            exit_code = status

        logger.info("openconnect (PID %d) exited with code %d", pid, exit_code)

        # Clear process reference
        self.proc = None
        self._child_watch_id = None

        # If disconnect was requested, don't do anything — Disconnect() handles cleanup
        if self._disconnect_requested:
            logger.info("Disconnect was requested, not restarting")
            return

        # Exit code 2 means auth failure — cookie is invalid
        if exit_code == 2:
            logger.warning("Auth failure (exit code 2) — cookie invalid, clearing")
            self.cookie = None
            if self.gateway and not self._disconnect_requested:
                # Session expired (e.g. 24h server timeout). Set reconnection
                # pending so NM's reactive Disconnect() schedules re-activation.
                # NM will call ConnectInteractive() with no cookie, triggering
                # the direct-auth (browser) path for fresh authentication.
                logger.info("Setting reconnection pending for re-authentication")
                self._reconnection_pending = True
            self.StateChanged(ServiceState.Stopped)
            return

        # Non-auth failure with valid cookie — NM reactive Disconnect() will
        # schedule fast re-activation via ActivateConnection D-Bus API
        if self.cookie and self.gateway:
            self._consecutive_restart_failures += 1
            logger.warning(
                "openconnect exited unexpectedly (attempt %d), "
                "waiting for NM re-activation...",
                self._consecutive_restart_failures,
            )

            if self._consecutive_restart_failures >= 5:
                # Too many consecutive failures — cookie likely stale/IP-bound.
                # Treat as auth failure: clear cookie and trigger re-authentication.
                logger.error(
                    "openconnect failed %d consecutive times with exit code %d — "
                    "cookie likely invalid, triggering re-authentication",
                    self._consecutive_restart_failures, exit_code,
                )
                self._consecutive_restart_failures = 0
                self.cookie = None
                if self.gateway and not self._disconnect_requested:
                    self._reconnection_pending = True
                    self.StateChanged(ServiceState.Starting)
                    self._schedule_direct_auth(1000)
                else:
                    self.StateChanged(ServiceState.Stopped)
                return

        # Emit Stopped — NM reactive Disconnect() will schedule re-activation
        self.StateChanged(ServiceState.Stopped)

    def _on_idle_quit_timeout(self) -> bool:
        """Quit service after 5 minutes of inactivity (no Connect() received).

        After a reactive disconnect, we stay alive to retain the cookie.
        If no Connect() comes within 5 minutes, quit to release resources.

        Returns False to prevent GLib timeout from repeating.
        """
        self._idle_quit_timeout_id = None
        if self.proc is not None:
            return False  # VPN is running, don't quit
        logger.info("No reconnection after 5 minutes — quitting service")
        self.cookie = None
        self.gateway = None
        self.loop.quit()
        return False

    def _reactivate_vpn_via_nm(self) -> bool:
        """Re-activate the VPN connection through NetworkManager's D-Bus API.

        Called after cooperating with NM's Disconnect() teardown. Goes through
        NM's proper ActivateConnection flow so routes are managed correctly.

        Returns False to prevent GLib timeout from repeating.
        """
        self._reactivation_timeout_id = None

        if self._disconnect_requested:
            logger.info("Disconnect requested during delay, aborting VPN re-activation")
            return False

        try:
            bus = dbus.SystemBus()

            # Find VPN connection by service type (our plugin)
            settings_obj = bus.get_object(
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager/Settings",
            )
            settings_iface = dbus.Interface(
                settings_obj, "org.freedesktop.NetworkManager.Settings"
            )

            vpn_conn_path = None
            for conn_path in settings_iface.ListConnections():
                conn = bus.get_object("org.freedesktop.NetworkManager", conn_path)
                conn_settings = dbus.Interface(
                    conn, "org.freedesktop.NetworkManager.Settings.Connection"
                )
                s = conn_settings.GetSettings()
                conn_type = s.get("connection", {}).get("type", "")
                vpn_service = s.get("vpn", {}).get("service-type", "")
                if conn_type == "vpn" and vpn_service == NM_DBUS_SERVICE:
                    vpn_conn_path = conn_path
                    break

            if not vpn_conn_path:
                logger.error("No VPN connection found for service %s", NM_DBUS_SERVICE)
                return False

            logger.info("Re-activating VPN connection: %s", vpn_conn_path)
            nm_obj = bus.get_object(
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager",
            )
            nm_iface = dbus.Interface(nm_obj, "org.freedesktop.NetworkManager")
            nm_iface.ActivateConnection(
                vpn_conn_path,
                dbus.ObjectPath("/"),   # No specific device (VPN)
                dbus.ObjectPath("/"),   # No specific object
            )
            logger.info("VPN re-activation requested successfully")
        except Exception as e:
            logger.error("Failed to re-activate VPN via NetworkManager: %s", e)

        return False  # Don't repeat

    def _schedule_auth_retry(self, reason: str):
        """
        Schedule an auth retry or emit failure if max retries exceeded.

        This consolidates retry logic to ensure proper state emission when
        all retries are exhausted.
        """
        if self._reconnection_retry_count >= self._max_reconnection_retries:
            logger.error(
                "Max auth retries (%d) exceeded: %s",
                self._max_reconnection_retries,
                reason,
            )
            self._reconnection_pending = False
            self.StateChanged(ServiceState.Stopped)
            self.Failure(
                f"VPN reconnection failed after {self._max_reconnection_retries} attempts: {reason}"
            )
        else:
            logger.info(
                "Scheduling auth retry in %dms (attempt %d/%d): %s",
                self._reconnection_retry_interval,
                self._reconnection_retry_count,
                self._max_reconnection_retries,
                reason,
            )
            self._schedule_direct_auth(self._reconnection_retry_interval)

    def _schedule_direct_auth(self, delay_ms: int):
        """
        Schedule the direct-auth helper with the provided delay, replacing any existing timer.
        """
        if delay_ms < 0:
            delay_ms = 0

        if self._direct_auth_timeout_id is not None:
            GLib.source_remove(self._direct_auth_timeout_id)

        self._direct_auth_timeout_id = GLib.timeout_add(
            delay_ms, self._launch_direct_auth
        )

    def _cancel_direct_auth_timer(self):
        """Cancel any pending direct-auth timeout."""
        if self._direct_auth_timeout_id is not None:
            GLib.source_remove(self._direct_auth_timeout_id)
            self._direct_auth_timeout_id = None

    def _kill_auth_dialog(self):
        """Kill any running auth-dialog subprocess and clean up.

        Since auth-dialog is launched via systemd-run --pipe --wait, killing the
        systemd-run process causes systemd to stop the transient unit and its
        cgroup, which terminates the auth-dialog and CEF browser.
        """
        proc = self._auth_dialog_proc
        if proc is not None:
            logger.info("Killing auth-dialog subprocess PID %d", proc.pid)
            try:
                proc.kill()
            except OSError:
                pass  # Process may have already exited
            self._auth_dialog_proc = None

        if self._auth_dialog_timeout_id is not None:
            GLib.source_remove(self._auth_dialog_timeout_id)
            self._auth_dialog_timeout_id = None

    def _launch_direct_auth(self) -> bool:
        """
        Launch auth-dialog directly, bypassing NM's agent system.

        After suspend/resume, nm-applet's secret agent often doesn't respond.
        This method bypasses NM entirely by running the auth-dialog directly
        in the user's graphical session using systemd-run.

        Non-blocking: starts the subprocess and returns immediately.
        _on_auth_dialog_exit() handles the result when the process exits.

        Returns False to prevent GLib timeout from repeating.
        """
        # GLib invoked this callback; clear the stored source ID
        self._direct_auth_timeout_id = None

        # Clean up stale routes so auth browser can reach VPN server
        self._cleanup_stale_vpn_routes()

        # Wait for DNS to be ready before launching browser.
        # After suspend/resume or network change, DNS may not be functional yet.
        # Opening the browser before DNS is ready shows a blank page.
        if self.gateway:
            try:
                hostname = urlparse(self.gateway).hostname or self.gateway
            except Exception:
                hostname = self.gateway
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(5)
                try:
                    socket.getaddrinfo(hostname, 443)
                finally:
                    socket.setdefaulttimeout(old_timeout)
                logger.debug("DNS ready: %s resolves", hostname)
            except (socket.gaierror, socket.timeout, OSError) as e:
                logger.info(
                    "DNS not ready for %s (%s), retrying in 2s (attempt %d/%d)",
                    hostname, e,
                    self._reconnection_retry_count + 1,
                    self._max_reconnection_retries,
                )
                if self._reconnection_retry_count < self._max_reconnection_retries:
                    self._schedule_direct_auth(2000)
                else:
                    self._schedule_auth_retry(f"DNS not ready for {hostname}")
                return False

        if not self._reconnection_pending:
            logger.debug("Reconnection no longer pending, skipping direct auth")
            return False

        self._reconnection_retry_count += 1

        if self._reconnection_retry_count > self._max_reconnection_retries:
            logger.error(
                "Max auth retries (%d) exceeded, giving up",
                self._max_reconnection_retries,
            )
            self._reconnection_pending = False
            self.StateChanged(ServiceState.Stopped)
            self.Failure("VPN reconnection failed - please reconnect manually")
            return False

        logger.info(
            "Direct auth attempt %d/%d",
            self._reconnection_retry_count,
            self._max_reconnection_retries,
        )

        try:
            # Find graphical session via loginctl
            result = subprocess.run(
                ["loginctl", "list-sessions", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            user = None
            session_type = None
            session_leader = None
            display = ":0"

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 1:
                    session_id = parts[0]
                    # Get session properties
                    # Note: --property=A,B,C syntax doesn't work, must use separate flags
                    show = subprocess.run(
                        [
                            "loginctl",
                            "show-session",
                            session_id,
                            "--property=Name",
                            "--property=Type",
                            "--property=Display",
                            "--property=Leader",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    props = {}
                    for prop_line in show.stdout.strip().split("\n"):
                        if "=" in prop_line:
                            k, v = prop_line.split("=", 1)
                            props[k] = v

                    # Look for graphical session (x11 or wayland)
                    if props.get("Type") in ("x11", "wayland"):
                        user = props.get("Name")
                        session_type = props.get("Type")
                        session_leader = props.get("Leader")
                        display = props.get("Display") or ":0"
                        logger.debug(
                            "Found graphical session: user=%s, type=%s, display=%s, leader=%s",
                            user,
                            session_type,
                            display,
                            session_leader,
                        )
                        break

            if not user:
                logger.error("No graphical session found, will retry")
                self._schedule_direct_auth(self._reconnection_retry_interval)
                return False

            # Get UID for environment wiring
            uid = pwd.getpwnam(user).pw_uid
            user_home = pwd.getpwnam(user).pw_dir

            # Default environment values for graphical auth
            runtime_dir = f"/run/user/{uid}"
            dbus_addr = f"unix:path={runtime_dir}/bus"
            wayland_display = None
            xauthority = None

            # Try to inherit graphical-session env from the session leader
            if session_leader and session_leader.isdigit():
                environ_path = f"/proc/{session_leader}/environ"
                try:
                    with open(environ_path, "rb") as f:
                        raw_env = f.read()
                    env_map = {}
                    for entry in raw_env.split(b"\0"):
                        if not entry or b"=" not in entry:
                            continue
                        k, v = entry.split(b"=", 1)
                        env_map[k.decode(errors="ignore")] = v.decode(errors="ignore")

                    display = env_map.get("DISPLAY", display)
                    runtime_dir = env_map.get("XDG_RUNTIME_DIR", runtime_dir)
                    dbus_addr = env_map.get(
                        "DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir}/bus"
                    )
                    wayland_display = env_map.get("WAYLAND_DISPLAY")
                    xauthority = env_map.get("XAUTHORITY")
                except Exception as e:
                    logger.debug(
                        "Could not read session leader environment (%s): %s",
                        environ_path,
                        e,
                    )

            # If we are in a Wayland session and DISPLAY is absent/invalid,
            # prefer native Wayland socket discovery over forcing :0.
            if session_type == "wayland":
                if not wayland_display:
                    try:
                        for name in os.listdir(runtime_dir):
                            if name.startswith("wayland-"):
                                wayland_display = name
                                break
                    except Exception:
                        pass

                if display == ":0":
                    display = ""

            # Derive auth-dialog path from helper_script (same directory)
            auth_dialog = self.helper_script.replace(
                "nm-pulse-sso-helper", "pulse-sso-auth-dialog"
            )

            logger.info(
                "Launching auth-dialog as %s (uid=%d, display=%s)", user, uid, display
            )

            env_args = [
                f"--setenv=HOME={user_home}",
                f"--setenv=XDG_RUNTIME_DIR={runtime_dir}",
                f"--setenv=DBUS_SESSION_BUS_ADDRESS={dbus_addr}",
            ]
            if display:
                env_args.append(f"--setenv=DISPLAY={display}")
            if session_type:
                env_args.append(f"--setenv=XDG_SESSION_TYPE={session_type}")
            if wayland_display:
                env_args.append(f"--setenv=WAYLAND_DISPLAY={wayland_display}")
                env_args.append("--setenv=OZONE_PLATFORM=wayland")
            if xauthority:
                env_args.append(f"--setenv=XAUTHORITY={xauthority}")

            # Store launch commands for the async fallback chain
            self._auth_launch_commands = [
                # Primary path: use user manager via machine bridge.
                [
                    "systemd-run",
                    "--user",
                    f"--machine={user}@",
                    "--pipe",
                    "--wait",
                    "--quiet",
                    *env_args,
                    "--",
                    auth_dialog,
                ],
                # Some setups require the explicit .host suffix.
                [
                    "systemd-run",
                    "--user",
                    f"--machine={user}@.host",
                    "--pipe",
                    "--wait",
                    "--quiet",
                    *env_args,
                    "--",
                    auth_dialog,
                ],
                # Fallback: launch through the system manager as the target UID.
                [
                    "systemd-run",
                    "--pipe",
                    "--wait",
                    "--quiet",
                    f"--uid={uid}",
                    *env_args,
                    "--",
                    auth_dialog,
                ],
            ]
            self._auth_launch_index = 0

            # Auth-dialog protocol: send gateway via stdin
            self._auth_input_data = f"DATA_KEY=gateway\nDATA_VAL={self.gateway}\nDONE\n".encode()

            # Start the first launch attempt (non-blocking)
            self._try_next_auth_launch()

        except Exception as e:
            logger.exception("Direct auth failed: %s", e)
            self._schedule_auth_retry(f"Direct auth failed: {e}")

        return False

    def _try_next_auth_launch(self):
        """Try the next auth-dialog launch strategy asynchronously."""
        if not self._reconnection_pending:
            logger.debug("Reconnection cancelled, aborting auth launch")
            return

        if self._auth_launch_index >= len(self._auth_launch_commands):
            logger.error("Auth-dialog failed after all launch strategies")
            self._schedule_auth_retry("All launch strategies failed")
            return

        launch_cmd = self._auth_launch_commands[self._auth_launch_index]
        logger.debug(
            "Auth-dialog launch attempt %d/%d: %s",
            self._auth_launch_index + 1,
            len(self._auth_launch_commands),
            " ".join(launch_cmd[:4]),
        )

        try:
            proc = subprocess.Popen(
                launch_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Write input data and close stdin immediately.
            # Non-blocking for small data (< PIPE_BUF = 4096 bytes on Linux).
            proc.stdin.write(self._auth_input_data)
            proc.stdin.close()

            # Store the proc so Disconnect() can kill it
            self._auth_dialog_proc = proc

            # Monitor the process asynchronously via GLib
            self._auth_dialog_child_watch_id = GLib.child_watch_add(
                proc.pid, self._on_auth_dialog_exit
            )

            # Set a timeout for the auth-dialog (300 seconds)
            self._auth_dialog_timeout_id = GLib.timeout_add(
                300_000, self._on_auth_dialog_timeout
            )

        except Exception as e:
            logger.error(
                "Failed to launch auth-dialog (attempt %d): %s",
                self._auth_launch_index + 1,
                e,
            )
            self._auth_launch_index += 1
            # Try next strategy via idle callback to avoid deep recursion
            GLib.idle_add(self._try_next_auth_launch)

    def _on_auth_dialog_timeout(self) -> bool:
        """Called when auth-dialog has been running too long. Kill it."""
        self._auth_dialog_timeout_id = None
        logger.error("Auth-dialog timed out (300s)")
        self._kill_auth_dialog()
        return False

    def _on_auth_dialog_exit(self, pid: int, status: int):
        """
        Called by GLib when auth-dialog subprocess exits.

        Reads output from the process pipes, parses the cookie,
        and either starts openconnect or schedules a retry.
        """
        # Cancel the timeout
        if self._auth_dialog_timeout_id is not None:
            GLib.source_remove(self._auth_dialog_timeout_id)
            self._auth_dialog_timeout_id = None

        self._auth_dialog_child_watch_id = None
        proc = self._auth_dialog_proc
        self._auth_dialog_proc = None

        if proc is None or proc.pid != pid:
            logger.debug("Ignoring exit for unknown auth-dialog PID %d", pid)
            return

        # Check if disconnect was requested while we were waiting
        if not self._reconnection_pending:
            logger.info(
                "Reconnection no longer pending after auth-dialog exit, not retrying"
            )
            # Clean up pipes
            try:
                proc.stdout.close()
                proc.stderr.close()
            except Exception:
                pass
            return

        # Get exit code
        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            exit_code = -os.WTERMSIG(status)
        else:
            exit_code = status

        # Read stdout/stderr now that process has exited.
        # Safe because the process is dead and data is in kernel pipe buffers.
        try:
            stdout = proc.stdout.read()
            stderr = proc.stderr.read()
            proc.stdout.close()
            proc.stderr.close()
        except Exception as e:
            logger.error("Failed to read auth-dialog output: %s", e)
            self._schedule_auth_retry("Failed to read auth-dialog output")
            return

        if exit_code != 0:
            logger.error(
                "Auth-dialog (attempt %d) failed (exit %d): %s",
                self._auth_launch_index + 1,
                exit_code,
                stderr.decode(errors="replace"),
            )
            # Try next launch strategy
            self._auth_launch_index += 1
            if self._auth_launch_index < len(self._auth_launch_commands):
                self._try_next_auth_launch()
            else:
                self._schedule_auth_retry("All launch strategies failed")
            return

        # Parse cookie from stdout (protocol: key\nvalue\nkey\nvalue...)
        lines = stdout.decode().strip().split("\n")
        cookie = None
        gwcert = None
        i = 0
        while i < len(lines):
            if lines[i] == "cookie" and i + 1 < len(lines):
                cookie = lines[i + 1]
                i += 2
            elif lines[i] == "gwcert" and i + 1 < len(lines):
                gwcert = lines[i + 1]
                i += 2
            else:
                i += 1

        if not cookie:
            logger.error("No cookie in auth-dialog output: %s", stdout.decode())
            self._schedule_auth_retry("No cookie in auth-dialog output")
            return

        # Check disconnect again (could have been requested during output parsing)
        if not self._reconnection_pending:
            logger.info("Disconnect requested, discarding auth result")
            return

        # Success! Update credentials and start openconnect
        logger.info("Got fresh cookie from auth-dialog, starting openconnect")
        self.cookie = cookie
        self.servercert = gwcert

        self.StateChanged(ServiceState.Starting)
        try:
            self._start_openconnect()
            # Only clear reconnection state AFTER openconnect starts successfully
            self._reconnection_pending = False
            self._reconnection_retry_count = 0
            self._auth_failure_count = 0
            self._cancel_direct_auth_timer()
        except Exception as e:
            logger.exception("Failed to start openconnect after auth: %s", e)
            self._schedule_auth_retry("Failed to start openconnect")

    @method(
        dbus_interface=NM_DBUS_INTERFACE, in_signature="a{sa{sv}}", out_signature=""
    )
    def Connect(self, connection: dict[str, dict[str, Any]]):
        """
        Non-interactive VPN connection.

        If no cookie is present, launch direct browser auth.
        This is the main entry point now that NeedSecrets returns '' to
        bypass NM's secrets agent system (which doesn't support our VPN type).
        """
        connection = convert_dbus_types(connection)
        logger.info("Connect called with connection: %s", connection)

        # Cancel idle quit timer — we got a Connect call
        if self._idle_quit_timeout_id is not None:
            GLib.source_remove(self._idle_quit_timeout_id)
            self._idle_quit_timeout_id = None
        self._disconnect_requested = False

        vpn_secrets = connection.get("vpn", {}).get("secrets", {})
        if not vpn_secrets.get("cookie"):
            # No cookie from NM — check if we have one internally from previous connection
            if self.cookie:
                logger.info("No cookie from NM, using internally-stored cookie")
                # Inject into connection dict for _do_connect
                connection.setdefault("vpn", {}).setdefault("secrets", {})["cookie"] = self.cookie
                if self.servercert:
                    connection["vpn"]["secrets"]["gwcert"] = self.servercert
                self._do_connect(connection)
                return

            # No cookie at all - launch direct auth (browser popup)
            logger.info("No cookie in Connect, launching direct auth")

            # Extract gateway from connection
            vpn_data = connection.get("vpn", {}).get("data", {})
            gateway = vpn_data.get("gateway", "")
            if not gateway:
                raise LaunchFailedError("No gateway specified in VPN configuration")

            # Ensure gateway has https:// prefix
            if not gateway.startswith("http://") and not gateway.startswith("https://"):
                gateway = f"https://{gateway}"

            # Store connection and gateway for use after auth completes
            self.pending_connection = connection
            self.gateway = gateway
            self._reconnection_pending = True
            self._reconnection_retry_count = 0

            self.StateChanged(ServiceState.Starting)

            # Launch direct auth immediately (will open browser)
            self._schedule_direct_auth(0)
            return  # Return now, _launch_direct_auth will call _start_openconnect when done

        self._do_connect(connection)

    @method(
        dbus_interface=NM_DBUS_INTERFACE,
        in_signature="a{sa{sv}}a{sv}",
        out_signature="",
    )
    def ConnectInteractive(self, connection: dict, details: dict):
        """
        Interactive connection - trigger direct auth if no cookie.

        We launch the browser directly instead of emitting SecretsRequired,
        which avoids plasma-nm showing a generic secrets dialog.
        """
        connection = convert_dbus_types(connection)
        logger.info("ConnectInteractive called with connection: %s", connection)

        # Cancel idle quit timer — we got a Connect call
        if self._idle_quit_timeout_id is not None:
            GLib.source_remove(self._idle_quit_timeout_id)
            self._idle_quit_timeout_id = None
        self._disconnect_requested = False

        # Store connection for later use
        self.pending_connection = connection

        # Extract secrets
        vpn_secrets = connection.get("vpn", {}).get("secrets", {})
        cookie = vpn_secrets.get("cookie", "")

        # Extract gateway for direct auth
        vpn_data = connection.get("vpn", {}).get("data", {})
        gateway = vpn_data.get("gateway", "")

        if not cookie:
            # No cookie from NM — check if we have one internally from previous connection
            if self.cookie:
                logger.info("ConnectInteractive: No cookie from NM, using internally-stored cookie")
                connection.setdefault("vpn", {}).setdefault("secrets", {})["cookie"] = self.cookie
                if self.servercert:
                    connection["vpn"]["secrets"]["gwcert"] = self.servercert
                self._do_connect(connection)
                return

            # No cookie at all - trigger direct auth immediately
            # Don't emit SecretsRequired to avoid plasma-nm showing a dialog
            logger.info("No cookie, triggering direct auth immediately")

            if not gateway:
                raise LaunchFailedError("No gateway specified in VPN configuration")

            # Ensure gateway has https:// prefix
            if not gateway.startswith("http://") and not gateway.startswith("https://"):
                gateway = f"https://{gateway}"

            self.gateway = gateway
            self._reconnection_pending = True
            self._reconnection_retry_count = 0
            self.StateChanged(ServiceState.Starting)
            self._schedule_direct_auth(0)
            return

        # Have cookie, proceed with connection
        self._do_connect(connection)

    @method(
        dbus_interface=NM_DBUS_INTERFACE, in_signature="a{sa{sv}}", out_signature="s"
    )
    def NeedSecrets(self, settings: dict[str, dict[str, Any]]) -> str:
        """
        Check if secrets are needed.

        Always return '' to prevent NM from asking agents for secrets.
        We handle authentication ourselves via direct browser auth in Connect().
        This is necessary because KDE's secrets agent (and others) don't support
        our custom pulse-sso VPN type.
        """
        settings = convert_dbus_types(settings)
        vpn_secrets = settings.get("vpn", {}).get("secrets", {})

        if vpn_secrets.get("cookie"):
            logger.info("NeedSecrets: have cookie, no secrets needed")
        else:
            logger.info(
                "NeedSecrets: no cookie, but returning empty (we handle auth in Connect)"
            )

        # Always return '' - we handle auth ourselves, don't rely on secrets agents
        return ""

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature="", out_signature="")
    def Disconnect(self):
        """
        Stop VPN connection.

        Called by NetworkManager when user requests disconnection OR reactively
        when NM detects the tunnel (tun0) has died.

        Key insight: when openconnect dies, _on_openconnect_exit() fires FIRST
        (via SIGCHLD/GLib child_watch), setting self.proc = None. NM's reactive
        Disconnect() arrives later over D-Bus. When the USER clicks disconnect,
        NM calls Disconnect() while self.proc is still running (not None).

        - proc is not None → user-initiated disconnect → remove flag file, quit
        - proc is None → reactive disconnect → stay alive with cookie for reconnect
        """
        logger.info("Disconnect called")

        # If openconnect has already exited (killed externally or network failure),
        # this is NM's reactive cleanup after the tunnel died.
        # Key insight: when openconnect dies externally, _on_openconnect_exit()
        # fires FIRST (via SIGCHLD/GLib child_watch), setting self.proc = None.
        # NM's reactive Disconnect() arrives later over D-Bus.
        # When the USER clicks disconnect, NM calls Disconnect() while
        # self.proc is still running (not None).
        #
        # We must cooperate with NM's teardown (emit Stopped) then re-activate
        # through NM's proper ActivateConnection flow. If we return early,
        # NM tears down routes anyway but our scheduled restart creates a
        # new tunnel that NM doesn't know about → zombie VPN.
        if self.proc is None and not self._disconnect_requested:
            # If re-activation is already pending, this is a second Disconnect()
            # call — treat as user-initiated disconnect
            if self._reactivation_timeout_id is not None:
                logger.info("Disconnect called during pending re-activation — "
                            "treating as user disconnect")
                GLib.source_remove(self._reactivation_timeout_id)
                self._reactivation_timeout_id = None
                self._disconnect_requested = True
                self.cookie = None
                self.gateway = None
                self.StateChanged(ServiceState.Stopped)
                self.loop.quit()
                return

            logger.info("Disconnect called but openconnect already exited — "
                        "cooperating with NM teardown, will re-activate")

            # Cancel any pending auth timers
            self._cancel_direct_auth_timer()
            self._kill_auth_dialog()

            # Determine if we should re-activate after NM teardown
            should_reactivate = bool(
                self.gateway and (self.cookie or self._reconnection_pending)
            )

            # Reset reconnection state (will be re-set in Connect() if needed)
            self._reconnection_pending = False

            # Tell NM we stopped — lets NM properly tear down routes
            self.StateChanged(ServiceState.Stopped)

            # Schedule VPN re-activation through NM (after teardown completes)
            if should_reactivate:
                logger.info("Scheduling VPN re-activation through NetworkManager in 1s")
                self._reactivation_timeout_id = GLib.timeout_add(
                    1000, self._reactivate_vpn_via_nm
                )
            else:
                logger.info("No credentials for re-activation, staying stopped")
                if self._idle_quit_timeout_id is not None:
                    GLib.source_remove(self._idle_quit_timeout_id)
                self._idle_quit_timeout_id = GLib.timeout_add(
                    300000, self._on_idle_quit_timeout
                )

            return  # Don't quit — keep service alive for re-activation

        # If reconnection is in progress, clean up but keep the service alive.
        # NM's state machine may call Disconnect() in reaction to our
        # StateChanged(Starting) during reconnection.  If we quit here, NM
        # won't be able to call Connect() when the external service triggers
        # nmcli connection up.
        if self._reconnection_pending and self.proc is None:
            logger.info(
                "Disconnect during reconnection pending — "
                "cleaning up auth state but keeping service alive"
            )
            self._cancel_direct_auth_timer()
            self._kill_auth_dialog()
            self._reconnection_pending = False
            self.StateChanged(ServiceState.Stopped)
            return

        if self.proc is not None:
            # User/NM initiated disconnect while VPN is running
            logger.info("User-initiated disconnect — removing auto-reconnect flag")
            self._disconnect_requested = True

            # Remove flag file so external service doesn't reconnect
            try:
                os.unlink("/run/vpn-auto-reconnect")
            except FileNotFoundError:
                pass

            # Cancel any pending auth
            self._cancel_direct_auth_timer()
            self._kill_auth_dialog()
            self._reconnection_pending = False

            # Cancel any pending re-activation
            if self._reactivation_timeout_id is not None:
                GLib.source_remove(self._reactivation_timeout_id)
                self._reactivation_timeout_id = None

            # Clear credentials and pending state to prevent restart
            self.cookie = None
            self.gateway = None
            self.pending_connection = None

            # Kill openconnect
            logger.info("Terminating openconnect process %d", self.proc.pid)
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                logger.warning("Process did not terminate, killing")
                self.proc.kill()
                self.proc.wait()

            logger.info("openconnect exit code: %d", self.proc.returncode)
            self.proc = None

            self._clear_cached_secrets()
            self.StateChanged(ServiceState.Stopped)

            # Exit the service - NM will restart it when needed
            logger.info("Stopping service event loop")
            self.loop.quit()
        else:
            # Fallback: reactive disconnect with disconnect already requested
            logger.info("Reactive disconnect (disconnect_requested) — stopping")
            self.StateChanged(ServiceState.Stopped)
            self.loop.quit()

    def _clear_cached_secrets(self):
        """Clear cached VPN secrets from NetworkManager via D-Bus."""
        try:
            # Get the connection settings via D-Bus
            bus = dbus.SystemBus()
            nm = bus.get_object(
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/NetworkManager/Settings",
            )
            settings_iface = dbus.Interface(
                nm, "org.freedesktop.NetworkManager.Settings"
            )

            # Find our connection by service type
            for conn_path in settings_iface.ListConnections():
                conn = bus.get_object("org.freedesktop.NetworkManager", conn_path)
                conn_settings = dbus.Interface(
                    conn, "org.freedesktop.NetworkManager.Settings.Connection"
                )
                settings = conn_settings.GetSettings()

                conn_type = settings.get("connection", {}).get("type", "")
                vpn_service = settings.get("vpn", {}).get("service-type", "")
                if conn_type == "vpn" and vpn_service == NM_DBUS_SERVICE:
                    # Clear secrets by calling ClearSecrets()
                    conn_settings.ClearSecrets()
                    logger.info("Cleared cached VPN secrets via D-Bus")
                    return

            logger.warning("Could not find VPN connection to clear secrets")
        except Exception as e:
            logger.warning("Failed to clear secrets via D-Bus: %s", e)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature="a{sv}")
    def SetConfig(self, config: dict[str, Any]):
        """Called by helper script with general VPN config."""
        logger.info("SetConfig called: %s", config)
        self.config = convert_dbus_types(config)
        self.Config(config)
        logger.info("Config signal emitted")

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature="a{sv}")
    def SetIp4Config(self, config: dict[str, Any]):
        """
        Called by helper script with IPv4 configuration.

        This signals that the VPN tunnel is established.
        """
        logger.info("SetIp4Config called: %s", config)

        # Reset failure counters on successful connection
        if self._auth_failure_count > 0:
            logger.info(
                "Resetting auth failure count (was %d)", self._auth_failure_count
            )
            self._auth_failure_count = 0

        if self._reconnection_retry_count > 0:
            logger.info(
                "Resetting reconnection retry count (was %d)",
                self._reconnection_retry_count,
            )
            self._reconnection_retry_count = 0

        # Reset consecutive restart failure counter on successful connection
        if self._consecutive_restart_failures > 0:
            logger.info(
                "Resetting consecutive restart failure count (was %d)",
                self._consecutive_restart_failures,
            )
            self._consecutive_restart_failures = 0

        self._cancel_direct_auth_timer()

        # Store converted types for internal use
        self.ip4config = convert_dbus_types(config)

        # Emit signal to NetworkManager with raw D-Bus types (not converted)
        # The signal expects a{sv} so we pass the config as received
        self.Ip4Config(config)
        self.StateChanged(ServiceState.Started)

        logger.info("VPN connection established")

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature="a{sv}")
    @trace
    def SetIp6Config(self, config: dict[str, Any]):
        """Called by helper script with IPv6 configuration."""
        self.Ip6Config(config)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature="s")
    @trace
    def SetFailure(self, reason: str):
        """Called when VPN connection fails."""
        logger.error("VPN failure: %s", reason)
        self.StateChanged(ServiceState.Stopped)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature="a{sa{sv}}")
    def NewSecrets(self, connection: dict[str, dict[str, Any]]):
        """
        Called by NM with secrets collected from auth-dialog.

        After SecretsRequired is emitted, NM runs the auth-dialog and
        sends the collected secrets here.
        """
        connection = convert_dbus_types(connection)
        logger.info("NewSecrets called with: %s", connection)

        vpn_secrets = connection.get("vpn", {}).get("secrets", {})

        # If no cookie provided (e.g., KDE plasma-nm sends empty secrets),
        # trigger direct auth instead of failing
        if not vpn_secrets.get("cookie"):
            logger.info("NewSecrets called with no cookie, triggering direct auth")

            # Extract gateway from connection or pending_connection
            vpn_data = connection.get("vpn", {}).get("data", {})
            gateway = vpn_data.get("gateway", "")
            if not gateway and self.pending_connection:
                gateway = (
                    self.pending_connection.get("vpn", {})
                    .get("data", {})
                    .get("gateway", "")
                )

            if not gateway:
                logger.error("No gateway available for direct auth")
                self.StateChanged(ServiceState.Stopped)
                self.Failure("No VPN gateway configured")
                return

            # Ensure gateway has https:// prefix
            if not gateway.startswith("http://") and not gateway.startswith("https://"):
                gateway = f"https://{gateway}"

            self.gateway = gateway
            self._reconnection_pending = True
            self._reconnection_retry_count = 0
            self._schedule_direct_auth(0)
            return

        if self.pending_connection:
            # Normal flow - update pending connection and connect
            if "vpn" not in self.pending_connection:
                self.pending_connection["vpn"] = {}
            if "secrets" not in self.pending_connection["vpn"]:
                self.pending_connection["vpn"]["secrets"] = {}
            self.pending_connection["vpn"]["secrets"].update(vpn_secrets)

            self._do_connect(self.pending_connection)
            self.pending_connection = None
        elif self.gateway:
            # Re-auth flow - build connection from stored gateway
            logger.info("Re-auth flow: using stored gateway %s", self.gateway)
            reauth_connection = {
                "vpn": {
                    "data": {"gateway": self.gateway},
                    "secrets": vpn_secrets,
                }
            }
            self._do_connect(reauth_connection)
        else:
            logger.warning("NewSecrets called but no pending connection or gateway")

    # D-Bus Signals

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature="u")
    def StateChanged(self, state: int):
        """Emitted when VPN state changes."""
        logger.info("StateChanged: %s", ServiceState(state).name)

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature="a{sv}")
    def Config(self, config: dict[str, Any]):
        """Emitted with general VPN configuration."""
        pass

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature="a{sv}")
    def Ip4Config(self, ip4config: dict[str, Any]):
        """Emitted with IPv4 configuration."""
        logger.info("Ip4Config signal: %s", ip4config)

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature="a{sv}")
    def Ip6Config(self, ip6config: dict[str, Any]):
        """Emitted with IPv6 configuration."""
        pass

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature="s")
    def Failure(self, reason: str):
        """Emitted when connection fails."""
        pass

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature="sas")
    def SecretsRequired(self, message: str, secrets: list):
        """Emitted during ConnectInteractive when secrets are needed."""
        logger.info("SecretsRequired: %s, secrets=%s", message, secrets)


def run(args: Namespace):
    """Main entry point - setup D-Bus and run event loop."""
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    bus = dbus.SystemBus()
    bus_name = dbus.service.BusName(args.bus_name, bus)

    loop = GLib.MainLoop()

    plugin = PulseSSOPlugin(
        loop=loop,
        conn=bus,
        object_path=NM_DBUS_PATH,
        bus_name=bus_name,
        helper_script=args.helper_script,
    )

    # Handle termination signals
    def handle_signal(signum, frame):
        logger.info("Received signal %d, shutting down", signum)
        loop.quit()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info("Starting %s D-Bus service", args.bus_name)
    loop.run()
    logger.info("Service stopped")


def main():
    parser = ArgumentParser(description="NetworkManager VPN Plugin for Pulse SSO")
    parser.add_argument(
        "--bus-name", default=NM_DBUS_SERVICE, help="D-Bus service name"
    )
    parser.add_argument(
        "--helper-script", required=True, help="Path to openconnect helper script"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        run(args)
    except Exception:
        logger.exception("Service failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

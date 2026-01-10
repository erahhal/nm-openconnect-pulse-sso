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
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from enum import IntEnum
from functools import wraps
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Any, Optional

import dbus
import dbus.mainloop.glib
import dbus.service
from dbus.service import method, signal as dbus_signal
from gi.repository import GLib

NM_DBUS_SERVICE = 'org.freedesktop.NetworkManager.pulse-sso'
NM_DBUS_INTERFACE = 'org.freedesktop.NetworkManager.VPN.Plugin'
NM_DBUS_PATH = '/org/freedesktop/NetworkManager/VPN/Plugin'

# Config file written by NixOS
CONFIG_PATH = Path('/etc/nm-pulse-sso/config')


def is_dtls_enabled() -> bool:
    """
    Check if DTLS/ESP is enabled by reading the NixOS config file.

    Returns True if DTLS is enabled (better performance, full restart on reconnect).
    Returns False if DTLS is disabled (uses --no-dtls, SIGUSR2 reconnect).
    """
    try:
        if CONFIG_PATH.exists():
            content = CONFIG_PATH.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('ENABLE_DTLS='):
                    value = line.split('=', 1)[1].strip().lower()
                    return value == 'true'
    except Exception as e:
        logger.warning('Failed to read config file %s: %s', CONFIG_PATH, e)
    # Default to DTLS disabled (current behavior)
    return False


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nm-pulse-sso')


def trace(fn):
    """Decorator to log method calls for debugging."""
    @wraps(fn)
    def traced(self, *args, **kwargs):
        logger.debug('%s(%s, %s)', fn.__name__, args, kwargs)
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
    _dbus_error_name = 'org.freedesktop.NetworkManager.VPN.Error.InteractiveNotSupported'


class LaunchFailedError(dbus.DBusException):
    """Exception when VPN launch fails."""
    _dbus_error_name = 'org.freedesktop.NetworkManager.VPN.Error.LaunchFailed'


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

        # Pending restart timeout ID (to cancel if connection succeeds)
        self._restart_timeout_id: Optional[int] = None

        # Count consecutive auth failures to prevent infinite loops
        self._auth_failure_count: int = 0

        # Flag to prevent Disconnect() from quitting when we're about to trigger
        # browser re-auth (prevents race with NM calling Disconnect after StateChanged)
        self._reconnection_pending: bool = False

        # Retry tracking for reconnection attempts (nm-applet may not be ready after suspend)
        self._reconnection_retry_count: int = 0
        self._max_reconnection_retries: int = 10
        self._reconnection_retry_interval: int = 3000  # milliseconds

        # Track the last cookie rejected by the server to avoid tight restart loops
        self._last_failed_cookie: Optional[str] = None

        # Track any pending direct-auth timer (GLib source ID) to prevent duplicates
        self._direct_auth_timeout_id: Optional[int] = None

        # Track secrets request timeout - if NM's agent doesn't respond, fall back to direct auth
        # This handles cases where plasma-nm or other agents don't support our VPN type
        self._secrets_timeout_id: Optional[int] = None
        self._secrets_timeout_ms: int = 5000  # 5 seconds to wait for secrets agent

    def _do_connect(self, connection: dict):
        """
        Actually establish the VPN connection with provided credentials.

        This is called from Connect(), ConnectInteractive(), or NewSecrets()
        once we have all required credentials.
        """
        try:
            # Extract VPN data (from connection config)
            vpn_data = connection.get('vpn', {}).get('data', {})
            gateway = vpn_data.get('gateway', '')

            # Extract secrets
            vpn_secrets = connection.get('vpn', {}).get('secrets', {})
            cookie = vpn_secrets.get('cookie', '')
            servercert = vpn_secrets.get('gwcert', '')

            if not gateway:
                raise LaunchFailedError('No gateway specified in VPN configuration')

            if not cookie:
                raise LaunchFailedError('No cookie provided - auth-dialog may have failed')

            # Ensure gateway has https:// prefix (openconnect needs full URL)
            if not gateway.startswith('http://') and not gateway.startswith('https://'):
                gateway = f'https://{gateway}'

            if self._last_failed_cookie and cookie == self._last_failed_cookie:
                logger.warning('Provided cookie matches last failed cookie; deferring until new credentials arrive')
                self._ensure_direct_auth('stale cookie from NetworkManager', delay_ms=0)
                return

            if self._last_failed_cookie and cookie != self._last_failed_cookie:
                logger.debug('Received new cookie, clearing failed-cookie tracker')
                self._last_failed_cookie = None

            logger.info('Starting openconnect for gateway: %s', gateway)
            self.StateChanged(ServiceState.Starting)

            self.gateway = gateway
            self.cookie = cookie
            self.servercert = servercert

            # Reset disconnect flag - we're starting a new connection
            self._disconnect_requested = False

            # Clear reconnection state - we're now actually connecting
            self._reconnection_pending = False
            self._reconnection_retry_count = 0

            self._start_openconnect()

        except LaunchFailedError:
            raise
        except Exception as e:
            logger.exception('_do_connect failed')
            self.StateChanged(ServiceState.Stopped)
            raise LaunchFailedError(f'Connection failed: {e}')

    def _start_openconnect(self):
        """
        Start openconnect with the current cookie.

        This is called both for initial connection and for restarts after
        unexpected exits (non-auth failures).
        """
        # Build openconnect command based on working openconnect-pulse-launcher
        # Key differences from CLI version:
        # - No -b (background): we need to track the process for disconnect
        # - Using --script with helper that CALLS vpnc-script AND reports to D-Bus
        #
        # DTLS/ESP handling:
        # - With DTLS disabled (default): --no-dtls forces SSL-only mode.
        #   Required for SIGUSR2 reconnection after suspend/resume to work.
        #   Pulse ESP reconnect is broken: https://gitlab.com/openconnect/openconnect/-/issues/141
        # - With DTLS enabled: No --no-dtls flag, uses ESP/UDP for better performance.
        #   Reconnection uses SIGTERM (full restart) instead of SIGUSR2.
        dtls_enabled = is_dtls_enabled()
        logger.info('DTLS/ESP mode: %s', 'enabled' if dtls_enabled else 'disabled')

        cmd = [
            'openconnect',
        ]

        # Only add --no-dtls if DTLS is disabled
        if not dtls_enabled:
            cmd.append('--no-dtls')

        cmd.extend([
            '-C', self.cookie,
            '--protocol=pulse',
            f'--script={self.helper_script}',
            self.gateway,
        ])

        # Log command (but mask cookie value)
        safe_cmd = [c if i == 0 or cmd[i-1] != '-C' else '***' for i, c in enumerate(cmd)]
        logger.info('Executing: %s', ' '.join(safe_cmd))

        # Set environment for helper script to find our D-Bus service
        env = os.environ.copy()
        env['NM_DBUS_SERVICE_PULSE_SSO'] = NM_DBUS_SERVICE

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

        logger.info('openconnect started with PID %d', self.proc.pid)

        # Monitor the process for unexpected exits
        # GLib.child_watch_add will call our callback when the process exits
        self._child_watch_id = GLib.child_watch_add(
            self.proc.pid,
            self._on_openconnect_exit
        )

    def _on_openconnect_exit(self, pid: int, status: int):
        """
        Called by GLib when openconnect process exits.

        If the exit was unexpected (not from Disconnect()) and we have a valid
        cookie, restart openconnect. Only re-authenticate on exit code 2.
        """
        # Only handle exit for the process we're currently tracking
        # This prevents stale exit events from old processes triggering restarts
        if self.proc is None or self.proc.pid != pid:
            logger.debug('Ignoring exit for old process PID %d (current: %s)',
                         pid, self.proc.pid if self.proc else 'None')
            return

        # Convert wait status to exit code
        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            exit_code = -os.WTERMSIG(status)
        else:
            exit_code = status

        logger.info('openconnect (PID %d) exited with code %d', pid, exit_code)

        # Clear process reference
        self.proc = None
        self._child_watch_id = None

        # If disconnect was requested, don't restart
        if self._disconnect_requested:
            logger.info('Disconnect was requested, not restarting')
            return

        # Exit code 2 means auth failure - cookie is invalid
        if exit_code == 2:
            logger.error('openconnect auth failure (exit code 2) - cookie invalid')
            failed_cookie = self.cookie
            self.cookie = None

            if failed_cookie:
                logger.debug('Tracking failed cookie to avoid reuse')
                self._last_failed_cookie = failed_cookie

            # Count consecutive auth failures to prevent infinite loops
            self._auth_failure_count += 1
            logger.info('Auth failure count: %d', self._auth_failure_count)

            if self._auth_failure_count > 3:
                logger.error('Too many consecutive auth failures (%d), giving up',
                            self._auth_failure_count)
                self.StateChanged(ServiceState.Stopped)
                self.Failure('Authentication failed repeatedly - please reconnect manually')
                return

            if self.gateway and not self._disconnect_requested:
                # Cookie expired - need to re-authenticate via browser
                # Note: SecretsRequired doesn't work here because it's only valid
                # during an ongoing ConnectInteractive() call, and NM's agent
                # system doesn't respond after suspend/resume anyway.
                logger.info('Cookie expired, launching direct auth for gateway: %s', self.gateway)
                # Set flag to prevent Disconnect() from quitting during reconnection
                self._reconnection_pending = True
                # Emit Starting (not Stopped) so NM knows we're reconnecting
                # If we emit Stopped, NM tears down the connection and nm-applet shows disconnected
                self.StateChanged(ServiceState.Starting)
                # Launch auth-dialog directly (bypasses NM's broken agent system)
                self._schedule_direct_auth(1000)
            else:
                logger.error('Cannot reconnect - no gateway or disconnect requested')
                self.StateChanged(ServiceState.Stopped)
                self.Failure('Authentication failed - cookie expired')
            return

        # Non-auth failure with valid cookie - restart
        if self.cookie and self.gateway:
            logger.warning('openconnect exited unexpectedly, restarting in 2 seconds...')
            # Signal that we're reconnecting so nm-applet doesn't clear VPN icon
            self.StateChanged(ServiceState.Starting)
            # Small delay to avoid tight restart loop
            # Track timeout ID so we can cancel if connection succeeds before timeout fires
            self._restart_timeout_id = GLib.timeout_add(2000, self._do_restart)
        else:
            logger.error('Cannot restart - no cookie or gateway')
            self.StateChanged(ServiceState.Stopped)

    def _do_restart(self) -> bool:
        """
        Actually restart openconnect (called from GLib timeout).

        Returns False to prevent the timeout from repeating.
        """
        # Clear the timeout ID since we're now executing
        self._restart_timeout_id = None

        # Double-check we still should restart
        if self._disconnect_requested:
            logger.info('Disconnect was requested during restart delay, aborting restart')
            return False

        if not self.cookie or not self.gateway:
            logger.error('Cannot restart - credentials cleared')
            self.StateChanged(ServiceState.Stopped)
            return False

        logger.info('Restarting openconnect with existing cookie')
        try:
            self._start_openconnect()
        except Exception as e:
            logger.exception('Failed to restart openconnect: %s', e)
            self.StateChanged(ServiceState.Stopped)

        return False  # Don't repeat the timeout

    def _schedule_auth_retry(self, reason: str):
        """
        Schedule an auth retry or emit failure if max retries exceeded.

        This consolidates retry logic to ensure proper state emission when
        all retries are exhausted.
        """
        if self._reconnection_retry_count >= self._max_reconnection_retries:
            logger.error('Max auth retries (%d) exceeded: %s',
                        self._max_reconnection_retries, reason)
            self._reconnection_pending = False
            self.StateChanged(ServiceState.Stopped)
            self.Failure(f'VPN reconnection failed after {self._max_reconnection_retries} attempts: {reason}')
        else:
            logger.info('Scheduling auth retry in %dms (attempt %d/%d): %s',
                       self._reconnection_retry_interval,
                       self._reconnection_retry_count,
                       self._max_reconnection_retries,
                       reason)
            self._schedule_direct_auth(self._reconnection_retry_interval)

    def _schedule_direct_auth(self, delay_ms: int):
        """
        Schedule the direct-auth helper with the provided delay, replacing any existing timer.
        """
        if delay_ms < 0:
            delay_ms = 0

        if self._direct_auth_timeout_id is not None:
            GLib.source_remove(self._direct_auth_timeout_id)

        self._direct_auth_timeout_id = GLib.timeout_add(delay_ms, self._launch_direct_auth)

    def _cancel_direct_auth_timer(self):
        """Cancel any pending direct-auth timeout."""
        if self._direct_auth_timeout_id is not None:
            GLib.source_remove(self._direct_auth_timeout_id)
            self._direct_auth_timeout_id = None

    def _schedule_secrets_timeout(self):
        """
        Schedule a fallback to direct auth if no secrets arrive.

        This handles cases where the desktop's secrets agent (e.g., plasma-nm)
        doesn't know how to get secrets for our VPN type.
        """
        self._cancel_secrets_timeout()
        logger.info('Scheduling secrets timeout (%dms) - will fall back to direct auth if no response',
                   self._secrets_timeout_ms)
        self._secrets_timeout_id = GLib.timeout_add(
            self._secrets_timeout_ms,
            self._on_secrets_timeout
        )

    def _cancel_secrets_timeout(self):
        """Cancel any pending secrets timeout."""
        if self._secrets_timeout_id is not None:
            GLib.source_remove(self._secrets_timeout_id)
            self._secrets_timeout_id = None

    def _on_secrets_timeout(self) -> bool:
        """
        Called when secrets timeout expires - fall back to direct auth.

        This handles cases where plasma-nm or other agents don't support
        our VPN type and can't provide secrets.

        Returns False to prevent GLib timeout from repeating.
        """
        self._secrets_timeout_id = None

        # Check if we still need secrets (NewSecrets wasn't called)
        if self.pending_connection is None:
            logger.debug('Secrets timeout fired but no pending connection - ignoring')
            return False

        if self.proc is not None:
            logger.debug('Secrets timeout fired but already connected - ignoring')
            return False

        logger.info('Secrets agent did not respond in time, falling back to direct auth')

        # Extract gateway from pending connection for direct auth
        vpn_data = self.pending_connection.get('vpn', {}).get('data', {})
        gateway = vpn_data.get('gateway', '')

        if not gateway:
            logger.error('No gateway in pending connection, cannot do direct auth')
            self.StateChanged(ServiceState.Stopped)
            self.Failure('No VPN gateway configured')
            self.pending_connection = None
            return False

        # Ensure gateway has https:// prefix
        if not gateway.startswith('http://') and not gateway.startswith('https://'):
            gateway = f'https://{gateway}'

        # Set up for direct auth
        self.gateway = gateway
        self._reconnection_pending = True
        self._reconnection_retry_count = 0

        # Launch direct auth (will open browser)
        self._schedule_direct_auth(0)

        return False

    def _ensure_direct_auth(self, reason: str, delay_ms: int = 0):
        """
        Ensure the direct auth flow is scheduled (used when NM hands us a stale cookie).
        """
        if not self._reconnection_pending:
            logger.info('Scheduling direct auth (%s)', reason)
        else:
            logger.info('Direct auth already pending (%s) - refreshing timer', reason)

        self._reconnection_pending = True
        self.StateChanged(ServiceState.Starting)
        self._schedule_direct_auth(delay_ms)

    def _launch_direct_auth(self) -> bool:
        """
        Launch auth-dialog directly, bypassing NM's agent system.

        After suspend/resume, nm-applet's secret agent often doesn't respond.
        This method bypasses NM entirely by running the auth-dialog directly
        in the user's graphical session using runuser.

        Returns False to prevent GLib timeout from repeating.
        """
        # GLib invoked this callback; clear the stored source ID
        self._direct_auth_timeout_id = None

        if not self._reconnection_pending:
            logger.debug('Reconnection no longer pending, skipping direct auth')
            return False

        self._reconnection_retry_count += 1

        if self._reconnection_retry_count > self._max_reconnection_retries:
            logger.error('Max auth retries (%d) exceeded, giving up',
                        self._max_reconnection_retries)
            self._reconnection_pending = False
            self.StateChanged(ServiceState.Stopped)
            self.Failure('VPN reconnection failed - please reconnect manually')
            return False

        logger.info('Direct auth attempt %d/%d',
                   self._reconnection_retry_count, self._max_reconnection_retries)

        try:
            # Find graphical session via loginctl
            result = subprocess.run(
                ['loginctl', 'list-sessions', '--no-legend'],
                capture_output=True, text=True, timeout=5
            )

            user = None
            display = ':0'

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 1:
                    session_id = parts[0]
                    # Get session properties
                    # Note: --property=A,B,C syntax doesn't work, must use separate flags
                    show = subprocess.run(
                        ['loginctl', 'show-session', session_id,
                         '--property=Name', '--property=Type', '--property=Display'],
                        capture_output=True, text=True, timeout=5
                    )
                    props = {}
                    for prop_line in show.stdout.strip().split('\n'):
                        if '=' in prop_line:
                            k, v = prop_line.split('=', 1)
                            props[k] = v

                    # Look for graphical session (x11 or wayland)
                    if props.get('Type') in ('x11', 'wayland'):
                        user = props.get('Name')
                        display = props.get('Display') or ':0'
                        logger.debug('Found graphical session: user=%s, type=%s, display=%s',
                                    user, props.get('Type'), display)
                        break

            if not user:
                logger.error('No graphical session found, will retry')
                self._schedule_direct_auth(self._reconnection_retry_interval)
                return False

            # Get UID for XDG_RUNTIME_DIR
            uid = pwd.getpwnam(user).pw_uid

            # Derive auth-dialog path from helper_script (same directory)
            auth_dialog = self.helper_script.replace('nm-pulse-sso-helper', 'pulse-sso-auth-dialog')

            logger.info('Launching auth-dialog as %s (uid=%d, display=%s)', user, uid, display)

            # Use systemd-run to launch in user's session, escaping NM's ProtectHome sandbox
            # --machine=user@ connects to the user's systemd instance
            # --pipe connects stdin/stdout/stderr
            # --wait waits for completion
            # --setenv passes the DISPLAY for X11/Wayland access
            proc = subprocess.Popen(
                [
                    'systemd-run',
                    '--user',
                    f'--machine={user}@',
                    '--pipe',
                    '--wait',
                    '--quiet',
                    f'--setenv=DISPLAY={display}',
                    '--',
                    auth_dialog,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Auth-dialog protocol: send gateway via stdin
            input_data = f"DATA_KEY=gateway\nDATA_VAL={self.gateway}\nDONE\n"
            stdout, stderr = proc.communicate(input=input_data.encode(), timeout=300)

            if proc.returncode != 0:
                logger.error('Auth-dialog failed (exit %d): %s',
                            proc.returncode, stderr.decode())
                self._schedule_direct_auth(self._reconnection_retry_interval)
                return False

            # Parse cookie from stdout (protocol: key\nvalue\nkey\nvalue...)
            lines = stdout.decode().strip().split('\n')
            cookie = None
            gwcert = None
            i = 0
            while i < len(lines):
                if lines[i] == 'cookie' and i + 1 < len(lines):
                    cookie = lines[i + 1]
                    i += 2
                elif lines[i] == 'gwcert' and i + 1 < len(lines):
                    gwcert = lines[i + 1]
                    i += 2
                else:
                    i += 1

            if not cookie:
                logger.error('No cookie in auth-dialog output: %s', stdout.decode())
                self._schedule_auth_retry('No cookie in auth-dialog output')
                return False

            # Success! Update credentials and start openconnect
            logger.info('Got fresh cookie from auth-dialog, starting openconnect')
            self.cookie = cookie
            self.servercert = gwcert
            self._last_failed_cookie = None

            self.StateChanged(ServiceState.Starting)
            try:
                self._start_openconnect()
                # Only clear reconnection state AFTER openconnect starts successfully
                # This ensures retries work if _start_openconnect() fails
                self._reconnection_pending = False
                self._reconnection_retry_count = 0
                self._auth_failure_count = 0
                self._cancel_direct_auth_timer()
            except Exception as e:
                logger.exception('Failed to start openconnect after auth: %s', e)
                self._schedule_auth_retry('Failed to start openconnect')
                return False

        except subprocess.TimeoutExpired:
            logger.error('Auth-dialog timed out (user may have closed browser)')
            self._schedule_auth_retry('Auth-dialog timed out')
        except Exception as e:
            logger.exception('Direct auth failed: %s', e)
            self._schedule_auth_retry(f'Direct auth failed: {e}')

        return False

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='a{sa{sv}}',
            out_signature='')
    def Connect(self, connection: dict[str, dict[str, Any]]):
        """
        Non-interactive VPN connection.

        If no cookie is present, launch direct browser auth.
        This is the main entry point now that NeedSecrets returns '' to
        bypass NM's secrets agent system (which doesn't support our VPN type).
        """
        connection = convert_dbus_types(connection)
        logger.info('Connect called with connection: %s', connection)

        vpn_secrets = connection.get('vpn', {}).get('secrets', {})
        if not vpn_secrets.get('cookie'):
            # No cookie - launch direct auth (browser popup)
            logger.info('No cookie in Connect, launching direct auth')

            # Extract gateway from connection
            vpn_data = connection.get('vpn', {}).get('data', {})
            gateway = vpn_data.get('gateway', '')
            if not gateway:
                raise LaunchFailedError('No gateway specified in VPN configuration')

            # Ensure gateway has https:// prefix
            if not gateway.startswith('http://') and not gateway.startswith('https://'):
                gateway = f'https://{gateway}'

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

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='a{sa{sv}}a{sv}',
            out_signature='')
    def ConnectInteractive(self, connection: dict, details: dict):
        """
        Interactive connection - trigger direct auth if no cookie.

        We launch the browser directly instead of emitting SecretsRequired,
        which avoids plasma-nm showing a generic secrets dialog.
        """
        connection = convert_dbus_types(connection)
        logger.info('ConnectInteractive called with connection: %s', connection)

        # Store connection for later use
        self.pending_connection = connection

        # Extract secrets
        vpn_secrets = connection.get('vpn', {}).get('secrets', {})
        cookie = vpn_secrets.get('cookie', '')

        # Extract gateway for direct auth
        vpn_data = connection.get('vpn', {}).get('data', {})
        gateway = vpn_data.get('gateway', '')

        if cookie and self._last_failed_cookie and cookie == self._last_failed_cookie:
            logger.info('ConnectInteractive received stale cookie, triggering direct auth')
            cookie = ''  # Treat as no cookie

        if not cookie:
            # No cookie - trigger direct auth immediately
            # Don't emit SecretsRequired to avoid plasma-nm showing a dialog
            logger.info('No cookie, triggering direct auth immediately')

            if not gateway:
                raise LaunchFailedError('No gateway specified in VPN configuration')

            # Ensure gateway has https:// prefix
            if not gateway.startswith('http://') and not gateway.startswith('https://'):
                gateway = f'https://{gateway}'

            self.gateway = gateway
            self._reconnection_pending = True
            self._reconnection_retry_count = 0
            self.StateChanged(ServiceState.Starting)
            self._schedule_direct_auth(0)
            return

        # Have cookie, proceed with connection
        self._do_connect(connection)

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='a{sa{sv}}',
            out_signature='s')
    def NeedSecrets(self, settings: dict[str, dict[str, Any]]) -> str:
        """
        Check if secrets are needed.

        Always return '' to prevent NM from asking agents for secrets.
        We handle authentication ourselves via direct browser auth in Connect().
        This is necessary because KDE's secrets agent (and others) don't support
        our custom pulse-sso VPN type.
        """
        settings = convert_dbus_types(settings)
        vpn_secrets = settings.get('vpn', {}).get('secrets', {})

        if vpn_secrets.get('cookie'):
            logger.info('NeedSecrets: have cookie, no secrets needed')
        else:
            logger.info('NeedSecrets: no cookie, but returning empty (we handle auth in Connect)')

        # Always return '' - we handle auth ourselves, don't rely on secrets agents
        return ''

    @method(dbus_interface=NM_DBUS_INTERFACE,
            in_signature='',
            out_signature='')
    def Disconnect(self):
        """
        Stop VPN connection.

        Called by NetworkManager when user requests disconnection.
        """
        logger.info('Disconnect called')

        # If reconnection is in progress, don't quit - just mark disconnect requested
        # The user may have clicked disconnect during re-auth, so we set the flag
        # and let the reconnection logic handle it
        if self._reconnection_pending:
            logger.info('Disconnect called but reconnection pending, not quitting')
            self._disconnect_requested = True
            self.StateChanged(ServiceState.Stopped)
            return

        # Mark that disconnect was requested - prevents auto-restart
        self._disconnect_requested = True

        # Clear credentials and pending state to prevent restart
        self.cookie = None
        self.gateway = None
        self._last_failed_cookie = None
        self.pending_connection = None
        self._cancel_direct_auth_timer()
        self._cancel_secrets_timeout()

        if self.proc is not None:
            logger.info('Terminating openconnect process %d', self.proc.pid)
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except:
                logger.warning('Process did not terminate, killing')
                self.proc.kill()
                self.proc.wait()

            logger.info('openconnect exit code: %d', self.proc.returncode)
            self.proc = None

        # Clear cached VPN secrets so next connect gets fresh auth
        # The cookie becomes invalid after disconnect, so we need to
        # force re-authentication on the next connect
        self._clear_cached_secrets()

        self.StateChanged(ServiceState.Stopped)

        # Exit the service - NM will restart it when needed
        logger.info('Stopping service event loop')
        self.loop.quit()

    def _clear_cached_secrets(self):
        """Clear cached VPN secrets from NetworkManager via D-Bus."""
        try:
            # Get the connection settings via D-Bus
            bus = dbus.SystemBus()
            nm = bus.get_object('org.freedesktop.NetworkManager',
                               '/org/freedesktop/NetworkManager/Settings')
            settings_iface = dbus.Interface(nm, 'org.freedesktop.NetworkManager.Settings')

            # Find our connection by name
            for conn_path in settings_iface.ListConnections():
                conn = bus.get_object('org.freedesktop.NetworkManager', conn_path)
                conn_settings = dbus.Interface(conn, 'org.freedesktop.NetworkManager.Settings.Connection')
                settings = conn_settings.GetSettings()

                conn_id = settings.get('connection', {}).get('id', '')
                if conn_id == 'Pulse VPN':
                    # Clear secrets by calling ClearSecrets()
                    conn_settings.ClearSecrets()
                    logger.info('Cleared cached VPN secrets via D-Bus')
                    return

            logger.warning('Could not find Pulse VPN connection to clear secrets')
        except Exception as e:
            logger.warning('Failed to clear secrets via D-Bus: %s', e)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sv}')
    def SetConfig(self, config: dict[str, Any]):
        """Called by helper script with general VPN config."""
        logger.info('SetConfig called: %s', config)
        self.config = convert_dbus_types(config)
        self.Config(config)
        logger.info('Config signal emitted')

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sv}')
    def SetIp4Config(self, config: dict[str, Any]):
        """
        Called by helper script with IPv4 configuration.

        This signals that the VPN tunnel is established.
        """
        logger.info('SetIp4Config called: %s', config)

        # Cancel any pending restart timeout - we're successfully connected now
        if self._restart_timeout_id is not None:
            logger.debug('Canceling pending restart timeout')
            GLib.source_remove(self._restart_timeout_id)
            self._restart_timeout_id = None

        # Reset auth failure counter on successful connection
        if self._auth_failure_count > 0:
            logger.info('Resetting auth failure count (was %d)', self._auth_failure_count)
            self._auth_failure_count = 0

        # Reset reconnection retry counter on successful connection
        if self._reconnection_retry_count > 0:
            logger.info('Resetting reconnection retry count (was %d)', self._reconnection_retry_count)
            self._reconnection_retry_count = 0

        if self._last_failed_cookie is not None:
            logger.debug('Clearing last failed cookie after successful connection')
            self._last_failed_cookie = None

        self._cancel_direct_auth_timer()

        # Store converted types for internal use
        self.ip4config = convert_dbus_types(config)

        # Emit signal to NetworkManager with raw D-Bus types (not converted)
        # The signal expects a{sv} so we pass the config as received
        self.Ip4Config(config)
        self.StateChanged(ServiceState.Started)

        logger.info('VPN connection established')

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sv}')
    @trace
    def SetIp6Config(self, config: dict[str, Any]):
        """Called by helper script with IPv6 configuration."""
        self.Ip6Config(config)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='s')
    @trace
    def SetFailure(self, reason: str):
        """Called when VPN connection fails."""
        logger.error('VPN failure: %s', reason)
        self.StateChanged(ServiceState.Stopped)

    @method(dbus_interface=NM_DBUS_INTERFACE, in_signature='a{sa{sv}}')
    def NewSecrets(self, connection: dict[str, dict[str, Any]]):
        """
        Called by NM with secrets collected from auth-dialog.

        After SecretsRequired is emitted, NM runs the auth-dialog and
        sends the collected secrets here.
        """
        # Cancel secrets timeout - we got a response from an agent
        self._cancel_secrets_timeout()

        connection = convert_dbus_types(connection)
        logger.info('NewSecrets called with: %s', connection)

        vpn_secrets = connection.get('vpn', {}).get('secrets', {})

        # If no cookie provided (e.g., KDE plasma-nm sends empty secrets),
        # trigger direct auth instead of failing
        if not vpn_secrets.get('cookie'):
            logger.info('NewSecrets called with no cookie, triggering direct auth')

            # Extract gateway from connection or pending_connection
            vpn_data = connection.get('vpn', {}).get('data', {})
            gateway = vpn_data.get('gateway', '')
            if not gateway and self.pending_connection:
                gateway = self.pending_connection.get('vpn', {}).get('data', {}).get('gateway', '')

            if not gateway:
                logger.error('No gateway available for direct auth')
                self.StateChanged(ServiceState.Stopped)
                self.Failure('No VPN gateway configured')
                return

            # Ensure gateway has https:// prefix
            if not gateway.startswith('http://') and not gateway.startswith('https://'):
                gateway = f'https://{gateway}'

            self.gateway = gateway
            self._reconnection_pending = True
            self._reconnection_retry_count = 0
            self._schedule_direct_auth(0)
            return

        if self.pending_connection:
            # Normal flow - update pending connection and connect
            if 'vpn' not in self.pending_connection:
                self.pending_connection['vpn'] = {}
            if 'secrets' not in self.pending_connection['vpn']:
                self.pending_connection['vpn']['secrets'] = {}
            self.pending_connection['vpn']['secrets'].update(vpn_secrets)

            self._do_connect(self.pending_connection)
            self.pending_connection = None
        elif self.gateway:
            # Re-auth flow - build connection from stored gateway
            logger.info('Re-auth flow: using stored gateway %s', self.gateway)
            reauth_connection = {
                'vpn': {
                    'data': {'gateway': self.gateway},
                    'secrets': vpn_secrets,
                }
            }
            self._do_connect(reauth_connection)
        else:
            logger.warning('NewSecrets called but no pending connection or gateway')

    # D-Bus Signals

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature='u')
    def StateChanged(self, state: int):
        """Emitted when VPN state changes."""
        logger.info('StateChanged: %s', ServiceState(state).name)

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature='a{sv}')
    def Config(self, config: dict[str, Any]):
        """Emitted with general VPN configuration."""
        pass

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature='a{sv}')
    def Ip4Config(self, ip4config: dict[str, Any]):
        """Emitted with IPv4 configuration."""
        logger.info('Ip4Config signal: %s', ip4config)

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature='a{sv}')
    def Ip6Config(self, ip6config: dict[str, Any]):
        """Emitted with IPv6 configuration."""
        pass

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature='s')
    def Failure(self, reason: str):
        """Emitted when connection fails."""
        pass

    @dbus_signal(dbus_interface=NM_DBUS_INTERFACE, signature='sas')
    def SecretsRequired(self, message: str, secrets: list):
        """Emitted during ConnectInteractive when secrets are needed."""
        logger.info('SecretsRequired: %s, secrets=%s', message, secrets)


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
        logger.info('Received signal %d, shutting down', signum)
        loop.quit()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info('Starting %s D-Bus service', args.bus_name)
    loop.run()
    logger.info('Service stopped')


def main():
    parser = ArgumentParser(description='NetworkManager VPN Plugin for Pulse SSO')
    parser.add_argument(
        '--bus-name',
        default=NM_DBUS_SERVICE,
        help='D-Bus service name'
    )
    parser.add_argument(
        '--helper-script',
        required=True,
        help='Path to openconnect helper script'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        run(args)
    except Exception:
        logger.exception('Service failed')
        sys.exit(1)


if __name__ == '__main__':
    main()

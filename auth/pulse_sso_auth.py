#!/usr/bin/env python3
"""
pulse-sso-auth: CEF-based browser authentication for Pulse VPN

Extracts DSID cookie via CEF (Chromium Embedded Framework) for use with openconnect.
CEF embeds Chromium directly without WebDriver protocol, avoiding bot detection
markers that Selenium exposes (like navigator.webdriver = true).

Usage:
    pulse-sso-auth --url https://vpn.example.com/emp [--format nm|json] [--timeout 300]

Output formats:
    nm:   NetworkManager auth-dialog format (key\nvalue\n pairs)
    json: JSON object with gateway, cookie, gwcert fields
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

from cefpython3 import cefpython as cef


def get_xdg_config_home():
    """Get XDG_CONFIG_HOME path."""
    return os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))


class CookieVisitor:
    """
    CEF cookie visitor callback.

    CEF uses an async visitor pattern for cookie access.
    This visitor is called for each cookie matching the URL.
    """

    def __init__(self, target_cookie: str, callback):
        self.target_cookie = target_cookie
        self.callback = callback
        self.found_value = None

    def Visit(self, cookie, count, total, delete_cookie_out):
        """Called for each cookie. Return True to continue, False to stop."""
        if cookie.GetName() == self.target_cookie:
            self.found_value = cookie.GetValue()
            self.callback(self.found_value)
            return False  # Stop visiting
        return True  # Continue visiting


def get_server_cert_fingerprint(hostname: str, port: int = 443) -> str:
    """Get SHA256 fingerprint of server certificate for certificate pinning."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                return "sha256:" + hashlib.sha256(cert_der).hexdigest()
    except Exception as e:
        print(f"Warning: Could not get server certificate: {e}", file=sys.stderr)
        return ""


def build_windows_user_agent() -> str:
    """
    Build Windows user agent string for Okta bypass.

    Okta blocks Linux user agents, so we spoof Windows.
    """
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/66.0.3359.181 Safari/537.36"
    )


class AuthHandler:
    """
    Handles authentication flow by polling for DSID cookie.
    """

    def __init__(self, vpn_url: str, timeout: int):
        self.vpn_url = vpn_url
        self.hostname = urlparse(vpn_url).hostname
        self.timeout = timeout
        self.result = None
        self.start_time = None
        self.browser = None

    def on_cookie_found(self, dsid_value: str):
        """Called when DSID cookie is detected."""
        if not self.result:
            print(f"DSID cookie found!", file=sys.stderr)
            self.result = {
                "gateway": self.hostname,
                "cookie": dsid_value,
                "gwcert": get_server_cert_fingerprint(self.hostname),
            }

    def check_cookies(self):
        """Check for DSID cookie."""
        if self.result:
            return

        try:
            cookie_manager = cef.CookieManager.GetGlobalManager()
            visitor = CookieVisitor("DSID", self.on_cookie_found)
            cookie_manager.VisitUrlCookies(self.vpn_url, True, visitor)
        except Exception as e:
            print(f"Cookie check error: {e}", file=sys.stderr)

    def check_timeout(self):
        """Check if authentication has timed out."""
        if self.start_time and (time.time() - self.start_time) > self.timeout:
            return True
        return False


def get_dsid_cookie(
    vpn_url: str,
    profile_dir: str,
    timeout: int = 300,
) -> dict:
    """
    Launch CEF browser, navigate to VPN URL, wait for DSID cookie after SAML auth.

    Args:
        vpn_url: Full URL to VPN endpoint (e.g., https://vpn.example.com/emp)
        profile_dir: Directory for browser profile persistence
        timeout: Maximum seconds to wait for authentication

    Returns:
        Dict with gateway, cookie, gwcert keys
    """
    # Ensure profile directory exists
    os.makedirs(profile_dir, exist_ok=True)

    # Set up exception hook
    sys.excepthook = cef.ExceptHook

    # Initialize CEF settings
    settings = {
        "cache_path": profile_dir,
        "persist_session_cookies": 1,
        "persist_user_preferences": 1,
        "user_agent": build_windows_user_agent(),
        "log_severity": cef.LOGSEVERITY_WARNING,
        "log_file": os.path.join(profile_dir, "cef.log"),
        # Performance settings
        "windowless_rendering_enabled": False,
        "multi_threaded_message_loop": False,
    }

    # Command line switches for better performance
    switches = {
        # Enable GPU acceleration
        "enable-gpu": "",
        "enable-gpu-rasterization": "",
        # Disable features that slow things down
        "disable-gpu-compositing": "",  # Can actually help on some systems
        "disable-smooth-scrolling": "",
    }
    # NOTE: WebAuthn/FIDO2 not supported in CEF 66 (Chromium 66, April 2018)
    # WebAuthn was finalized in 2019 and enabled by default in Chrome 67+

    # Initialize CEF
    cef.Initialize(settings, switches)

    # Create auth handler
    handler = AuthHandler(vpn_url, timeout)
    handler.start_time = time.time()

    # Create browser window
    handler.browser = cef.CreateBrowserSync(
        url=vpn_url,
        window_title="Pulse VPN Authentication",
    )

    # Main event loop - process messages rapidly for responsive UI
    last_cookie_check = 0
    while True:
        # Process CEF messages (do multiple iterations for responsiveness)
        for _ in range(10):
            cef.MessageLoopWork()

        # Check cookies every second
        now = time.time()
        if now - last_cookie_check >= 1.0:
            handler.check_cookies()
            last_cookie_check = now

        # Check if we got the result
        if handler.result:
            break

        # Check timeout
        if handler.check_timeout():
            cef.Shutdown()
            raise Exception(f"Authentication timed out after {timeout} seconds")

        # Minimal sleep - just yield to other processes
        time.sleep(0.001)

    # Close browser and shutdown CEF
    handler.browser.CloseBrowser(True)
    cef.Shutdown()

    return handler.result


def output_nm_format(result: dict) -> None:
    """Output in NetworkManager auth-dialog format (key\nvalue\n pairs)."""
    # NM expects these specific keys for openconnect
    print(f"gateway\n{result['gateway']}")
    print(f"cookie\n{result['cookie']}")
    if result.get("gwcert"):
        print(f"gwcert\n{result['gwcert']}")
    print()  # Empty line signals end of secrets


def output_json_format(result: dict) -> None:
    """Output as JSON object."""
    print(json.dumps(result, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pulse VPN SSO Authentication - retrieve DSID cookie via CEF browser"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="VPN URL (e.g., https://vpn.example.com/emp)",
    )
    parser.add_argument(
        "--format",
        choices=["nm", "json"],
        default="nm",
        help="Output format: nm (NetworkManager) or json",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Authentication timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--profile-dir",
        default=None,
        help="Browser profile directory (default: ~/.config/cef/pulsevpn)",
    )
    args = parser.parse_args()

    # Setup profile directory
    profile_dir = args.profile_dir
    if profile_dir is None:
        profile_dir = os.path.join(get_xdg_config_home(), "cef", "pulsevpn")

    try:
        result = get_dsid_cookie(
            vpn_url=args.url,
            profile_dir=profile_dir,
            timeout=args.timeout,
        )

        if args.format == "json":
            output_json_format(result)
        else:
            output_nm_format(result)

        return 0

    except KeyboardInterrupt:
        print("Authentication cancelled by user", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

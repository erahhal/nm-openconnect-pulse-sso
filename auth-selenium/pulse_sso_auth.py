#!/usr/bin/env python3
"""
pulse-sso-auth: Standalone browser-based authentication for Pulse VPN

Extracts DSID cookie via Selenium browser automation for use with openconnect.
Designed to be called by NetworkManager auth dialogs or CLI tools.

Usage:
    pulse-sso-auth --url https://vpn.example.com/emp [--format nm|json] [--timeout 300]

Output formats:
    nm:   NetworkManager auth-dialog format (key\\nvalue\\n pairs)
    json: JSON object with gateway, cookie, gwcert fields
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import sys
from urllib.parse import urlparse

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium_stealth import stealth
from xdg_base_dirs import xdg_config_home
import undetected_chromedriver as uc


def find_chromedriver() -> str | None:
    """Find chromedriver in PATH."""
    return shutil.which("chromedriver")


def find_chromium() -> str | None:
    """
    Find chromium/chrome binary in PATH.

    On NixOS, the browser isn't in standard locations like /usr/bin/chromium.
    The Nix wrapper adds it to PATH, so we find it there and explicitly tell
    Selenium where it is via binary_location.
    """
    for name in ["chromium", "chromium-browser", "google-chrome", "chrome"]:
        path = shutil.which(name)
        if path:
            return path
    return None


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


def cleanup_stale_chrome_locks(profile_dir: str) -> None:
    """
    Remove stale Chrome lock files that prevent new sessions.

    Chrome leaves these files when it crashes or is killed without cleanup.
    Without removal, new sessions fail with "Could not remove old devtools port file".
    """
    lock_files = [
        "DevToolsActivePort",
        "SingletonLock",
        "SingletonSocket",
        "SingletonCookie",
    ]

    for lock_file in lock_files:
        path = os.path.join(profile_dir, lock_file)
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"Removed stale lock file: {path}", file=sys.stderr)
        except OSError as e:
            print(f"Warning: Could not remove {path}: {e}", file=sys.stderr)


def get_dsid_cookie(
    vpn_url: str,
    chrome_profile_dir: str,
    chromedriver_path: str | None = None,
    timeout: int = 300,
) -> dict:
    """
    Launch browser, navigate to VPN URL, wait for DSID cookie after SAML auth.

    Args:
        vpn_url: Full URL to VPN endpoint (e.g., https://vpn.example.com/emp)
        chrome_profile_dir: Directory for Chrome profile persistence
        chromedriver_path: Optional path to chromedriver binary
        timeout: Maximum seconds to wait for authentication

    Returns:
        Dict with gateway, cookie, gwcert keys
    """
    hostname = urlparse(vpn_url).hostname

    # Clean up any stale lock files from previous crashed sessions
    cleanup_stale_chrome_locks(chrome_profile_dir)

    # Find chromedriver - either from explicit path or PATH
    driver_path = chromedriver_path or find_chromedriver()
    if driver_path:
        service = Service(executable_path=driver_path)
    else:
        service = None

    # Find Chrome binary from PATH (important for NixOS where it's not in standard locations)
    chrome_binary = find_chromium()
    if chrome_binary:
        print(f"Using Chrome binary: {chrome_binary}", file=sys.stderr)
    else:
        print("Warning: Could not find chromium in PATH, Selenium will try default locations", file=sys.stderr)

    # Get original user agent from temp browser
    temp_options = webdriver.ChromeOptions()
    if chrome_binary:
        temp_options.binary_location = chrome_binary
    if service:
        temp_driver = webdriver.Chrome(service=service, options=temp_options)
    else:
        temp_driver = webdriver.Chrome(options=temp_options)
    original_ua = temp_driver.execute_script("return navigator.userAgent")
    temp_driver.quit()
    print(f"Original user agent: {original_ua}", file=sys.stderr)

    # Transform to Windows user agent for Okta bypass
    windows_ua = re.sub(r'X11; Linux x86_64', 'Windows NT 10.0; Win64; x64', original_ua)
    print(f"Windows user agent: {windows_ua}", file=sys.stderr)

    # Setup Chrome options with bot detection evasion
    chrome_options = uc.ChromeOptions()
    if chrome_binary:
        chrome_options.binary_location = chrome_binary
    chrome_options.add_argument("--window-size=800,900")
    chrome_options.add_argument(f"user-agent={windows_ua}")
    chrome_options.add_argument(f"user-data-dir={chrome_profile_dir}")

    if service:
        driver = webdriver.Chrome(service=service, options=chrome_options)
    else:
        # Fall back to letting selenium find/download it (not recommended in Nix)
        driver = webdriver.Chrome(options=chrome_options)

    # Apply stealth.js to bypass Cloudflare/bot detection
    stealth(
        driver,
        languages=["en-US", "en"],
        vendor="Google Inc.",
        platform="Win32",
        webgl_vendor="Intel Inc.",
        renderer="Intel Iris OpenGL Engine",
        fix_hairline=True,
    )

    try:
        # Initial page load with Windows user agent (bypasses Okta)
        driver.get(vpn_url)

        # Switch back to Linux user agent after initial page load
        driver.execute_cdp_cmd('Network.setUserAgentOverride', {"userAgent": original_ua, "platform": "Linux"})
        driver.get(vpn_url)
        driver.back()

        # Wait for DSID cookie (set after successful SAML/SSO auth)
        dsid = WebDriverWait(driver, timeout).until(
            lambda d: d.get_cookie("DSID")
        )

        return {
            "gateway": hostname,
            "cookie": dsid['value'],  # Just the value, openconnect -C expects raw cookie value
            "gwcert": get_server_cert_fingerprint(hostname),
        }
    finally:
        driver.quit()


def output_nm_format(result: dict) -> None:
    """Output in NetworkManager auth-dialog format (key\\nvalue\\n pairs)."""
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
        description="Pulse VPN SSO Authentication - retrieve DSID cookie via browser"
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
        help="Chrome profile directory (default: ~/.config/chromedriver/pulsevpn)",
    )
    parser.add_argument(
        "--chromedriver-path",
        default=None,
        help="Path to chromedriver binary",
    )
    args = parser.parse_args()

    # Setup profile directory (same as openconnect-pulse-launcher for session sharing)
    profile_dir = args.profile_dir
    if profile_dir is None:
        profile_dir = os.path.join(xdg_config_home(), "chromedriver", "pulsevpn")
    os.makedirs(profile_dir, exist_ok=True)

    try:
        result = get_dsid_cookie(
            vpn_url=args.url,
            chrome_profile_dir=profile_dir,
            chromedriver_path=args.chromedriver_path,
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

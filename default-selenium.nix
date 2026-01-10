{
  lib,
  stdenv,
  makeWrapper,
  python3,
  chromedriver,
  chromium,
  openconnect,
  vpnc-scripts,
  gobject-introspection,
  wrapGAppsHook3,
  fetchurl,
  fetchPypi,
  util-linux,  # For runuser (direct auth-dialog launch)
  systemd,     # For loginctl (session detection)
}:

let
  # Build selenium-stealth from PyPI (not in nixpkgs)
  selenium-stealth = python3.pkgs.buildPythonPackage rec {
    pname = "selenium-stealth";
    version = "1.0.6";
    format = "wheel";

    src = fetchurl {
      url = "https://files.pythonhosted.org/packages/cb/ac/7877df8b819d54a4e317a093a0a9e0a38d21d884a7250aa713f2f0869442/selenium_stealth-1.0.6-py3-none-any.whl";
      hash = "sha256-ti2lRSqkqE8ppN+yGpaWr/IHiKfFcN0LgbwEqUCEi5c=";
    };

    propagatedBuildInputs = with python3.pkgs; [
      selenium
      setuptools
    ];

    doCheck = false;
  };

  # Build undetected-chromedriver from PyPI (same as openconnect-pulse-launcher)
  undetected-chromedriver = python3.pkgs.buildPythonPackage rec {
    pname = "undetected-chromedriver";
    version = "3.5.5";
    format = "setuptools";

    src = fetchPypi {
      inherit pname version;
      hash = "sha256-n5ReFDUAUker4X3jFrz9qFsoSkF3/V8lFnx4ztM7Zew=";
    };

    propagatedBuildInputs = with python3.pkgs; [
      selenium
      requests
      websockets
      setuptools
    ];

    doCheck = false;
  };

  # Python environment for auth-dialog (needs selenium for browser auth)
  pythonEnvAuth = python3.withPackages (ps: with ps; [
    selenium
    selenium-stealth
    undetected-chromedriver
    xdg-base-dirs
    setuptools  # Required for distutils compatibility in Python 3.12+
  ]);

  # Python environment for VPN service (needs dbus/gobject for D-Bus)
  pythonEnvService = python3.withPackages (ps: with ps; [
    dbus-python
    pygobject3
  ]);
in
stdenv.mkDerivation rec {
  pname = "nm-pulse-sso-selenium";
  version = "1.0.0";

  src = ./.;

  # Required for NetworkManager to recognize this as a VPN plugin
  passthru.networkManagerPlugin = "VPN/nm-pulse-sso-service.name";

  nativeBuildInputs = [
    makeWrapper
    wrapGAppsHook3
    gobject-introspection
  ];

  buildInputs = [
    pythonEnvService
  ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    # Install the D-Bus VPN service (runs as root, PASSIVE - just receives credentials)
    install -Dm755 vpn-service/nm-pulse-sso-service.py $out/libexec/nm-pulse-sso-service

    # Install the helper script (called by openconnect --script)
    install -Dm755 vpn-service/nm-pulse-sso-helper $out/libexec/nm-pulse-sso-helper

    # Install the auth-dialog (runs as user, does browser auth via Selenium)
    # Use explicit shebang to pythonEnvAuth since patchShebangs would use pythonEnvService
    install -Dm755 auth-dialog/pulse-sso-auth-dialog-selenium $out/libexec/pulse-sso-auth-dialog
    sed -i "1s|.*|#!${pythonEnvAuth}/bin/python3|" $out/libexec/pulse-sso-auth-dialog

    # Install auth module for auth-dialog to import (selenium version)
    mkdir -p $out/lib/python
    cp -r auth-selenium $out/lib/python/auth

    # Create .name file with paths substituted
    mkdir -p $out/lib/NetworkManager/VPN
    substitute dbus/nm-pulse-sso-service.name.in \
      $out/lib/NetworkManager/VPN/nm-pulse-sso-service.name \
      --subst-var-by SERVICE_BIN "$out/libexec/nm-pulse-sso-service" \
      --subst-var-by AUTH_DIALOG_BIN "$out/libexec/pulse-sso-auth-dialog"

    # Install D-Bus policy file
    install -Dm644 dbus/nm-pulse-sso-service.conf \
      $out/share/dbus-1/system.d/nm-pulse-sso-service.conf

    runHook postInstall
  '';

  postFixup = ''
    # Wrap the auth-dialog (runs as user, needs chromedriver/chromium for browser)
    wrapProgram $out/libexec/pulse-sso-auth-dialog \
      --prefix PATH : ${lib.makeBinPath [ chromedriver chromium ]} \
      --prefix PYTHONPATH : "$out/lib/python" \
      --set PYTHONPATH "${pythonEnvAuth}/${pythonEnvAuth.sitePackages}:$out/lib/python"

    # Wrap the VPN service (runs as root, needs openconnect + tools for direct auth)
    # Note: No chromedriver/chromium - auth-dialog handles browser
    # util-linux provides runuser, systemd provides loginctl (for session detection)
    wrapProgram $out/libexec/nm-pulse-sso-service \
      --prefix PATH : ${lib.makeBinPath [ openconnect util-linux systemd ]} \
      --set PYTHONPATH "${pythonEnvService}/${pythonEnvService.sitePackages}" \
      --add-flags "--helper-script $out/libexec/nm-pulse-sso-helper"

    # Wrap the helper script
    # Set VPNC_SCRIPT so it can call the real vpnc-script for network setup
    wrapProgram $out/libexec/nm-pulse-sso-helper \
      --set PYTHONPATH "${pythonEnvService}/${pythonEnvService.sitePackages}" \
      --set VPNC_SCRIPT "${vpnc-scripts}/bin/vpnc-script"
  '';

  meta = with lib; {
    description = "NetworkManager VPN plugin for Pulse with Selenium-based SSO authentication";
    longDescription = ''
      This plugin provides NetworkManager integration for Pulse Secure VPNs
      that require browser-based SAML/SSO authentication.

      Uses Selenium WebDriver with undetected-chromedriver for browser automation.

      Architecture:
      - auth-dialog: Runs as user, opens browser for SAML auth, outputs credentials
      - VPN service: Runs as root, receives credentials from NM, runs openconnect

      The root service is PASSIVE - it does not launch browsers or user processes.
      NetworkManager handles running the auth-dialog as the user.

      Note: This plugin does not appear in nm-connection-editor's "Add VPN"
      dialog. Create connections via nmcli or NixOS ensureProfiles.
    '';
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
    maintainers = [];
  };
}

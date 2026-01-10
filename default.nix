{
  lib,
  stdenv,
  makeWrapper,
  python3,
  openconnect,
  vpnc-scripts,
  gobject-introspection,
  wrapGAppsHook3,
  gtk3,
  glib,
  glib-networking,
  util-linux,
  systemd,
  cef-pulse-auth,
}:

let
  # Python environment for auth-dialog (basic - just stdlib)
  pythonEnvAuthDialog = python3.withPackages (ps: []);

  # Python environment for VPN service (needs dbus/gobject for D-Bus)
  pythonEnvService = python3.withPackages (ps: with ps; [
    dbus-python
    pygobject3
  ]);
in
stdenv.mkDerivation rec {
  pname = "nm-pulse-sso";
  version = "3.0.0";  # Modern CEF with WebAuthn support

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
    gtk3
    glib-networking
  ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    # Install the D-Bus VPN service (runs as root, PASSIVE - just receives credentials)
    install -Dm755 vpn-service/nm-pulse-sso-service.py $out/libexec/nm-pulse-sso-service

    # Install the helper script (called by openconnect --script)
    install -Dm755 vpn-service/nm-pulse-sso-helper $out/libexec/nm-pulse-sso-helper

    # Install the auth-dialog (simple Python script that calls CEF binary)
    install -Dm755 auth-dialog/pulse-sso-auth-dialog $out/libexec/pulse-sso-auth-dialog

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
    # Wrap the VPN service (runs as root, needs openconnect + tools for direct auth)
    wrapProgram $out/libexec/nm-pulse-sso-service \
      --prefix PATH : ${lib.makeBinPath [ openconnect util-linux systemd ]} \
      --set PYTHONPATH "${pythonEnvService}/${pythonEnvService.sitePackages}" \
      --add-flags "--helper-script $out/libexec/nm-pulse-sso-helper"

    # Wrap the helper script
    wrapProgram $out/libexec/nm-pulse-sso-helper \
      --set PYTHONPATH "${pythonEnvService}/${pythonEnvService.sitePackages}" \
      --set VPNC_SCRIPT "${vpnc-scripts}/bin/vpnc-script"

    # Wrap the auth-dialog with path to CEF binary
    wrapProgram $out/libexec/pulse-sso-auth-dialog \
      --set PYTHONHOME "${pythonEnvAuthDialog}" \
      --prefix PATH : "${pythonEnvAuthDialog}/bin" \
      --add-flags "--cef-binary ${cef-pulse-auth}/bin/pulse-browser-auth"
  '';

  meta = with lib; {
    description = "NetworkManager VPN plugin for Pulse with modern CEF-based SSO authentication";
    longDescription = ''
      This plugin provides NetworkManager integration for Pulse Secure VPNs
      that require browser-based SAML/SSO authentication.

      Uses CEF (Chromium Embedded Framework) version 142 for browser
      automation. This modern CEF version supports WebAuthn/FIDO2 for
      Yubikey and other hardware token authentication.

      Architecture:
      - auth-dialog: Runs as user, launches CEF browser for authentication
      - CEF binary: Native C++ application using modern Chromium
      - VPN service: Runs as root, receives credentials from NM, runs openconnect
    '';
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
    maintainers = [];
  };
}

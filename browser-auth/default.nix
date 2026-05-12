{
  lib,
  stdenv,
  makeWrapper,
  python3,
  openconnect,
  vpnc-scripts,
  gobject-introspection,
  wrapGAppsHook3,
  util-linux,
  systemd,
  iproute2,
  xdg-utils,
  # Local TLS cert+key for the MITM proxy (generated in module.nix from cfg.gateway)
  cert,
  key,
  proxyPort ? 8443,
}:

let
  pythonEnvAuth = python3.withPackages (_ps: []);

  pythonEnvService = python3.withPackages (ps: with ps; [
    dbus-python
    pygobject3
  ]);
in
stdenv.mkDerivation rec {
  pname = "nm-pulse-sso-browser-auth";
  version = "1.0.0";

  src = ./..;

  passthru.networkManagerPlugin = "VPN/nm-pulse-sso-service.name";

  nativeBuildInputs = [
    makeWrapper
    wrapGAppsHook3
    gobject-introspection
  ];

  buildInputs = [ pythonEnvService ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 vpn-service/nm-pulse-sso-service.py $out/libexec/nm-pulse-sso-service
    install -Dm755 vpn-service/nm-pulse-sso-helper     $out/libexec/nm-pulse-sso-helper
    install -Dm755 browser-auth/auth-dialog            $out/libexec/pulse-sso-auth-dialog

    # IMPORTANT: install proxy.py under $out/share/, NOT $out/libexec/.
    # wrapGAppsHook3 (kept for the dbus vpn-service's pygobject3 typelib path)
    # walks $out/libexec/ and wraps anything executable there — including
    # .py files — turning them into ELF wrappers. When python3 then tries to
    # interpret the resulting binary as source, it fails with
    # `SyntaxError: source code cannot contain null bytes`. Installing the
    # Python source outside libexec/ (and as mode 644) keeps it as plain text.
    install -Dm644 browser-auth/proxy.py               $out/share/nm-pulse-sso-browser-auth/proxy.py

    mkdir -p $out/lib/NetworkManager/VPN
    substitute dbus/nm-pulse-sso-service.name.in \
      $out/lib/NetworkManager/VPN/nm-pulse-sso-service.name \
      --subst-var-by SERVICE_BIN     "$out/libexec/nm-pulse-sso-service" \
      --subst-var-by AUTH_DIALOG_BIN "$out/libexec/pulse-sso-auth-dialog"

    install -Dm644 dbus/nm-pulse-sso-service.conf \
      $out/share/dbus-1/system.d/nm-pulse-sso-service.conf

    runHook postInstall
  '';

  postFixup = ''
    # Proxy: pure stdlib, no extra deps needed.
    # Points at the source file under $out/share/ (see installPhase note above).
    makeWrapper ${pythonEnvAuth}/bin/python3 $out/bin/pulse-browser-proxy \
      --add-flags "$out/share/nm-pulse-sso-browser-auth/proxy.py"

    # auth-dialog shells out to `xdg-open` to launch the user's default
    # browser; pin xdg-utils on PATH so we don't silently rely on the host
    # having it installed.
    wrapProgram $out/libexec/pulse-sso-auth-dialog \
      --set PYTHONHOME "${pythonEnvAuth}" \
      --prefix PATH : "${lib.makeBinPath [ pythonEnvAuth xdg-utils ]}" \
      --add-flags "--proxy-binary $out/bin/pulse-browser-proxy" \
      --add-flags "--cert ${cert}" \
      --add-flags "--key ${key}" \
      --add-flags "--proxy-port ${toString proxyPort}"

    wrapProgram $out/libexec/nm-pulse-sso-service \
      --prefix PATH : ${lib.makeBinPath [ openconnect util-linux systemd ]} \
      --set PYTHONPATH "${pythonEnvService}/${pythonEnvService.sitePackages}" \
      --add-flags "--helper-script $out/libexec/nm-pulse-sso-helper"

    wrapProgram $out/libexec/nm-pulse-sso-helper \
      --prefix PATH : ${lib.makeBinPath [ iproute2 ]} \
      --set PYTHONPATH "${pythonEnvService}/${pythonEnvService.sitePackages}" \
      --set VPNC_SCRIPT "${vpnc-scripts}/bin/vpnc-script"
  '';

  meta = with lib; {
    description = "NetworkManager VPN plugin for Pulse SSO (native browser + MITM proxy backend)";
    longDescription = ''
      Uses the user's default browser (xdg-open) for SAML authentication.
      A local HTTPS MITM proxy intercepts the DSID cookie from the server's
      Set-Cookie response header without requiring CEF or Selenium.

      Requires:
        - /etc/hosts redirect: <gateway-hostname> → 127.0.0.1
        - iptables NAT OUTPUT: 127.0.0.1:443 → 127.0.0.1:<proxyPort>
        - Local CA cert trusted by the system (security.pki.certificateFiles)
    '';
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
    maintainers = [];
  };
}

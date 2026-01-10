{
  lib,
  stdenv,
  cmake,
  cef-binary,
  makeWrapper,
  xorg,
  gtk3,
  glib,
  nss,
  nspr,
  atk,
  at-spi2-atk,
  at-spi2-core,
  libdrm,
  expat,
  libxkbcommon,
  mesa,
  libGL,
  alsa-lib,
  dbus,
  cups,
  pango,
  cairo,
  gdk-pixbuf,
  udev,
  fontconfig,
  freetype,
  libva,
  libvdpau,
  vulkan-loader,
  pcsclite,
  libfido2,
}:

stdenv.mkDerivation {
  pname = "pulse-browser-auth";
  version = "1.0.0";

  src = ./.;

  nativeBuildInputs = [
    cmake
    makeWrapper
  ];

  buildInputs = [
    cef-binary
    xorg.libX11
    xorg.libXcomposite
    xorg.libXdamage
    xorg.libXext
    xorg.libXfixes
    xorg.libXrandr
    xorg.libxcb
    xorg.libXtst
    xorg.libXScrnSaver
    xorg.libXcursor
    xorg.libXi
    xorg.libXrender
    gtk3
    glib
    nss
    nspr
    atk
    at-spi2-atk
    at-spi2-core
    libdrm
    expat
    libxkbcommon
    mesa
    libGL
    alsa-lib
    dbus
    cups
    pango
    cairo
    gdk-pixbuf
    udev
    fontconfig
    freetype
    libva
    libvdpau
    vulkan-loader
    pcsclite
    libfido2
  ];

  CEF_ROOT = cef-binary;

  cmakeFlags = [
    "-DCEF_ROOT=${cef-binary}"
  ];

  postInstall = ''
    # Rename binary
    mv $out/bin/cef-pulse-auth $out/bin/pulse-browser-auth
    # Create wrapper with proper library paths
    wrapProgram $out/bin/pulse-browser-auth \
      --prefix LD_LIBRARY_PATH : "$out/lib/cef" \
      --prefix LD_LIBRARY_PATH : "${lib.makeLibraryPath [
        xorg.libX11
        xorg.libXcomposite
        xorg.libXdamage
        xorg.libXext
        xorg.libXfixes
        xorg.libXrandr
        xorg.libxcb
        xorg.libXtst
        xorg.libXScrnSaver
        xorg.libXcursor
        xorg.libXi
        xorg.libXrender
        gtk3
        glib
        nss
        nspr
        atk
        at-spi2-atk
        at-spi2-core
        libdrm
        expat
        libxkbcommon
        mesa
        libGL
        alsa-lib
        dbus
        cups
        pango
        cairo
        gdk-pixbuf
        udev
        fontconfig
        freetype
        libva
        libvdpau
        vulkan-loader
        pcsclite
        libfido2
      ]}"
  '';

  meta = with lib; {
    description = "CEF-based authentication for Pulse VPN SSO";
    license = licenses.bsd3;
    platforms = platforms.linux;
  };
}

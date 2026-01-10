{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

# Bitwarden browser extension for CEF
# Extension ID: nngceckbapebfimnlniiiahkandclblb
stdenv.mkDerivation rec {
  pname = "bitwarden-chrome-extension";
  version = "2025.1.0";

  # Download from Chrome Web Store via CRX URL
  src = fetchurl {
    url = "https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx2,crx3&prodversion=120.0&x=id%3Dnngceckbapebfimnlniiiahkandclblb%26installsource%3Dondemand%26uc";
    name = "bitwarden-${version}.crx";
    sha256 = "sha256-KOmTzxU1wDL49t0hBAsjfNUEiXTkKLoYI+Ls1RTWMK0=";
  };

  nativeBuildInputs = [ unzip ];

  # CRX files are just ZIP files with a header
  unpackPhase = ''
    # Skip CRX header (first bytes) and extract as zip
    # CRX3 format: magic (4) + version (4) + header_size (4) + header
    # We use unzip which can handle the extra bytes
    unzip -q "$src" -d unpacked || true
  '';

  installPhase = ''
    mkdir -p $out
    cp -r unpacked/* $out/
  '';

  meta = with lib; {
    description = "Bitwarden password manager Chrome extension";
    homepage = "https://bitwarden.com";
    license = licenses.gpl3;
    platforms = platforms.all;
  };
}

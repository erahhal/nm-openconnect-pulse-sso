{
  description = "NetworkManager VPN plugin for Pulse with CEF-based SSO authentication";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Build the CEF authentication binary
        pulse-browser-auth = pkgs.callPackage ./cef-auth/default.nix { };
      in
      {
        packages = {
          inherit pulse-browser-auth;
          default = pkgs.callPackage ./default.nix { cef-pulse-auth = pulse-browser-auth; };
          nm-pulse-sso = pkgs.callPackage ./default.nix { cef-pulse-auth = pulse-browser-auth; };
          nm-pulse-sso-selenium = pkgs.callPackage ./default-selenium.nix { };
        };

        # Development shell for testing
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            (python312.withPackages (ps: with ps; [
              dbus-python
              pygobject3
            ]))
            openconnect
            dbus
            gtk3
            pulse-browser-auth
          ];
        };
      }
    ) // {
      # Overlay for easy integration into other flakes
      overlays.default = final: prev: {
        pulse-browser-auth = final.callPackage ./cef-auth/default.nix { };
        nm-pulse-sso = final.callPackage ./default.nix {
          cef-pulse-auth = final.pulse-browser-auth;
        };
        nm-pulse-sso-selenium = final.callPackage ./default-selenium.nix { };
      };

      # Plasma-nm overlay for KDE integration
      overlays.plasma-nm = import ./plasma-nm-overlay.nix {
        plasma-plugin-src = ./plasma-plugin;
      };

      # NixOS module for easy integration
      nixosModules.default = import ./module.nix;
    };
}

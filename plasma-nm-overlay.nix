# Overlay to patch plasma-nm with the pulse-sso VPN plugin
# This adds support for org.freedesktop.NetworkManager.pulse-sso to KDE Plasma's network applet

{ plasma-plugin-src ? ./plasma-plugin }:

final: prev: {
  kdePackages = prev.kdePackages.overrideScope (kfinal: kprev: {
    plasma-nm = kprev.plasma-nm.overrideAttrs (oldAttrs: {
      # Add our plugin source to the build
      postPatch = (oldAttrs.postPatch or "") + ''
        # Create directory for our plugin
        mkdir -p vpn/pulsesso

        # Copy our plugin source files
        cp ${plasma-plugin-src}/pulsessoui.json vpn/pulsesso/
        cp ${plasma-plugin-src}/pulsessoui.h vpn/pulsesso/
        cp ${plasma-plugin-src}/pulsessoui.cpp vpn/pulsesso/
        cp ${plasma-plugin-src}/pulsessowidget.h vpn/pulsesso/
        cp ${plasma-plugin-src}/pulsessowidget.cpp vpn/pulsesso/
        cp ${plasma-plugin-src}/pulsessowidget.ui vpn/pulsesso/
        cp ${plasma-plugin-src}/CMakeLists.txt vpn/pulsesso/

        # Add our plugin directory to the main vpn CMakeLists.txt
        echo 'add_subdirectory(pulsesso)' >> vpn/CMakeLists.txt
      '';
    });
  });
}

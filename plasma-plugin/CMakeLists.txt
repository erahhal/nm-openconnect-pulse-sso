# CMakeLists.txt for pulse-sso plasma-nm plugin
# This file is added to the plasma-nm build via overlay

# Translation domain for i18n
add_definitions(-DTRANSLATION_DOMAIN=\"plasmanetworkmanagement_pulsessoui\")

# Source files
set(pulsesso_SRCS
    pulsessoui.cpp
    pulsessowidget.cpp
)

# Wrap UI files
ki18n_wrap_ui(pulsesso_SRCS pulsessowidget.ui)

# Create the plugin library
add_library(plasmanetworkmanagement_pulsessoui MODULE ${pulsesso_SRCS})

# Link against required libraries
target_link_libraries(plasmanetworkmanagement_pulsessoui
    plasmanm_internal
    plasmanm_editor
    KF6::NetworkManagerQt
    KF6::I18n
    KF6::CoreAddons
    Qt6::Widgets
)

# Install to the VPN plugin directory
install(TARGETS plasmanetworkmanagement_pulsessoui DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/network/vpn)

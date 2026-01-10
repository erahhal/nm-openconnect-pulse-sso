/*
    SPDX-FileCopyrightText: 2024 Ellis Rahhal <github@rahh.al>
    SPDX-License-Identifier: GPL-2.0-or-later

    Plasma-nm VPN plugin for Pulse SSO authentication.
    This plugin allows KDE Plasma's network applet to handle
    org.freedesktop.NetworkManager.pulse-sso VPN connections.
*/

#ifndef PLASMA_NM_PULSE_SSO_UI_H
#define PLASMA_NM_PULSE_SSO_UI_H

#include "vpnuiplugin.h"

class Q_DECL_EXPORT PulseSsoUiPlugin : public VpnUiPlugin
{
    Q_OBJECT
public:
    explicit PulseSsoUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~PulseSsoUiPlugin() override;

    SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent = nullptr) override;
    SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent = nullptr) override;

    QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const override;
};

#endif // PLASMA_NM_PULSE_SSO_UI_H

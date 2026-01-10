/*
    SPDX-FileCopyrightText: 2024 Ellis Rahhal <github@rahh.al>
    SPDX-License-Identifier: GPL-2.0-or-later

    Settings widget for Pulse SSO VPN connections.
*/

#ifndef PLASMA_NM_PULSE_SSO_WIDGET_H
#define PLASMA_NM_PULSE_SSO_WIDGET_H

#include "settingwidget.h"

#include <NetworkManagerQt/VpnSetting>

namespace Ui
{
class PulseSsoWidget;
}

class PulseSsoSettingWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit PulseSsoSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent = nullptr);
    ~PulseSsoSettingWidget() override;

    void loadConfig(const NetworkManager::Setting::Ptr &setting) override;
    void loadSecrets(const NetworkManager::Setting::Ptr &setting) override;

    QVariantMap setting() const override;
    bool isValid() const override;

private:
    Ui::PulseSsoWidget *m_ui;
    NetworkManager::VpnSetting::Ptr m_setting;
};

#endif // PLASMA_NM_PULSE_SSO_WIDGET_H

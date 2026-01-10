/*
    SPDX-FileCopyrightText: 2024 Ellis Rahhal <github@rahh.al>
    SPDX-License-Identifier: GPL-2.0-or-later

    Settings widget implementation for Pulse SSO VPN connections.
*/

#include "pulsessowidget.h"
#include "ui_pulsessowidget.h"

#include <NetworkManagerQt/Setting>
#include <NetworkManagerQt/VpnSetting>

PulseSsoSettingWidget::PulseSsoSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
    : SettingWidget(setting, parent)
    , m_ui(new Ui::PulseSsoWidget)
    , m_setting(setting)
{
    m_ui->setupUi(this);

    // Load initial configuration
    if (setting && !setting->isNull()) {
        loadConfig(setting);
    }
}

PulseSsoSettingWidget::~PulseSsoSettingWidget()
{
    delete m_ui;
}

void PulseSsoSettingWidget::loadConfig(const NetworkManager::Setting::Ptr &setting)
{
    const NetworkManager::VpnSetting::Ptr vpnSetting = setting.staticCast<NetworkManager::VpnSetting>();
    if (!vpnSetting) {
        return;
    }

    const NMStringMap data = vpnSetting->data();
    const QString gateway = data.value(QStringLiteral("gateway"));

    m_ui->gatewayLabel->setText(gateway.isEmpty() ? QStringLiteral("(not configured)") : gateway);
}

void PulseSsoSettingWidget::loadSecrets(const NetworkManager::Setting::Ptr &setting)
{
    Q_UNUSED(setting);
    // Secrets are handled by the VPN service's auth-dialog via browser SAML
    // No secrets are stored in NetworkManager
}

QVariantMap PulseSsoSettingWidget::setting() const
{
    NetworkManager::VpnSetting setting;
    setting.setServiceType(QStringLiteral("org.freedesktop.NetworkManager.pulse-sso"));

    NMStringMap data;

    // Gateway is read from the UI (though typically set via NixOS config)
    const QString gateway = m_ui->gatewayLabel->text();
    if (!gateway.isEmpty() && gateway != QStringLiteral("(not configured)")) {
        data.insert(QStringLiteral("gateway"), gateway);
    }

    setting.setData(data);

    return setting.toMap();
}

bool PulseSsoSettingWidget::isValid() const
{
    // Connection is valid if we have a gateway configured
    const QString gateway = m_ui->gatewayLabel->text();
    return !gateway.isEmpty() && gateway != QStringLiteral("(not configured)");
}

/*
    SPDX-FileCopyrightText: 2024 Ellis Rahhal <github@rahh.al>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pulsessoui.h"
#include "pulsessowidget.h"

#include <KPluginFactory>

K_PLUGIN_CLASS_WITH_JSON(PulseSsoUiPlugin, "pulsessoui.json")

PulseSsoUiPlugin::PulseSsoUiPlugin(QObject *parent, const QVariantList &)
    : VpnUiPlugin(parent)
{
}

PulseSsoUiPlugin::~PulseSsoUiPlugin() = default;

SettingWidget *PulseSsoUiPlugin::widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
{
    return new PulseSsoSettingWidget(setting, parent);
}

SettingWidget *PulseSsoUiPlugin::askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent)
{
    Q_UNUSED(setting);
    Q_UNUSED(hints);
    Q_UNUSED(parent);
    // Return nullptr - authentication is handled by the VPN service directly
    // via browser popup, not through a KDE widget
    return nullptr;
}

QString PulseSsoUiPlugin::suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const
{
    Q_UNUSED(connection);
    // No export functionality - connections are created via NixOS configuration
    return QString();
}

#include "pulsessoui.moc"

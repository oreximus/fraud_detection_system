package com.fraudagent

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class FraudAgentApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NotificationManager::class.java)

            val alertChannel = NotificationChannel(
                CHANNEL_ALERTS,
                "Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority security alerts for detected threats"
                enableVibration(true)
            }

            val warningChannel = NotificationChannel(
                CHANNEL_WARNINGS,
                "Warnings",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Warnings for suspicious content"
            }

            val infoChannel = NotificationChannel(
                CHANNEL_INFO,
                "Information",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "General information and logs"
            }

            notificationManager.createNotificationChannels(
                listOf(alertChannel, warningChannel, infoChannel)
            )
        }
    }

    companion object {
        const val CHANNEL_ALERTS = "fraud_alerts"
        const val CHANNEL_WARNINGS = "fraud_warnings"
        const val CHANNEL_INFO = "fraud_info"
    }
}
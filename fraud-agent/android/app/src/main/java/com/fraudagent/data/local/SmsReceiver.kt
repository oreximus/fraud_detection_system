package com.fraudagent.data.local

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.app.NotificationManager
import android.app.NotificationChannel
import android.os.Build
import com.fraudagent.FraudAgentApplication
import com.fraudagent.domain.model.*
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SmsReceiver : BroadcastReceiver() {
    
    @Inject
    lateinit var detector: TFLiteDetector
    
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            return
        }
        
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val sb = StringBuilder()
        
        for (message in messages) {
            sb.append(message.messageBody)
        }
        
        val content = sb.toString()
        
        if (content.isBlank()) return
        
        CoroutineScope(Dispatchers.IO).launch {
            analyzeAndNotify(context, content)
        }
    }
    
    private fun analyzeAndNotify(context: Context, content: String) {
        val result = detector.analyze(content)
        
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        when (result.notificationLevel) {
            NotificationLevel.NONE -> {
                // Quiet log - no notification
            }
            NotificationLevel.SOFT -> {
                showNotification(
                    context,
                    notificationManager,
                    channelId = FraudAgentApplication.CHANNEL_WARNINGS,
                    title = "Suspicious Message",
                    message = result.explanation,
                    notificationId = result.hashCode()
                )
            }
            NotificationLevel.ALERT -> {
                showNotification(
                    context,
                    notificationManager,
                    channelId = FraudAgentApplication.CHANNEL_ALERTS,
                    title = "Potential Phishing Detected",
                    message = result.explanation,
                    notificationId = result.hashCode()
                )
            }
            NotificationLevel.FULL -> {
                showNotification(
                    context,
                    notificationManager,
                    channelId = FraudAgentApplication.CHANNEL_ALERTS,
                    title = "BLOCKED: Threat Detected",
                    message = result.explanation,
                    notificationId = result.hashCode()
                )
            }
        }
    }
    
    private fun showNotification(
        context: Context,
        notificationManager: NotificationManager,
        channelId: String,
        title: String,
        message: String,
        notificationId: Int
    ) {
        val notification = Notification.Builder(context, channelId)
            .setContentTitle(title)
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setAutoCancel(true)
            .build()
        
        notificationManager.notify(notificationId, notification)
    }
}

@AndroidEntryPoint
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // Could schedule periodic scanning here
        }
    }
}

@AndroidEntryPoint
class SmsAnalysisService : android.app.Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_NOT_STICKY
    }
    
    override fun onBind(intent: Intent?): android.os.IBinder? = null
}
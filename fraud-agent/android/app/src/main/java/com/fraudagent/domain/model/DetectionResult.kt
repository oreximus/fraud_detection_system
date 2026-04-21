package com.fraudagent.domain.model

data class ThreatScore(
    val score: Double,
    val level: ThreatLevel,
    val confidence: Double
)

enum class ThreatLevel {
    SAFE,
    SUSPICIOUS,
    PHISHING,
    SCAM
}

enum class ActionType {
    ALLOW,
    WARN,
    QUARANTINE,
    BLOCK
}

enum class NotificationLevel {
    NONE,
    SOFT,
    ALERT,
    FULL
}

enum class MessageSource {
    SMS,
    EMAIL,
    BROWSER
}

data class Indicator(
    val type: IndicatorType,
    val value: String,
    val description: String
)

enum class IndicatorType {
    URL,
    PHONE,
    EMAIL,
    KEYWORD,
    PATTERN
}

data class DetectionResult(
    val id: String,
    val timestamp: Long,
    val source: MessageSource,
    val content: String,
    val threatScore: ThreatScore,
    val action: ActionType,
    val notificationLevel: NotificationLevel,
    val explanation: String,
    val detectedIndicators: List<Indicator>
)

data class CommunityReport(
    val id: String,
    val hash: String,
    val threatScore: Float,
    val timestamp: Long,
    val source: MessageSource,
    val indicatorType: IndicatorType
)

object ThreatThresholds {
    const val ALLOW_MAX = 0.30
    const val WARN_MAX = 0.60
    const val QUARANTINE_MAX = 0.85
    const val BLOCK_MAX = 1.00

    fun scoreToAction(score: Double): ActionType = when {
        score <= ALLOW_MAX -> ActionType.ALLOW
        score <= WARN_MAX -> ActionType.WARN
        score <= QUARANTINE_MAX -> ActionType.QUARANTINE
        else -> ActionType.BLOCK
    }

    fun scoreToNotificationLevel(score: Double): NotificationLevel = when {
        score <= ALLOW_MAX -> NotificationLevel.NONE
        score <= WARN_MAX -> NotificationLevel.SOFT
        score <= QUARANTINE_MAX -> NotificationLevel.ALERT
        else -> NotificationLevel.FULL
    }

    fun scoreToThreatLevel(score: Double): ThreatLevel = when {
        score <= ALLOW_MAX -> ThreatLevel.SAFE
        score <= WARN_MAX -> ThreatLevel.SUSPICIOUS
        score <= QUARANTINE_MAX -> ThreatLevel.PHISHING
        else -> ThreatLevel.SCAM
    }
}
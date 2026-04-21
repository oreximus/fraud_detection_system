package com.fraudagent.data.local

import androidx.room.*
import com.fraudagent.domain.model.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "detections")
data class DetectionEntity(
    @PrimaryKey val id: String,
    val timestamp: Long,
    val source: String,
    val content: String,
    val contentHash: String,
    val threatScore: Double,
    val threatLevel: String,
    val confidence: Double,
    val action: String,
    val notificationLevel: String,
    val explanation: String,
    val indicatorsJson: String
)

fun DetectionEntity.toDomain(): DetectionResult {
    return DetectionResult(
        id = id,
        timestamp = timestamp,
        source = MessageSource.valueOf(source),
        content = content,
        threatScore = ThreatScore(
            score = threatScore,
            level = ThreatLevel.valueOf(threatLevel),
            confidence = confidence
        ),
        action = ActionType.valueOf(action),
        notificationLevel = NotificationLevel.valueOf(notificationLevel),
        explanation = explanation,
        detectedIndicators = parseIndicators(indicatorsJson)
    )
}

fun DetectionResult.toEntity(): DetectionEntity {
    return DetectionEntity(
        id = id,
        timestamp = timestamp,
        source = source.value,
        content = content,
        contentHash = content.hashCode().toString(),
        threatScore = threatScore.score,
        threatLevel = threatScore.level.value,
        confidence = threatScore.confidence,
        action = action.value,
        notificationLevel = notificationLevel.value,
        explanation = explanation,
        indicatorsJson = serializeIndicators(detectedIndicators)
    )
}

private fun parseIndicators(json: String): List<Indicator> {
    if (json.isEmpty()) return emptyList()
    return try {
        val gson = com.google.gson.Gson()
        val array = gson.fromJson(json, Array<Indicator>::class.java)
        array?.toList() ?: emptyList()
    } catch (e: Exception) {
        emptyList()
    }
}

private fun serializeIndicators(indicators: List<Indicator>): String {
    if (indicators.isEmpty()) return ""
    val gson = com.google.gson.Gson()
    return gson.toJson(indicators.toTypedArray())
}

@Entity(tableName = "reports")
data class ReportEntity(
    @PrimaryKey val id: String,
    val hash: String,
    val threatScore: Float,
    val timestamp: Long,
    val source: String,
    val indicatorType: String,
    val reportCount: Int = 1
)

fun ReportEntity.toDomain(): CommunityReport {
    return CommunityReport(
        id = id,
        hash = hash,
        threatScore = threatScore,
        timestamp = timestamp,
        source = MessageSource.valueOf(source),
        indicatorType = IndicatorType.valueOf(indicatorType)
    )
}

fun CommunityReport.toEntity(): ReportEntity {
    return ReportEntity(
        id = id,
        hash = hash,
        threatScore = threatScore,
        timestamp = timestamp,
        source = source.value,
        indicatorType = indicatorType.value,
        reportCount = 1
    )
}

@Dao
interface DetectionDao {
    @Query("SELECT * FROM detections ORDER BY timestamp DESC")
    fun getAllDetections(): Flow<List<DetectionEntity>>

    @Query("SELECT * FROM detections WHERE id = :id")
    suspend fun getDetection(id: String): DetectionEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDetection(detection: DetectionEntity)

    @Query("DELETE FROM detections WHERE id = :id")
    suspend fun deleteDetection(id: String)

    @Query("SELECT COUNT(*) FROM detections")
    suspend fun getTotalCount(): Int

    @Query("SELECT COUNT(*) FROM detections WHERE action = :action")
    suspend fun getCountByAction(action: String): Int
}

@Dao
interface ReportDao {
    @Query("SELECT * FROM reports ORDER BY timestamp DESC")
    suspend fun getAllReports(): List<ReportEntity>

    @Query("SELECT * FROM reports WHERE threatScore >= :minScore ORDER BY threatScore DESC")
    suspend fun getThreatFeed(minScore: Float): List<ReportEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReport(report: ReportEntity)

    @Query("SELECT * FROM reports WHERE hash = :hash LIMIT 1")
    suspend fun getReportByHash(hash: String): ReportEntity?

    @Query("UPDATE reports SET reportCount = reportCount + 1 WHERE hash = :hash")
    suspend fun incrementReportCount(hash: String)
}
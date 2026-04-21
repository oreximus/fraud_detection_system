package com.fraudagent.domain.repository

import com.fraudagent.domain.model.CommunityReport
import com.fraudagent.domain.model.DetectionResult
import kotlinx.coroutines.flow.Flow

interface DetectionRepository {
    suspend fun analyzeContent(
        content: String,
        source: String,
        metadata: Map<String, String>?
    ): DetectionResult

    fun getDetectionHistory(): Flow<List<DetectionResult>>

    suspend fun getDetection(id: String): DetectionResult?

    suspend fun saveDetection(detection: DetectionResult)

    suspend fun deleteDetection(id: String)
}

interface ReportRepository {
    suspend fun createReport(
        indicatorHash: String,
        threatScore: Float,
        indicatorType: String,
        source: String
    ): CommunityReport

    suspend fun getReports(): List<CommunityReport>

    suspend fun getThreatFeed(minScore: Float = 0.5f): List<CommunityReport>
}
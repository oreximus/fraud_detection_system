package com.fraudagent.data.repository

import com.fraudagent.data.local.*
import com.fraudagent.domain.model.*
import com.fraudagent.domain.repository.DetectionRepository
import com.fraudagent.domain.repository.ReportRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

class DetectionRepositoryImpl @Inject constructor(
    private val database: FraudAgentDatabase,
    private val detector: TFLiteDetector
) : DetectionRepository {
    
    private val dao = database.detectionDao()
    
    override suspend fun analyzeContent(
        content: String,
        source: String,
        metadata: Map<String, String>?
    ): DetectionResult {
        val result = detector.analyze(content)
        saveDetection(result)
        return result
    }
    
    override fun getDetectionHistory(): Flow<List<DetectionResult>> {
        return dao.getAllDetections().map { entities ->
            entities.map { it.toDomain() }
        }
    }
    
    override suspend fun getDetection(id: String): DetectionResult? {
        return dao.getDetection(id)?.toDomain()
    }
    
    override suspend fun saveDetection(detection: DetectionResult) {
        dao.insertDetection(detection.toEntity())
    }
    
    override suspend fun deleteDetection(id: String) {
        dao.deleteDetection(id)
    }
}

class ReportRepositoryImpl @Inject constructor(
    private val database: FraudAgentDatabase
) : ReportRepository {
    
    private val dao = database.reportDao()
    
    override suspend fun createReport(
        indicatorHash: String,
        threatScore: Float,
        indicatorType: String,
        source: String
    ): CommunityReport {
        val existing = dao.getReportByHash(indicatorHash)
        
        if (existing != null) {
            dao.incrementReportCount(indicatorHash)
            return existing.toDomain()
        }
        
        val report = ReportEntity(
            id = "rpt_${System.currentTimeMillis()}",
            hash = indicatorHash,
            threatScore = threatScore,
            timestamp = System.currentTimeMillis(),
            source = source,
            indicatorType = indicatorType,
            reportCount = 1
        )
        
        dao.insertReport(report)
        
        return report.toDomain()
    }
    
    override suspend fun getReports(): List<CommunityReport> {
        return dao.getAllReports().map { it.toDomain() }
    }
    
    override suspend fun getThreatFeed(minScore: Float): List<CommunityReport> {
        return dao.getThreatFeed(minScore).map { it.toDomain() }
    }
}
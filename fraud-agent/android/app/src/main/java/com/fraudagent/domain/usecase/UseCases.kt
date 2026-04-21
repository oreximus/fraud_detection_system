package com.fraudagent.domain.usecase

import com.fraudagent.domain.model.*
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class AnalyzeContentUseCase @Inject constructor(
    private val detectionRepository: com.fraudagent.domain.repository.DetectionRepository
) {
    suspend operator fun invoke(
        content: String,
        source: String,
        metadata: Map<String, String>? = null
    ): DetectionResult {
        return detectionRepository.analyzeContent(content, source, metadata)
    }
}

class GetDetectionHistoryUseCase @Inject constructor(
    private val detectionRepository: com.fraudagent.domain.repository.DetectionRepository
) {
    operator fun invoke(): Flow<List<DetectionResult>> {
        return detectionRepository.getDetectionHistory()
    }
}

class CreateReportUseCase @Inject constructor(
    private val reportRepository: com.fraudagent.domain.repository.ReportRepository
) {
    suspend operator fun invoke(
        indicatorHash: String,
        threatScore: Float,
        indicatorType: String,
        source: String
    ): CommunityReport {
        return reportRepository.createReport(
            indicatorHash,
            threatScore,
            indicatorType,
            source
        )
    }
}

class GetThreatFeedUseCase @Inject constructor(
    private val reportRepository: com.fraudagent.domain.repository.ReportRepository
) {
    suspend operator fun invoke(minScore: Float = 0.5f): List<CommunityReport> {
        return reportRepository.getThreatFeed(minScore)
    }
}
package com.fraudagent.presentation.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.fraudagent.domain.model.*
import com.fraudagent.domain.usecase.*
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DetectionUiState(
    val isLoading: Boolean = false,
    val currentResult: DetectionResult? = null,
    val history: List<DetectionResult> = emptyList(),
    val stats: Stats = Stats(),
    val error: String? = null
)

data class Stats(
    val totalDetections: Int = 0,
    val blocked: Int = 0,
    val quarantined: Int = 0,
    val warned: Int = 0,
    val allowed: Int = 0
)

@HiltViewModel
class DetectionViewModel @Inject constructor(
    private val analyzeContentUseCase: AnalyzeContentUseCase,
    private val getDetectionHistoryUseCase: GetDetectionHistoryUseCase
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(DetectionUiState())
    val uiState: StateFlow<DetectionUiState> = _uiState.asStateFlow()
    
    init {
        loadHistory()
    }
    
    fun analyzeContent(content: String, source: String = "SMS") {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }
            
            try {
                val result = analyzeContentUseCase(content, source)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        currentResult = result
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        error = e.message ?: "Analysis failed"
                    )
                }
            }
        }
    }
    
    private fun loadHistory() {
        viewModelScope.launch {
            getDetectionHistoryUseCase().collect { detections ->
                val stats = calculateStats(detections)
                _uiState.update {
                    it.copy(
                        history = detections.take(100),
                        stats = stats
                    )
                }
            }
        }
    }
    
    private fun calculateStats(detections: List<DetectionResult>): Stats {
        return Stats(
            totalDetections = detections.size,
            blocked = detections.count { it.action == ActionType.BLOCK },
            quarantined = detections.count { it.action == ActionType.QUARANTINE },
            warned = detections.count { it.action == ActionType.WARN },
            allowed = detections.count { it.action == ActionType.ALLOW }
        )
    }
    
    fun clearCurrentResult() {
        _uiState.update { it.copy(currentResult = null) }
    }
    
    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }
}
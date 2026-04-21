package com.fraudagent.presentation.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.fraudagent.domain.model.*
import com.fraudagent.presentation.ui.theme.FraudAgentColors
import com.fraudagent.presentation.viewmodel.DetectionViewModel
import com.fraudagent.presentation.ui.theme.theme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: DetectionViewModel = hiltViewModel()
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var testContent by remember { mutableStateOf("") }
    
    val uiState by viewModel.uiState.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Fraud Agent") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    icon = { Icon(Icons.Default.Security, contentDescription = null) },
                    label = { Text("Analyze") },
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Default.History, contentDescription = null) },
                    label = { Text("History") },
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Default.Insights, contentDescription = null) },
                    label = { Text("Stats") },
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 }
                )
            }
        }
    ) { paddingValues ->
        when (selectedTab) {
            0 -> AnalyzeTab(
                content = testContent,
                onContentChange = { testContent = it },
                onAnalyze = { viewModel.analyzeContent(testContent) },
                currentResult = uiState.currentResult,
                isLoading = uiState.isLoading,
                modifier = Modifier.padding(paddingValues)
            )
            1 -> HistoryTab(
                detections = uiState.history,
                modifier = Modifier.padding(paddingValues)
            )
            2 -> StatsTab(
                stats = uiState.stats,
                modifier = Modifier.padding(paddingValues)
            )
        }
    }
}

@Composable
private fun AnalyzeTab(
    content: String,
    onContentChange: (String) -> Unit,
    onAnalyze: () -> Unit,
    currentResult: DetectionResult?,
    isLoading: Boolean,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        OutlinedTextField(
            value = content,
            onValueChange = onContentChange,
            label = { Text("Message Content") },
            placeholder = { Text("Enter SMS or email content to analyze") },
            modifier = Modifier
                .fillMaxWidth()
                .height(150.dp),
            maxLines = 6
        )
        
        Button(
            onClick = onAnalyze,
            modifier = Modifier.fillMaxWidth(),
            enabled = content.isNotBlank() && !isLoading
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Analyze Content")
            }
        }
        
        currentResult?.let { result ->
            ResultCard(result = result)
        }
    }
}

@Composable
private fun ResultCard(result: DetectionResult) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (result.action) {
                ActionType.BLOCK -> FraudAgentColors.Danger.copy(alpha = 0.1f)
                ActionType.QUARANTINE -> FraudAgentColors.Suspicious.copy(alpha = 0.1f)
                ActionType.WARN -> FraudAgentColors.Warning.copy(alpha = 0.1f)
                ActionType.ALLOW -> FraudAgentColors.Safe.copy(alpha = 0.1f)
            }
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = result.threatScore.level.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Text(
                    text = "Score: ${(result.threatScore.score * 100).toInt()}%",
                    style = MaterialTheme.typography.titleMedium,
                    color = when (result.action) {
                        ActionType.BLOCK -> FraudAgentColors.Danger
                        ActionType.QUARANTINE -> FraudAgentColors.Suspicious
                        ActionType.WARN -> FraudAgentColors.Warning
                        ActionType.ALLOW -> FraudAgentColors.Safe
                    }
                )
            }
            
            Text(
                text = "Action: ${result.action.name}",
                style = MaterialTheme.typography.bodyMedium
            )
            
            HorizontalDivider()
            
            Text(
                text = result.explanation,
                style = MaterialTheme.typography.bodyMedium
            )
            
            if (result.detectedIndicators.isNotEmpty()) {
                HorizontalDivider()
                
                Text(
                    text = "Detected Indicators:",
                    style = MaterialTheme.typography.labelMedium
                )
                
                result.detectedIndicators.take(5).forEach { indicator ->
                    Text(
                        text = "• ${indicator.type.name}: ${indicator.value}",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}

@Composable
private fun HistoryTab(
    detections: List<DetectionResult>,
    modifier: Modifier = Modifier
) {
    if (detections.isEmpty()) {
        Box(
            modifier = modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text("No detection history yet")
        }
    } else {
        LazyColumn(
            modifier = modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(detections) { detection ->
                DetectionHistoryItem(detection = detection)
            }
        }
    }
}

@Composable
private fun DetectionHistoryItem(detection: DetectionResult) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = detection.source.name,
                    style = MaterialTheme.typography.labelSmall
                )
                Text(
                    text = detection.content.take(50) + "...",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1
                )
            }
            
            Box(
                modifier = Modifier.padding(start = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "${(detection.threatScore.score * 100).toInt()}%",
                    color = when (detection.action) {
                        ActionType.BLOCK -> FraudAgentColors.Danger
                        ActionType.QUARANTINE -> FraudAgentColors.Suspicious
                        ActionType.WARN -> FraudAgentColors.Warning
                        ActionType.ALLOW -> FraudAgentColors.Safe
                    }
                )
            }
        }
    }
}

@Composable
private fun StatsTab(
    stats: com.fraudagent.presentation.viewmodel.Stats,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Detection Statistics",
            style = MaterialTheme.typography.headlineSmall
        )
        
        StatCard(label = "Total Detections", value = stats.totalDetections.toString())
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StatCard(
                label = "Blocked",
                value = stats.blocked.toString(),
                color = FraudAgentColors.Danger,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                label = "Quarantined",
                value = stats.quarantined.toString(),
                color = FraudAgentColors.Suspicious,
                modifier = Modifier.weight(1f)
            )
        }
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StatCard(
                label = "Warned",
                value = stats.warned.toString(),
                color = FraudAgentColors.Warning,
                modifier = Modifier.weight(1f)
            )
            StatCard(
                label = "Allowed",
                value = stats.allowed.toString(),
                color = FraudAgentColors.Safe,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun StatCard(
    label: String,
    value: String,
    color: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.primary,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = color.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.headlineMedium,
                color = color
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium
            )
        }
    }
}
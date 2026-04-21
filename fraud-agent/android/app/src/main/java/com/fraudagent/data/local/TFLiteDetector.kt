package com.fraudagent.data.local

import android.content.Context
import com.fraudagent.domain.model.*
import dagger.hilt.android.qualifiers.ApplicationContext
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.support.common.FileUtil
import java.io.File
import java.nio.MappedByteBuffer
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class TFLiteDetector @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private var interpreter: Interpreter? = null
    private val tokenizer = SimpleTokenizer()

    init {
        loadModel()
    }

    private fun loadModel() {
        try {
            val modelFile = File(context.filesDir, MODEL_NAME)
            if (modelFile.exists()) {
                interpreter = Interpreter(modelFile.readBytes().toTypedArray())
            } else {
                val assetBuffer = context.assets.open(MODEL_NAME)
                interpreter = Interpreter(assetBuffer.readBytes().toTypedArray())
            }
        } catch (e: Exception) {
            e.printStackTrace()
            interpreter = null
        }
    }

    fun analyze(content: String): DetectionResult {
        val startTime = System.currentTimeMillis()

        val (inputIds, attentionMask) = tokenizer.encode(content)

        val input = arrayOf(inputIds to attentionMask)
        val output = Array(1) { FloatArray(2) }

        if (interpreter != null) {
            interpreter?.run(input, output)
        }

        val probabilities = softmax(output[0])
        val predictedClass = probabilities.indices.maxByOrNull { probabilities[it] } ?: 0
        val confidence = probabilities.getOrNull(predictedClass) ?: 0.0
        val score = probabilities.getOrNull(1) ?: 0.5

        val quickResult = quickScan(content)
        val deepResult = deepScan(content, quickResult.indicators)

        val finalScore = combineScores(
            quickScore = quickResult.score,
            mlScore = score,
            deepScore = deepResult.score
        )

        val threatLevel = ThreatThresholds.scoreToThreatLevel(finalScore)
        val action = ThreatThresholds.scoreToAction(finalScore)
        val notificationLevel = ThreatThresholds.scoreToNotificationLevel(finalScore)

        val allIndicators = quickResult.indicators + deepResult.indicators
        val explanation = generateExplanation(finalScore, threatLevel, allIndicators)

        val inferenceTime = System.currentTimeMillis() - startTime

        return DetectionResult(
            id = generateId(),
            timestamp = System.currentTimeMillis(),
            source = MessageSource.SMS,
            content = content,
            threatScore = ThreatScore(
                score = finalScore,
                level = threatLevel,
                confidence = confidence
            ),
            action = action,
            notificationLevel = notificationLevel,
            explanation = explanation,
            detectedIndicators = allIndicators
        )
    }

    private fun quickScan(content: String): QuickScanResult {
        val indicators = mutableListOf<Indicator>()
        var score = 0.0

        val urlPattern = Regex("https?://[\\w.-]+\\.[\\w.-]+")
        urlPattern.findAll(content).forEach { match ->
            if (isSuspiciousUrl(match.value)) {
                indicators.add(Indicator(IndicatorType.URL, match.value, "Suspicious URL"))
                score += 0.3
            }
        }

        val phonePattern = Regex("\\+?[\\d]{10,}")
        phonePattern.findAll(content).forEach { match ->
            indicators.add(Indicator(IndicatorType.PHONE, match.value, "Phone number"))
            score += 0.25
        }

        val scamKeywords = setOf(
            "urgent", "immediate", "verify", "confirm", "account suspended",
            "password", "login", "security alert", "click here",
            "gift card", "bitcoin", "wire transfer"
        )

        val contentLower = content.lowercase()
        for (keyword in scamKeywords) {
            if (keyword in contentLower) {
                indicators.add(Indicator(IndicatorType.KEYWORD, keyword, "Scam keyword"))
                score += 0.15
            }
        }

        return QuickScanResult(
            indicators = indicators,
            score = minOf(score, 1.0)
        )
    }

    private fun deepScan(content: String, quickIndicators: List<Indicator>): DeepScanResult {
        val indicators = mutableListOf<Indicator>()
        var score = 0.0

        val contentLower = content.lowercase()

        val brands = listOf("amazon", "apple", "microsoft", "paypal", "bank")
        if (brands.any { it in contentLower }) {
            val actionWords = listOf("verify", "confirm", "update", "account")
            if (actionWords.any { it in contentLower }) {
                indicators.add(Indicator(IndicatorType.PATTERN, "brand_impersonation", "Brand impersonation detected"))
                score += 0.4
            }
        }

        val urgencyWords = listOf("urgent", "immediately", "within 24 hours", "act now")
        if (urgencyWords.any { it in contentLower }) {
            indicators.add(Indicator(IndicatorType.PATTERN, "urgency_tactic", "Urgency tactic detected"))
            score += 0.3
        }

        val rewardWords = listOf("won", "prize", "lottery", "inheritance", "winner")
        if (rewardWords.any { it in contentLower }) {
            indicators.add(Indicator(IndicatorType.PATTERN, "reward_scam", "Reward scam pattern"))
            score += 0.35
        }

        return DeepScanResult(
            indicators = indicators,
            score = minOf(score, 1.0)
        )
    }

    private fun combineScores(quickScore: Double, mlScore: Double, deepScore: Double): Double {
        return (0.2 * quickScore) + (0.6 * mlScore) + (0.2 * deepScore)
    }

    private fun generateExplanation(
        score: Double,
        threatLevel: ThreatLevel,
        indicators: List<Indicator>
    ): String {
        if (threatLevel == ThreatLevel.SAFE) {
            return "This content appears to be safe. No suspicious indicators detected."
        }

        val indicatorDescription = if (indicators.isNotEmpty()) {
            "Detected: ${indicators.take(3).joinToString(", ") { it.value }}"
        } else ""

        val recommendation = when {
            score > 0.85 -> "Highly likely phishing. Do not interact."
            score > 0.60 -> "Suspicious content. Verify through official channels."
            else -> "Proceed with caution."
        }

        return "$indicatorDescription $recommendation".trim()
    }

    private fun isSuspiciousUrl(url: String): Boolean {
        val suspiciousTlds = setOf(".xyz", ".top", ".club", ".win", ".online", ".icu")
        return suspiciousTlds.any { url.lowercase().contains(it) }
    }

    private fun softmax(x: FloatArray): FloatArray {
        val max = x.maxOrNull() ?: 0f
        val exp = x.map { kotlin.math.exp(it - max) }
        val sum = exp.sum()
        return exp.map { it / sum }.toFloatArray()
    }

    private fun generateId(): String = "det_${System.currentTimeMillis()}_${(0..999999).random()}"

    private data class QuickScanResult(
        val indicators: List<Indicator>,
        val score: Double
    )

    private data class DeepScanResult(
        val indicators: List<Indicator>,
        val score: Double
    )

    companion object {
        private const val MODEL_NAME = "phishing_detector.tflite"
    }
}

class SimpleTokenizer {
    private val vocab = buildVocab()
    private val maxLength = 256

    fun encode(text: String): Pair<IntArray, IntArray> {
        val tokens = text.lowercase().split(" ").take(maxLength - 2)

        val inputIds = mutableListOf(vocab["[CLS]"] ?: 2)
        for (token in tokens) {
            inputIds.add(vocab[token] ?: 1)
        }
        inputIds.add(vocab["[SEP]"] ?: 3)

        while (inputIds.size < maxLength) {
            inputIds.add(vocab["[PAD]"] ?: 0)
        }

        val attentionMask = IntArray(maxLength) { if (inputIds[it] != 0) 1 else 0 }

        return IntArray(maxLength) { inputIds[it] } to attentionMask
    }

    private fun buildVocab(): Map<String, Int> {
        val commonWords = listOf(
            "[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]",
            "the", "a", "an", "is", "are", "was", "be", "to", "of", "and",
            "in", "that", "have", "i", "it", "for", "not", "on", "with", "he",
            "as", "you", "do", "at", "this", "but", "his", "by", "from",
            "they", "we", "say", "her", "she", "or", "an", "will", "my", "one",
            "all", "would", "there", "their", "what", "so", "up", "out", "if",
            "about", "who", "get", "which", "go", "me", "account", "verify",
            "password", "login", "bank", "urgent", "secure", "click", "update"
        )

        return commonWords.mapIndexed { index, word -> word to index }.toMap()
    }
}
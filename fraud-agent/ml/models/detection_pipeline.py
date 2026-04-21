"""Detection pipeline following the exact order: CAPTURE → QUICK_SCAN → ML_CLASSIFY → DEEP_SCAN → ACTION → EXPLAIN → REPORT."""
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import numpy as np

from fraud_agent_shared.types import (
    ActionType,
    CommunityReport,
    Indicator,
    IndicatorType,
    MessageSource,
    NotificationLevel,
    ThreatLevel,
    ThreatScore,
    DetectionResult,
    DetectionPipelineConfig,
    DEFAULT_PIPELINE_CONFIG,
    generate_detection_id,
    generate_report_id,
    score_to_action,
    score_to_notification_level,
    score_to_threat_level,
)
from fraud_agent_shared.hashing import hash_indicator_sync
from .phishing_detector import PhishingDetectorModel, load_model

logger = logging.getLogger(__name__)


@dataclass
class CaptureResult:
    """Result from CAPTURE stage."""
    raw_content: str
    source: MessageSource
    timestamp: float
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class QuickScanResult:
    """Result from QUICK_SCAN stage."""
    indicators_found: List[Indicator]
    quick_threat_score: float  # 0.0-1.0 based on quick heuristics
    should_defer_to_ml: bool = True


@dataclass
class MLClassificationResult:
    """Result from ML_CLASSIFY stage."""
    ml_threat_score: float
    ml_confidence: float
    predicted_class: int
    inference_time_ms: float


@dataclass
class DeepScanResult:
    """Result from DEEP_SCAN stage."""
    deep_threat_score: float
    analysis_details: Dict[str, any]
    patterns_found: List[str]


class DetectionPipeline:
    """Complete detection pipeline for fraud detection.
    
    Pipeline stages (in order):
    1. CAPTURE - Receive and normalize incoming content
    2. QUICK_SCAN - Fast heuristic扫描
    3. ML_CLASSIFY - Run ML model inference
    4. DEEP_SCAN - Deep pattern analysis
    5. ACTION - Determine action based on scores
    6. EXPLAIN - Generate plain-language explanation
    7. REPORT - Optionally report to community feed
    """
    
    # Quick scan patterns (matched as regex)
    QUICK_PATTERNS = {
        IndicatorType.URL: [
            r"https?://[^\s]+",
            r"www\.[^\s]+\.[^\s]+",
        ],
        IndicatorType.PHONE: [
            r"\+?[1-9]\d{9,14}",  # E.164 format
            r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        ],
        IndicatorType.EMAIL: [
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ],
        IndicatorType.KEYWORD: [
            r"\b(urgent|immediate|verify|confirm|account|locked|suspended)\b",
            r"\b(password|login|credential|security|bank)\b",
            r"\b(click|link|update|action|required)\b",
        ],
    }
    
    # High-confidence scam keywords
    SCAM_KEYWORDS = {
        "urgent", "immediate action", "account suspended",
        "verify your identity", "confirm your account",
        "unauthorized access", "security alert", "click here",
        "limited time", "act now", "immediate payment",
        "gift card", "bitcoin", "wire transfer", "bank transfer",
    }
    
    def __init__(
        self,
        config: Optional[DetectionPipelineConfig] = None,
        model: Optional[PhishingDetectorModel] = None,
    ):
        """Initialize the detection pipeline.
        
        Args:
            config: Pipeline configuration
            model: Pre-loaded ML model (optional)
        """
        self.config = config or DEFAULT_PIPELINE_CONFIG
        self._model = model
        self._compilation_cache: Dict[str, re.Pattern] = {}
    
    @property
    def model(self) -> Optional[PhishingDetectorModel]:
        """Get or load the ML model."""
        if self._model is None:
            from ..shared.python.fraud_agent_shared.config import get_config
            config = get_config()
            model_path = config.MODEL_PATH
            if model_path and model_path.endswith('.tflite'):
                self._model = load_model(model_path, "tflite")
            else:
                self._model = load_model(model_path, "onnx")
        return self._model
    
    def process(
        self,
        content: str,
        source: MessageSource,
        metadata: Optional[Dict[str, str]] = None,
    ) -> DetectionResult:
        """Process content through the complete detection pipeline.
        
        Args:
            content: Raw content to analyze
            source: Source of the content (SMS, EMAIL, BROWSER)
            metadata: Additional metadata about the content
        
        Returns:
            Complete DetectionResult with all stages applied
        """
        start_time = time.time()
        
        # Stage 1: CAPTURE
        capture_result = self._capture(content, source, metadata)
        
        # Stage 2: QUICK_SCAN
        if self.config.enable_quick_scan:
            quick_result = self._quick_scan(capture_result.raw_content)
        else:
            quick_result = QuickScanResult([], 0.0, False)
        
        # Stage 3: ML_CLASSIFY
        ml_result = None
        if self.config.enable_deep_scan:
            ml_result = self._ml_classify(capture_result.raw_content)
        
        # Stage 4: DEEP_SCAN
        if self.config.enable_deep_scan:
            deep_result = self._deep_scan(
                capture_result.raw_content,
                quick_result.indicators_found,
            )
        else:
            deep_result = DeepScanResult(0.0, {}, [])
        
        # Combine scores
        final_score = self._combine_scores(
            quick_result.quick_threat_score,
            ml_result.ml_threat_score if ml_result else 0.0,
            deep_result.deep_threat_score,
        )
        
        # Stage 5: ACTION
        action = score_to_action(final_score)
        notification_level = score_to_notification_level(final_score)
        threat_level = score_to_threat_level(final_score)
        
        # Combine all indicators
        all_indicators = quick_result.indicators_found.copy()
        for indicator in deep_result.patterns_found:
            all_indicators.append(Indicator(
                type=IndicatorType.PATTERN,
                value=indicator,
                description="detected pattern from deep scan",
            ))
        
        # Stage 6: EXPLAIN
        explanation = self._explain(
            final_score,
            threat_level,
            all_indicators,
            quick_result,
            ml_result,
            deep_result,
        )
        
        # Stage 7: REPORT (optional, returns hashable report)
        community_report = None
        if self.config.enable_community_reporting and action in [
            ActionType.QUARANTINE,
            ActionType.BLOCK,
        ]:
            community_report = self._create_report(
                all_indicators,
                final_score,
                source,
            )
        
        total_time_ms = (time.time() - start_time) * 1000
        
        logger.info(
            "detection_complete",
            extra={
                "detection_id": generate_detection_id(),
                "source": source.value,
                "final_score": final_score,
                "action": action.value,
                "processing_time_ms": total_time_ms,
            }
        )
        
        return DetectionResult(
            id=generate_detection_id(),
            timestamp=capture_result.timestamp,
            source=source,
            content=capture_result.raw_content,
            threat_score=ThreatScore(
                score=final_score,
                level=threat_level,
                confidence=ml_result.ml_confidence if ml_result else final_score,
            ),
            action=action,
            notification_level=notification_level,
            explanation=explanation,
            detected_indicators=all_indicators[: self.config.max_indicators],
        )
    
    def _capture(
        self,
        content: str,
        source: MessageSource,
        metadata: Optional[Dict[str, str]],
    ) -> CaptureResult:
        """Stage 1: CAPTURE - Receive and normalize content."""
        normalized_content = content.strip()
        
        return CaptureResult(
            raw_content=normalized_content,
            source=source,
            timestamp=time.time(),
            metadata=metadata or {},
        )
    
    def _quick_scan(self, content: str) -> QuickScanResult:
        """Stage 2: QUICK_SCAN - Fast heuristic scanning."""
        indicators: List[Indicator] = []
        quick_score = 0.0
        
        content_lower = content.lower()
        
        # Extract URLs
        for pattern in self.QUICK_PATTERNS[IndicatorType.URL]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_suspicious_url(match):
                    indicators.append(Indicator(
                        type=IndicatorType.URL,
                        value=match,
                        description="Suspicious URL detected",
                    ))
                    quick_score += 0.3
        
        # Extract phone numbers
        for pattern in self.QUICK_PATTERNS[IndicatorType.PHONE]:
            matches = re.findall(pattern, content)
            for match in matches:
                if self._is_suspicious_phone(match):
                    indicators.append(Indicator(
                        type=IndicatorType.PHONE,
                        value=match,
                        description="Suspicious phone number",
                    ))
                    quick_score += 0.25
        
        # Extract emails
        for pattern in self.QUICK_PATTERNS[IndicatorType.EMAIL]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_suspicious_email(match):
                    indicators.append(Indicator(
                        type=IndicatorType.EMAIL,
                        value=match,
                        description="Suspicious email address",
                    ))
                    quick_score += 0.2
        
        # Check for scam keywords
        keyword_score = 0.0
        for keyword in self.SCAM_KEYWORDS:
            if keyword in content_lower:
                indicators.append(Indicator(
                    type=IndicatorType.KEYWORD,
                    value=keyword,
                    description=f"Scam-related keyword: {keyword}",
                ))
                keyword_score += 0.15
        
        quick_score = min(quick_score + keyword_score, 1.0)
        
        return QuickScanResult(
            indicators_found=indicators,
            quick_threat_score=quick_score,
            should_defer_to_ml=quick_score < 0.5,
        )
    
    def _ml_classify(self, content: str) -> MLClassificationResult:
        """Stage 3: ML_CLASSIFY - Run ML model inference."""
        start_time = time.time()
        
        if self.model is None:
            logger.warning("ML model not available, using fallback scoring")
            return MLClassificationResult(
                ml_threat_score=0.5,
                ml_confidence=0.0,
                predicted_class=0,
                inference_time_ms=0.0,
            )
        
        try:
            result = self.model.predict(content)
            
            # Convert to threat score (class 1 = phishing)
            ml_score = float(result.class_probabilities[1])
            
            return MLClassificationResult(
                ml_threat_score=ml_score,
                ml_confidence=result.confidence,
                predicted_class=result.predicted_class,
                inference_time_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            logger.error(f"ML inference failed: {e}")
            return MLClassificationResult(
                ml_threat_score=0.5,
                ml_confidence=0.0,
                predicted_class=0,
                inference_time_ms=0.0,
            )
    
    def _deep_scan(
        self,
        content: str,
        quick_indicators: List[Indicator],
    ) -> DeepScanResult:
        """Stage 4: DEEP_SCAN - Deep pattern analysis."""
        patterns_found: List[str] = []
        deep_score = 0.0
        
        content_lower = content.lower()
        
        # Check for impersonation patterns (fake links)
        if any(word in content_lower for word in ["amazon", "apple", "microsoft", "paypal"]):
            if any(word in content_lower for word in ["verify", "confirm", "update", "account"]):
                patterns_found.append("impersonation_brand")
                deep_score += 0.4
        
        # Check for urgency patterns
        if any(word in content_lower for word in ["urgent", "immediately", "within 24 hours"]):
            patterns_found.append("urgency_tactic")
            deep_score += 0.3
        
        # Check for reward/threat patterns
        if any(word in content_lower for word in ["won", "prize", "lottery", "inheritance"]):
            patterns_found.append("reward_scam")
            deep_score += 0.35
        
        # Check for monetary request patterns
        if any(word in content_lower for word in ["payment", "wire transfer", "gift card", "bitcoin"]):
            patterns_found.append("monetary_request")
            deep_score += 0.4
        
        # Check for suspicious URL patterns
        for indicator in quick_indicators:
            if indicator.type == IndicatorType.URL:
                if self._analyze_url_pattern(indicator.value):
                    patterns_found.append(f"url_pattern_{indicator.value[:30]}")
                    deep_score += 0.2
        
        return DeepScanResult(
            deep_threat_score=min(deep_score, 1.0),
            analysis_details={"patterns": patterns_found},
            patterns_found=patterns_found,
        )
    
    def _combine_scores(
        self,
        quick_score: float,
        ml_score: float,
        deep_score: float,
    ) -> float:
        """Combine scores from all stages."""
        # Weighted combination
        weights = {"quick": 0.2, "ml": 0.6, "deep": 0.2}
        
        combined = (
            weights["quick"] * quick_score +
            weights["ml"] * ml_score +
            weights["deep"] * deep_score
        )
        
        return min(combined, 1.0)
    
    def _explain(
        self,
        final_score: float,
        threat_level: ThreatLevel,
        indicators: List[Indicator],
        quick_result: QuickScanResult,
        ml_result: Optional[MLClassificationResult],
        deep_result: DeepScanResult,
    ) -> str:
        """Stage 6: EXPLAIN - Generate plain-language explanation."""
        explanations = []
        
        if threat_level == ThreatLevel.SAFE:
            return "This content appears to be safe. No suspicious indicators were detected."
        
        if indicators:
            indicator_summary = ", ".join([
                f"'{ind.value}' ({ind.type.value})"
                for ind in indicators[:5]
            ])
            explanations.append(
                f"Detected suspicious indicators: {indicator_summary}"
            )
        
        if ml_result and ml_result.ml_confidence > 0.7:
            explanations.append(
                f"ML model classified this with {ml_result.ml_confidence:.0%} confidence as potential {threat_level.value.lower()}"
            )
        
        if deep_result.patterns_found:
            pattern_summary = ", ".join(set(deep_result.patterns_found))
            explanations.append(f"Deep scan identified patterns: {pattern_summary}")
        
        if final_score > 0.85:
            explanations.append(
                "This is highly likely to be a phishing attempt or scam. "
                "We recommend blocking and not interacting with this content."
            )
        elif final_score > 0.60:
            explanations.append(
                "This content shows signs of being a phishing attempt. "
                "Proceed with caution and verify through official channels."
            )
        
        return " | ".join(explanations) if explanations else (
            "Analysis complete. Some suspicious elements detected."
        )
    
    def _create_report(
        self,
        indicators: List[Indicator],
        threat_score: float,
        source: MessageSource,
    ) -> Optional[CommunityReport]:
        """Stage 7: REPORT - Create privacy-preserving community report."""
        if not indicators:
            return None
        
        # Hash the first indicator
        primary_indicator = indicators[0]
        indicator_type_map = {
            IndicatorType.URL: IndicatorType.URL,
            IndicatorType.PHONE: IndicatorType.PHONE,
            IndicatorType.EMAIL: IndicatorType.EMAIL,
        }
        
        hash_value = hash_indicator_sync(
            primary_indicator.value,
            indicator_type_map.get(primary_indicator.type, IndicatorType.KEYWORD),
        )
        
        return CommunityReport(
            id=generate_report_id(),
            hash=hash_value,
            threat_score=threat_score,
            timestamp=time.time(),
            source=source,
            indicator_type=primary_indicator.type,
        )
    
    # Helper methods
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious."""
        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            
            # Check for IP address in host
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc or parsed.path):
                return True
            
            # Check for suspicious TLDs
            suspicious_tlds = {".xyz", ".top", ".club", ".win", ".online"}
            if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Check for URL shortening
            if len(parsed.netloc) < 15 and "." not in parsed.netloc[:-4]:
                return True
            
            return False
        except Exception:
            return True
    
    def _is_suspicious_phone(self, phone: str) -> bool:
        """Check if phone number is suspicious."""
        # Check for premium rate numbers
        if phone.startswith("1-900") or phone.startswith("0900"):
            return True
        return False
    
    def _is_suspicious_email(self, email: str) -> bool:
        """Check if email is suspicious."""
        # Check for free email providers used in business contexts
        free_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
        
        try:
            _, domain = email.rsplit("@", 1)
            if domain.lower() in free_providers:
                return True
        except Exception:
            pass
        
        return False
    
    def _analyze_url_pattern(self, url: str) -> bool:
        """Analyze URL for suspicious patterns."""
        suspicious_patterns = [
            r"login", r"signin", r"verify", r"account", r"update",
            r"secure", r"banking", r"confirm",
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in suspicious_patterns)


def create_pipeline(
    config: Optional[DetectionPipelineConfig] = None,
    model_path: Optional[str] = None,
) -> DetectionPipeline:
    """Create a configured detection pipeline.
    
    Args:
        config: Pipeline configuration
        model_path: Path to ML model
    
    Returns:
        Configured DetectionPipeline instance
    """
    model = None
    if model_path:
        model = load_model(model_path)
    
    return DetectionPipeline(config, model)
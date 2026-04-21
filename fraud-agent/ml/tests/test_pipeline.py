"""Unit tests for detection pipeline."""
import pytest

from ml.models.detection_pipeline import (
    DetectionPipeline,
    QuickScanResult,
    MLClassificationResult,
    DeepScanResult,
    create_pipeline,
)
from fraud_agent_shared.types import (
    MessageSource,
    ActionType,
    NotificationLevel,
    ThreatLevel,
    Indicator,
    IndicatorType,
)


class TestDetectionPipeline:
    """Tests for DetectionPipeline class."""

    def test_pipeline_safe_content(self):
        """Test pipeline with safe content."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "Meeting at 3pm tomorrow in conference room B.",
            source=MessageSource.SMS,
        )
        
        assert result.action == ActionType.ALLOW
        assert result.threat_score.score <= 0.30
        assert result.notification_level == NotificationLevel.NONE

    def test_pipeline_phishing_content(self):
        """Test pipeline with phishing content."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "Urgent: Verify your Amazon account within 24 hours or lose access. Click here: https://fake-amazon.com/verify",
            source=MessageSource.SMS,
        )
        
        assert result.threat_score.score > 0.30
        assert result.action in [ActionType.WARN, ActionType.QUARANTINE, ActionType.BLOCK]

    def test_pipeline_url_extraction(self):
        """Test URL extraction in quick scan."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "Click here: https://suspicious-site.xyz/login verify your account now",
            source=MessageSource.SMS,
        )
        
        url_indicators = [
            ind for ind in result.detected_indicators
            if ind.type == IndicatorType.URL
        ]
        
        assert len(url_indicators) > 0

    def test_pipeline_keyword_extraction(self):
        """Test keyword extraction in quick scan."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "URGENT: Your account has been suspended. Verify identity immediately.",
            source=MessageSource.SMS,
        )
        
        keyword_indicators = [
            ind for ind in result.detected_indicators
            if ind.type == IndicatorType.KEYWORD
        ]
        
        assert len(keyword_indicators) > 0
        assert result.threat_score.score > 0.0

    def test_pipeline_email_source(self):
        """Test pipeline with EMAIL source."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "Verify your account now",
            source=MessageSource.EMAIL,
        )
        
        assert result.source == MessageSource.EMAIL

    def test_pipeline_browser_source(self):
        """Test pipeline with BROWSER source."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "Your password expires in 24 hours. Update now.",
            source=MessageSource.BROWSER,
        )
        
        assert result.source == MessageSource.BROWSER

    def test_pipeline_explanation_generation(self):
        """Test explanation is generated."""
        pipeline = create_pipeline()
        
        result = pipeline.process(
            "URGENT: Click here to verify your account. Account will be suspended!",
            source=MessageSource.SMS,
        )
        
        assert result.explanation is not None
        assert len(result.explanation) > 0

    def test_pipeline_indicators_limited(self):
        """Test indicators limited by max_indicators config."""
        from fraud_agent_shared.types import DetectionPipelineConfig
        
        pipeline = create_pipeline(
            config=DetectionPipelineConfig(max_indicators=3)
        )
        
        result = pipeline.process(
            "Verify urgent account click link update confirm password login now https://example.com",
            source=MessageSource.SMS,
        )
        
        assert len(result.detected_indicators) <= 3


class TestQuickScan:
    """Tests for quick scan stage."""

    def test_quick_scan_detects_urls(self):
        """Test quick scan detects URLs."""
        pipeline = create_pipeline()
        
        result = pipeline._quick_scan("Check https://example.com for more info")
        
        assert len(result.indicators_found) > 0

    def test_quick_scan_detects_phones(self):
        """Test quick scan detects phone numbers."""
        pipeline = create_pipeline()
        
        result = pipeline._quick_scan("Call us at +1234567890 for help")
        
        phone_indicators = [
            ind for ind in result.indicators_found
            if ind.type == IndicatorType.PHONE
        ]
        
        assert len(phone_indicators) > 0

    def test_quick_scan_detects_emails(self):
        """Test quick scan detects emails."""
        pipeline = create_pipeline()
        
        result = pipeline._quick_scan("Email test@example.com for support")
        
        email_indicators = [
            ind for ind in result.indicators_found
            if ind.type == IndicatorType.EMAIL
        ]
        
        assert len(email_indicators) > 0

    def test_quick_scan_scam_keywords(self):
        """Test quick scan detects scam keywords."""
        pipeline = create_pipeline()
        
        result = pipeline._quick_scan("ACT NOW! Immediate payment required. Gift card.")
        
        keyword_indicators = [
            ind for ind in result.indicators_found
            if ind.type == IndicatorType.KEYWORD
        ]
        
        assert len(keyword_indicators) > 0


class TestDeepScan:
    """Tests for deep scan stage."""

    def test_deep_scan_impersonation(self):
        """Test deep scan detects brand impersonation."""
        pipeline = create_pipeline()
        
        result = pipeline._deep_scan(
            "Amazon verify your account now",
            [],
        )
        
        assert "impersonation_brand" in result.patterns_found

    def test_deep_scan_urgency(self):
        """Test deep scan detects urgency tactics."""
        pipeline = create_pipeline()
        
        result = pipeline._deep_scan(
            "URGENT: Verify your account immediately within 24 hours",
            [],
        )
        
        assert "urgency_tactic" in result.patterns_found


class TestScoreCombination:
    """Tests for score combination."""

    def test_combine_scores(self):
        """Test combining scores from different stages."""
        pipeline = create_pipeline()
        
        combined = pipeline._combine_scores(
            quick_score=0.2,
            ml_score=0.8,
            deep_score=0.3,
        )
        
        expected = 0.2 * 0.2 + 0.8 * 0.6 + 0.3 * 0.2
        assert abs(combined - expected) < 0.01

    def test_combine_scores_capped(self):
        """Test combined score is capped at 1.0."""
        pipeline = create_pipeline()
        
        combined = pipeline._combine_scores(
            quick_score=1.0,
            ml_score=1.0,
            deep_score=1.0,
        )
        
        assert combined <= 1.0


class TestSuspiciousDetectors:
    """Tests for suspicious pattern detection."""

    def test_suspicious_url_ip_address(self):
        """Test detection of IP address URLs."""
        pipeline = create_pipeline()
        
        assert pipeline._is_suspicious_url("http://192.168.1.1/login") is True

    def test_suspicious_url_suspicious_tld(self):
        """Test detection of suspicious TLDs."""
        pipeline = create_pipeline()
        
        assert pipeline._is_suspicious_url("https://example.xyz/login") is True

    def test_suspicious_phone_premium(self):
        """Test detection of premium rate numbers."""
        pipeline = create_pipeline()
        
        assert pipeline._is_suspicious_phone("1-900-123-4567") is True

    def test_suspicious_email_free_provider(self):
        """Test detection of free email providers."""
        pipeline = create_pipeline()
        
        assert pipeline._is_suspicious_email("business@gmail.com") is True
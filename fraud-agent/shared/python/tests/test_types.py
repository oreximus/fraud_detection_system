"""Unit tests for shared module types."""
import pytest

from fraud_agent_shared.types import (
    ThreatLevel,
    ActionType,
    NotificationLevel,
    IndicatorType,
    MessageSource,
    ThreatScore,
    DetectionResult,
    Indicator,
    score_to_action,
    score_to_notification_level,
    score_to_threat_level,
    generate_detection_id,
    generate_report_id,
    THREAT_SCORE_ALLOW,
    THREAT_SCORE_WARN,
    THREAT_SCORE_QUARANTINE,
)


class TestScoreToAction:
    """Tests for score_to_action function."""

    def test_score_allow(self):
        """Test low score returns ALLOW action."""
        assert score_to_action(0.0) == ActionType.ALLOW
        assert score_to_action(0.15) == ActionType.ALLOW
        assert score_to_action(0.30) == ActionType.ALLOW

    def test_score_warn(self):
        """Test medium-low score returns WARN action."""
        assert score_to_action(0.31) == ActionType.WARN
        assert score_to_action(0.45) == ActionType.WARN
        assert score_to_action(0.60) == ActionType.WARN

    def test_score_quarantine(self):
        """Test medium-high score returns QUARANTINE action."""
        assert score_to_action(0.61) == ActionType.QUARANTINE
        assert score_to_action(0.70) == ActionType.QUARANTINE
        assert score_to_action(0.85) == ActionType.QUARANTINE

    def test_score_block(self):
        """Test high score returns BLOCK action."""
        assert score_to_action(0.86) == ActionType.BLOCK
        assert score_to_action(0.95) == ActionType.BLOCK
        assert score_to_action(1.00) == ActionType.BLOCK


class TestScoreToNotificationLevel:
    """Tests for score_to_notification_level function."""

    def test_none_level(self):
        """Test low score returns NONE notification."""
        assert score_to_notification_level(0.0) == NotificationLevel.NONE
        assert score_to_notification_level(0.30) == NotificationLevel.NONE

    def test_soft_level(self):
        """Test medium-low score returns SOFT notification."""
        assert score_to_notification_level(0.31) == NotificationLevel.SOFT
        assert score_to_notification_level(0.60) == NotificationLevel.SOFT

    def test_alert_level(self):
        """Test medium-high score returns ALERT notification."""
        assert score_to_notification_level(0.61) == NotificationLevel.ALERT
        assert score_to_notification_level(0.85) == NotificationLevel.ALERT

    def test_full_level(self):
        """Test high score returns FULL notification."""
        assert score_to_notification_level(0.86) == NotificationLevel.FULL
        assert score_to_notification_level(1.00) == NotificationLevel.FULL


class TestScoreToThreatLevel:
    """Tests for score_to_threat_level function."""

    def test_safe_level(self):
        """Test low score returns SAFE level."""
        assert score_to_threat_level(0.0) == ThreatLevel.SAFE
        assert score_to_threat_level(0.30) == ThreatLevel.SAFE

    def test_suspicious_level(self):
        """Test medium-low score returns SUSPICIOUS level."""
        assert score_to_threat_level(0.31) == ThreatLevel.SUSPICIOUS
        assert score_to_threat_level(0.60) == ThreatLevel.SUSPICIOUS

    def test_phishing_level(self):
        """Test medium-high score returns PHISHING level."""
        assert score_to_threat_level(0.61) == ThreatLevel.PHISHING
        assert score_to_threat_level(0.85) == ThreatLevel.PHISHING

    def test_scam_level(self):
        """Test high score returns SCAM level."""
        assert score_to_threat_level(0.86) == ThreatLevel.SCAM
        assert score_to_threat_level(1.00) == ThreatLevel.SCAM


class TestGenerateIds:
    """Tests for ID generation functions."""

    def test_generate_detection_id(self):
        """Test detection ID generation."""
        id1 = generate_detection_id()
        id2 = generate_detection_id()
        
        assert id1.startswith("det_")
        assert id1 != id2

    def test_generate_report_id(self):
        """Test report ID generation."""
        id1 = generate_report_id()
        id2 = generate_report_id()
        
        assert id1.startswith("rpt_")
        assert id1 != id2


class TestThreatScore:
    """Tests for ThreatScore dataclass."""

    def test_create_threat_score(self):
        """Test creating a ThreatScore."""
        ts = ThreatScore(
            score=0.75,
            level=ThreatLevel.PHISHING,
            confidence=0.92
        )
        
        assert ts.score == 0.75
        assert ts.level == ThreatLevel.PHISHING
        assert ts.confidence == 0.92


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_create_detection_result(self):
        """Test creating a DetectionResult."""
        ts = ThreatScore(
            score=0.85,
            level=ThreatLevel.PHISHING,
            confidence=0.95
        )
        result = DetectionResult(
            id="det_123",
            timestamp=1234567890.0,
            source=MessageSource.SMS,
            content="Test message",
            threat_score=ts,
            action=ActionType.QUARANTINE,
            notification_level=NotificationLevel.ALERT,
            explanation="Phishing detected"
        )
        
        assert result.id == "det_123"
        assert result.source == MessageSource.SMS
        assert result.action == ActionType.QUARANTINE
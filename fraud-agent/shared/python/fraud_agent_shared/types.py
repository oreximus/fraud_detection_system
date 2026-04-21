"""Shared type definitions for fraud detection system."""
import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from datetime import datetime

THREAT_SCORE_ALLOW = 0.30
THREAT_SCORE_WARN = 0.60
THREAT_SCORE_QUARANTINE = 0.85
THREAT_SCORE_BLOCK = 1.00


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    SCAM = "SCAM"


class ActionType(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class NotificationLevel(str, Enum):
    NONE = "NONE"
    SOFT = "SOFT"
    ALERT = "ALERT"
    FULL = "FULL"


class IndicatorType(str, Enum):
    URL = "URL"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    KEYWORD = "KEYWORD"
    PATTERN = "PATTERN"


class MessageSource(str, Enum):
    SMS = "SMS"
    EMAIL = "EMAIL"
    BROWSER = "BROWSER"


@dataclass
class ThreatScore:
    """Threat score with level classification and confidence."""
    score: float
    level: ThreatLevel
    confidence: float


@dataclass
class Indicator:
    """Detected threat indicator."""
    type: IndicatorType
    value: str
    description: str


@dataclass
class DetectionResult:
    """Complete detection result from the pipeline."""
    id: str
    timestamp: float
    source: MessageSource
    content: str
    threat_score: ThreatScore
    action: ActionType
    notification_level: NotificationLevel
    explanation: str
    detected_indicators: List[Indicator] = field(default_factory=list)


@dataclass
class CommunityReport:
    """Privacy-preserving community report with hashed indicators."""
    id: str
    hash: str
    threat_score: float
    timestamp: float
    source: MessageSource
    indicator_type: IndicatorType


@dataclass
class DetectionPipelineConfig:
    """Configuration for the detection pipeline."""
    enable_quick_scan: bool = True
    enable_deep_scan: bool = True
    enable_community_reporting: bool = True
    ml_model_timeout: int = 5000
    max_indicators: int = 10


DEFAULT_PIPELINE_CONFIG = DetectionPipelineConfig()


def score_to_action(score: float) -> ActionType:
    """Convert threat score to recommended action."""
    if score <= THREAT_SCORE_ALLOW:
        return ActionType.ALLOW
    if score <= THREAT_SCORE_WARN:
        return ActionType.WARN
    if score <= THREAT_SCORE_QUARANTINE:
        return ActionType.QUARANTINE
    return ActionType.BLOCK


def score_to_notification_level(score: float) -> NotificationLevel:
    """Convert threat score to notification level."""
    if score <= THREAT_SCORE_ALLOW:
        return NotificationLevel.NONE
    if score <= THREAT_SCORE_WARN:
        return NotificationLevel.SOFT
    if score <= THREAT_SCORE_QUARANTINE:
        return NotificationLevel.ALERT
    return NotificationLevel.FULL


def score_to_threat_level(score: float) -> ThreatLevel:
    """Convert threat score to threat level."""
    if score <= THREAT_SCORE_ALLOW:
        return ThreatLevel.SAFE
    if score <= THREAT_SCORE_WARN:
        return ThreatLevel.SUSPICIOUS
    if score <= THREAT_SCORE_QUARANTINE:
        return ThreatLevel.PHISHING
    return ThreatLevel.SCAM


def generate_detection_id() -> str:
    """Generate unique detection ID."""
    return f"det_{int(datetime.now().timestamp() * 1000)}_{os.urandom(8).hex()}"


def generate_report_id() -> str:
    """Generate unique report ID."""
    return f"rpt_{int(datetime.now().timestamp() * 1000)}_{os.urandom(8).hex()}"
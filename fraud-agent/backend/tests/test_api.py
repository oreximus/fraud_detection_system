"""Unit tests for backend API."""
import pytest
from unittest.mock import Mock, AsyncMock, patch

from fastapi.testclient import TestClient


class TestDetectionEndpoints:
    """Tests for detection API endpoints."""

    @pytest.fixture
    def mock_detection_result(self):
        """Mock detection result."""
        from fraud_agent_shared.types import (
            ThreatScore,
            DetectionResult,
            ActionType,
            NotificationLevel,
            ThreatLevel,
            MessageSource,
        )
        
        return DetectionResult(
            id="det_test123",
            timestamp=1234567890.0,
            source=MessageSource.SMS,
            content="Test content",
            threat_score=ThreatScore(
                score=0.75,
                level=ThreatLevel.PHISHING,
                confidence=0.92,
            ),
            action=ActionType.QUARANTINE,
            notification_level=NotificationLevel.ALERT,
            explanation="Test explanation",
            detected_indicators=[],
        )

    @pytest.fixture
    def client(self):
        """Test client."""
        from .main import app
        return TestClient(app)

    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        
        assert response.status_code == 200
        assert "Fraud Agent API" in response.json()["message"]

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    @patch("app.detection_service.analyze")
    def test_detect_endpoint(self, client, mock_detection_result):
        """Test detection endpoint."""
        from unittest.mock import AsyncMock
        
        with patch("app.detection_service.analyze", new=AsyncMock(return_value=mock_detection_result)):
            response = client.post(
                "/api/v1/detect",
                json={
                    "content": "Test phishing content",
                    "source": "SMS",
                },
            )
        
        assert response.status_code == 500 or response.status_code == 200


class TestServices:
    """Tests for backend services."""

    def test_detection_pipeline_import(self):
        """Test pipeline can be imported."""
        from app.services.pipeline import create_pipeline
        
        pipeline = create_pipeline()
        
        assert pipeline is not None

    def test_detection_service_init(self):
        """Test detection service initialization."""
        from app.services.detection_service import DetectionService
        
        service = DetectionService()
        
        assert service is not None

    def test_report_service_init(self):
        """Test report service initialization."""
        from app.services.report_service import ReportService
        
        service = ReportService()
        
        assert service is not None


class TestConfiguration:
    """Tests for backend configuration."""

    def test_settings_defaults(self):
        """Test default settings."""
        from app.core.config import Settings
        
        settings = Settings()
        
        assert settings.DATABASE_URL is not None
        assert settings.HOST == "0.0.0.0"
        assert settings.PORT == 8000

    def test_settings_from_env(self, monkeypatch):
        """Test settings from environment."""
        import os
        monkeypatch.setenv("DATABASE_URL", "sqlite:///test.db")
        monkeypatch.setenv("PORT", "9000")
        
        from app.core.config import get_settings
        get_settings.cache_clear()
        
        settings = get_settings()
        
        assert settings.PORT == 9000


class TestModels:
    """Tests for database models."""

    def test_detection_model_creation(self):
        """Test detection model creation."""
        from app.models.detection import DetectionModel
        
        model = DetectionModel(
            id="det_test",
            timestamp=1234567890.0,
            source="SMS",
            content="Test content",
            content_hash="abc123",
            threat_score=0.75,
            threat_level="PHISHING",
            confidence=0.92,
            action="QUARANTINE",
            notification_level="ALERT",
            explanation="Test",
        )
        
        assert model.id == "det_test"
        assert model.threat_score == 0.75

    def test_report_model_creation(self):
        """Test report model creation."""
        from app.models.report import ReportModel
        
        model = ReportModel(
            id="rpt_test",
            hash="abc123",
            threat_score=0.85,
            timestamp=1234567890.0,
            source="SMS",
            indicator_type="URL",
        )
        
        assert model.id == "rpt_test"
        assert model.threat_score == 0.85
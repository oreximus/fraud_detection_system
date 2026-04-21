"""Configuration management for fraud detection system."""
import os
from functools import lru_cache
from typing import Optional

from .types import DEFAULT_PIPELINE_CONFIG, DetectionPipelineConfig


class Config:
    """Application configuration loaded from environment variables."""
    
    # Database
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./fraud_agent.db")
    
    # Redis
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    
    # ML Model
    MODEL_PATH: str = os.environ.get("MODEL_PATH", "./ml/models/phishing_detector.onnx")
    TFLITE_MODEL_PATH: str = os.environ.get("TFLITE_MODEL_PATH", "./ml/models/phishing_detector.tflite")
    
    # API Keys (should be loaded from secure storage in production)
    API_KEY: Optional[str] = os.environ.get("API_KEY")
    COMMUNITY_API_URL: str = os.environ.get("COMMUNITY_API_URL", "https://api.fraudagent.local")
    
    # Privacy
    SALT: Optional[str] = os.environ.get("FRAUD_AGENT_SALT")
    
    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.environ.get("LOG_FORMAT", "json")
    
    # Server
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "8000"))
    
    # Community Reporting
    ENABLE_COMMUNITY_REPORTING: bool = os.environ.get(
        "ENABLE_COMMUNITY_REPORTING", "true"
    ).lower() == "true"
    
    # ML Inference
    ML_TIMEOUT: int = int(os.environ.get("ML_TIMEOUT", "5000"))
    
    # Dashboard
    DASHBOARD_URL: str = os.environ.get("DASHBOARD_URL", "http://localhost:5173")
    
    @property
    def database_url(self) -> str:
        return self.DATABASE_URL
    
    @property
    def is_production(self) -> bool:
        return os.environ.get("ENVIRONMENT", "development") == "production"


@lru_cache()
def get_config() -> Config:
    """Get cached configuration instance."""
    return Config()


def get_pipeline_config() -> DetectionPipelineConfig:
    """Get detection pipeline configuration."""
    config = get_config()
    return DetectionPipelineConfig(
        enable_quick_scan=True,
        enable_deep_scan=True,
        enable_community_reporting=self.ENABLE_COMMUNITY_REPORTING,
        ml_model_timeout=self.ML_TIMEOUT,
        max_indicators=10,
    )
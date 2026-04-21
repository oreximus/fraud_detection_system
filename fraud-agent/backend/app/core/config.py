"""Backend configuration settings."""
import os
from functools import lru_cache


class Settings:
    """Application settings loaded from environment variables."""
    
    def __init__(self):
        self.DATABASE_URL: str = os.environ.get(
            "DATABASE_URL",
            "sqlite:///./fraud_agent.db"
        )
        self.REDIS_URL: str = os.environ.get(
            "REDIS_URL",
            "redis://localhost:6379/0"
        )
        self.CELERY_BROKER_URL: str = os.environ.get(
            "CELERY_BROKER_URL",
            "redis://localhost:6379/1"
        )
        self.CELERY_RESULT_BACKEND: str = os.environ.get(
            "CELERY_RESULT_BACKEND",
            "redis://localhost:6379/2"
        )
        
        self.DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"
        self.HOST: str = os.environ.get("HOST", "0.0.0.0")
        self.PORT: int = int(os.environ.get("PORT", "8000"))
        
        self.API_KEY: str = os.environ.get("API_KEY", "")
        self.API_KEYS: list = os.environ.get("API_KEYS", "").split(",")
        
        self.ENABLE_COMMUNITY_REPORTING: bool = os.environ.get(
            "ENABLE_COMMUNITY_REPORTING", "true"
        ).lower() == "true"
        
        self.MODEL_PATH: str = os.environ.get(
            "MODEL_PATH",
            "../ml/models/phishing_detector.onnx"
        )
        
        self.LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
        
        self.MAX_CONTENT_LENGTH: int = int(os.environ.get("MAX_CONTENT_LENGTH", "10000"))
        self.INFERENCE_TIMEOUT: int = int(os.environ.get("INFERENCE_TIMEOUT", "5000"))
        
        self.CORS_ORIGINS: list = os.environ.get(
            "CORS_ORIGINS",
            "*"
        ).split(",")


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
"""Detection service for analyzing content."""
import hashlib
import json
import logging
import time
from typing import Dict, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from ..models.detection import DetectionModel
from .pipeline import DetectionPipeline, create_pipeline as create_detection_pipeline

logger = logging.getLogger(__name__)


class DetectionService:
    """Service for handling detection operations."""
    
    def __init__(self):
        self._pipeline: Optional[DetectionPipeline] = None
    
    @property
    def pipeline(self) -> DetectionPipeline:
        """Get or create detection pipeline."""
        if self._pipeline is None:
            self._pipeline = create_detection_pipeline()
        return self._pipeline
    
    async def analyze(
        self,
        content: str,
        source: str,
        metadata: Optional[Dict] = None,
        db: Optional[Session] = None,
    ):
        """Analyze content for phishing/scams."""
        from fraud_agent_shared.types import MessageSource
        
        message_source = MessageSource(source.upper())
        
        logger.info(f"Analyzing content from {source}", extra={
            "source": source,
            "content_length": len(content),
        })
        
        result = self.pipeline.process(
            content=content,
            source=message_source,
            metadata=metadata,
        )
        
        if db is not None:
            self._save_detection(result, db)
        
        return result
    
    def _save_detection(self, result, db: Session):
        """Save detection to database."""
        model = DetectionModel(
            id=result.id,
            timestamp=result.timestamp,
            source=result.source.value,
            content=result.content,
            content_hash=hashlib.sha256(result.content.encode()).hexdigest(),
            threat_score=result.threat_score.score,
            threat_level=result.threat_score.level.value,
            confidence=result.threat_score.confidence,
            action=result.action.value,
            notification_level=result.notification_level.value,
            explanation=result.explanation,
            indicators=json.dumps([
                {
                    "type": ind.type.value,
                    "value": ind.value,
                    "description": ind.description,
                }
                for ind in result.detected_indicators
            ]),
        )
        
        db.add(model)
        db.commit()
        
        logger.info(f"Saved detection {result.id}")
    
    def list_detections(
        self,
        db: Session,
        limit: int = 100,
        offset: int = 0,
    ) -> List[DetectionModel]:
        """List detections with pagination."""
        return db.query(DetectionModel).order_by(
            DetectionModel.timestamp.desc()
        ).offset(offset).limit(limit).all()
    
    def get_detection(self, detection_id: str, db: Session) -> Optional[DetectionModel]:
        """Get a specific detection."""
        return db.query(DetectionModel).filter(
            DetectionModel.id == detection_id
        ).first()
    
    def get_statistics(self, db: Session) -> Dict:
        """Get detection statistics."""
        total = db.query(func.count(DetectionModel.id)).scalar() or 0
        
        blocked = db.query(func.count(DetectionModel.id)).filter(
            DetectionModel.action == "BLOCK"
        ).scalar() or 0
        
        quarantined = db.query(func.count(DetectionModel.id)).filter(
            DetectionModel.action == "QUARANTINE"
        ).scalar() or 0
        
        warned = db.query(func.count(DetectionModel.id)).filter(
            DetectionModel.action == "WARN"
        ).scalar() or 0
        
        allowed = db.query(func.count(DetectionModel.id)).filter(
            DetectionModel.action == "ALLOW"
        ).scalar() or 0
        
        recent = db.query(DetectionModel).order_by(
            DetectionModel.timestamp.desc()
        ).limit(10).all()
        
        return {
            "total_detections": total,
            "blocked_count": blocked,
            "quarantined_count": quarantined,
            "warned_count": warned,
            "allowed_count": allowed,
            "recent_threats": [
                {
                    "id": r.id,
                    "source": r.source,
                    "threat_score": r.threat_score,
                    "threat_level": r.threat_level,
                    "timestamp": r.timestamp,
                }
                for r in recent
                if r.threat_score > 0.5
            ],
        }
    
    async def log_detection(self, result):
        """Log detection (background task)."""
        logger.info("detection_complete", extra={
            "detection_id": result.id,
            "source": result.source.value,
            "score": result.threat_score.score,
            "action": result.action.value,
        })
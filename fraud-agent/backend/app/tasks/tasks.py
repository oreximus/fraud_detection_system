"""Celery configuration and tasks."""
import logging
import os

from celery import Celery

logger = logging.getLogger(__name__)

celery_app = Celery(
    "fraud_agent",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/1"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/2"),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30,
    task_soft_time_limit=25,
)


@celery_app.task(name="fraud_agent.tasks.detect_content")
def detect_content(content: str, source: str, metadata: dict = None):
    """Async task for content detection."""
    from ..services.pipeline import create_pipeline
    
    pipeline = create_pipeline()
    
    from fraud_agent_shared.types import MessageSource
    result = pipeline.process(
        content=content,
        source=MessageSource(source.upper()),
        metadata=metadata,
    )
    
    logger.info(f"Async detection complete: {result.id}")
    return {
        "id": result.id,
        "score": result.threat_score.score,
        "action": result.action.value,
    }


@celery_app.task(name="fraud_agent.tasks.batch_detect")
def batch_detect(items: list):
    """Batch detection task."""
    results = []
    
    for item in items:
        result = detect_content.delay(
            content=item["content"],
            source=item["source"],
            metadata=item.get("metadata"),
        )
        results.append(result.id)
    
    return results


@celery_app.task(name="fraud_agent.tasks.cleanup_old_reports")
def cleanup_old_reports(days: int = 30):
    """Clean up old community reports."""
    from datetime import datetime, timedelta
    from sqlalchemy import delete
    
    from ..db.database import SessionLocal
    from ..models.report import ReportModel
    
    session = SessionLocal()
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    try:
        session.execute(
            delete(ReportModel).where(
                ReportModel.created_at < cutoff
            )
        )
        session.commit()
        logger.info(f"Cleaned up reports older than {days} days")
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        session.rollback()
    finally:
        session.close()
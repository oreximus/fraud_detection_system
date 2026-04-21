"""Report service for community threat sharing."""
import logging
import time
from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from ..models.report import ReportModel

logger = logging.getLogger(__name__)


class ReportService:
    """Service for handling community reports."""
    
    async def create_report(
        self,
        indicator_hash: str,
        threat_score: float,
        indicator_type: str,
        source: str,
        db: Session,
    ) -> ReportModel:
        """Create or update a community report."""
        existing = db.query(ReportModel).filter(
            ReportModel.hash == indicator_hash
        ).first()
        
        if existing:
            existing.report_count += 1
            existing.threat_score = max(existing.threat_score, threat_score)
            existing.updated_at = func.now()
            db.commit()
            
            logger.info(f"Updated report {indicator_hash}")
            return existing
        
        report = ReportModel(
            id=f"rpt_{int(time.time() * 1000)}",
            hash=indicator_hash,
            threat_score=threat_score,
            timestamp=time.time(),
            source=source.upper(),
            indicator_type=indicator_type.upper(),
            report_count=1,
        )
        
        db.add(report)
        db.commit()
        
        logger.info(f"Created report {indicator_hash}")
        return report
    
    def list_reports(
        self,
        db: Session,
        limit: int = 100,
    ) -> List[ReportModel]:
        """List community reports."""
        return db.query(ReportModel).order_by(
            ReportModel.timestamp.desc()
        ).limit(limit).all()
    
    def get_report_count(self, hash_value: str, db: Session) -> int:
        """Get count of reports for a hash."""
        return db.query(func.count(ReportModel.id)).filter(
            ReportModel.hash == hash_value
        ).scalar() or 0
    
    def get_threat_feed(
        self,
        db: Session,
        min_score: float = 0.5,
        limit: int = 100,
    ) -> List[ReportModel]:
        """Get threat feed for community."""
        return db.query(ReportModel).filter(
            ReportModel.threat_score >= min_score
        ).order_by(
            ReportModel.threat_score.desc(),
            ReportModel.report_count.desc(),
        ).limit(limit).all()
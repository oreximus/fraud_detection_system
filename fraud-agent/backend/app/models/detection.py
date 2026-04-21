"""Detection DB model."""
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, Text, JSON, DateTime
from sqlalchemy.dialects.postgresql import JSONB

from ..db.database import Base


class DetectionModel(Base):
    """Detection record database model."""
    __tablename__ = "detections"
    
    id = Column(String(64), primary_key=True)
    timestamp = Column(Float, nullable=False, index=True)
    source = Column(String(16), nullable=False, index=True)
    content = Column(Text, nullable=False)
    content_hash = Column(String(64), nullable=False, index=True)
    
    threat_score = Column(Float, nullable=False)
    threat_level = Column(String(16), nullable=False)
    confidence = Column(Float, nullable=False)
    
    action = Column(String(16), nullable=False)
    notification_level = Column(String(16), nullable=False)
    
    explanation = Column(Text, nullable=False)
    indicators = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Detection {self.id} score={self.threat_score}>"


class ReportModel(Base):
    """Community report database model."""
    __tablename__ = "reports"
    
    id = Column(String(64), primary_key=True)
    hash = Column(String(64), nullable=False, index=True)
    threat_score = Column(Float, nullable=False)
    timestamp = Column(Float, nullable=False, index=True)
    source = Column(String(16), nullable=False)
    indicator_type = Column(String(16), nullable=False)
    
    report_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Report {self.hash} score={self.threat_score}>"
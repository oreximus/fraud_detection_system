"""FastAPI backend for fraud detection system."""
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .core.config import Settings
from .core.logging import setup_logging
from .db.database import Base, engine, get_db_session
from .models.detection import DetectionModel
from .models.report import ReportModel
from .services.detection_service import DetectionService
from .services.report_service import ReportService


setup_logging()
logger = logging.getLogger(__name__)
settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting up Fraud Agent API")
    
    Base.metadata.create_all(bind=engine)
    
    yield
    
    logger.info("Shutting down Fraud Agent API")


app = FastAPI(
    title="Fraud Agent API",
    description="Privacy-first fraud detection system API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DetectionRequest(BaseModel):
    """Request model for detection."""
    content: str = Field(..., description="Content to analyze")
    source: str = Field(..., description="Source: SMS, EMAIL, or BROWSER")
    metadata: Optional[dict] = Field(default=None, description="Additional metadata")


class DetectionResponse(BaseModel):
    """Response model for detection."""
    id: str
    timestamp: float
    source: str
    content: str
    threat_score: float
    threat_level: str
    confidence: float
    action: str
    notification_level: str
    explanation: str
    indicators: List[dict]


class ReportRequest(BaseModel):
    """Request model for community reporting."""
    indicator_hash: str = Field(..., description="SHA-256 hash of indicator")
    threat_score: float = Field(..., ge=0.0, le=1.0)
    indicator_type: str = Field(..., description="Type: URL, PHONE, EMAIL")
    source: str = Field(..., description="Source: SMS, EMAIL, or BROWSER")


class ReportResponse(BaseModel):
    """Response model for community report."""
    id: str
    hash: str
    threat_score: float
    timestamp: float
    source: str
    indicator_type: str
    report_count: int


class StatsResponse(BaseModel):
    """Response model for statistics."""
    total_detections: int
    blocked_count: int
    quarantined_count: int
    warned_count: int
    allowed_count: int
    recent_threats: List[dict]


detection_service = DetectionService()
report_service = ReportService()


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Fraud Agent API", "version": "0.1.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/api/v1/detect", response_model=DetectionResponse)
async def detect(
    request: DetectionRequest,
    background_tasks: BackgroundTasks,
    db=Depends(get_db_session),
):
    """Analyze content for phishing/m scam attempts."""
    try:
        result = await detection_service.analyze(
            content=request.content,
            source=request.source,
            metadata=request.metadata,
            db=db,
        )
        
        background_tasks.add_task(
            detection_service.log_detection,
            result,
        )
        
        return DetectionResponse(
            id=result.id,
            timestamp=result.timestamp,
            source=result.source.value,
            content=result.content,
            threat_score=result.threat_score.score,
            threat_level=result.threat_score.level.value,
            confidence=result.threat_score.confidence,
            action=result.action.value,
            notification_level=result.notification_level.value,
            explanation=result.explanation,
            indicators=[
                {
                    "type": ind.type.value,
                    "value": ind.value,
                    "description": ind.description,
                }
                for ind in result.detected_indicators
            ],
        )
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/detections", response_model=List[DetectionResponse])
async def list_detections(
    limit: int = 100,
    offset: int = 0,
    db=Depends(get_db_session),
):
    """List all detections."""
    try:
        detections = detection_service.list_detections(
            db=db,
            limit=limit,
            offset=offset,
        )
        
        return [
            DetectionResponse(
                id=d.id,
                timestamp=d.timestamp,
                source=d.source.value,
                content=d.content,
                threat_score=d.threat_score.score,
                threat_level=d.threat_score.level.value,
                confidence=d.threat_score.confidence,
                action=d.action.value,
                notification_level=d.notification_level.value,
                explanation=d.explanation,
                indicators=[
                    {
                        "type": ind.type.value,
                        "value": ind.value,
                        "description": ind.description,
                    }
                    for ind in d.detected_indicators
                ],
            )
            for d in detections
        ]
    except Exception as e:
        logger.error(f"Failed to list detections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/detections/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: str,
    db=Depends(get_db_session),
):
    """Get a specific detection."""
    detection = detection_service.get_detection(detection_id, db)
    
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    return DetectionResponse(
        id=detection.id,
        timestamp=detection.timestamp,
        source=detection.source.value,
        content=detection.content,
        threat_score=detection.threat_score.score,
        threat_level=detection.threat_score.level.value,
        confidence=detection.threat_score.confidence,
        action=detection.action.value,
        notification_level=detection.notification_level.value,
        explanation=detection.explanation,
        indicators=[
            {
                "type": ind.type.value,
                "value": ind.value,
                "description": ind.description,
            }
            for ind in detection.detected_indicators
        ],
    )


@app.post("/api/v1/reports", response_model=ReportResponse)
async def create_report(
    request: ReportRequest,
    db=Depends(get_db_session),
):
    """Create a community threat report."""
    try:
        report = await report_service.create_report(
            indicator_hash=request.indicator_hash,
            threat_score=request.threat_score,
            indicator_type=request.indicator_type,
            source=request.source,
            db=db,
        )
        
        return ReportResponse(
            id=report.id,
            hash=report.hash,
            threat_score=report.threat_score,
            timestamp=report.timestamp,
            source=report.source.value,
            indicator_type=report.indicator_type.value,
            report_count=1,
        )
    except Exception as e:
        logger.error(f"Failed to create report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/reports", response_model=List[ReportResponse])
async def list_reports(
    limit: int = 100,
    db=Depends(get_db_session),
):
    """List community reports."""
    try:
        reports = report_service.list_reports(db=db, limit=limit)
        
        result_reports = []
        for r in reports:
            count = report_service.get_report_count(r.hash, db)
            result_reports.append(
                ReportResponse(
                    id=r.id,
                    hash=r.hash,
                    threat_score=r.threat_score,
                    timestamp=r.timestamp,
                    source=r.source.value,
                    indicator_type=r.indicator_type.value,
                    report_count=count,
                )
            )
        
        return result_reports
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats", response_model=StatsResponse)
async def get_stats(db=Depends(get_db_session)):
    """Get detection statistics."""
    try:
        stats = detection_service.get_statistics(db)
        
        return StatsResponse(**stats)
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
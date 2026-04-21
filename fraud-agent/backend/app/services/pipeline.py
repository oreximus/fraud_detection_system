"""Pipeline wrapper for the backend."""
from ml.models.detection_pipeline import (
    DetectionPipeline as Pipeline,
    create_pipeline as create_detection_pipeline,
)

DetectionPipeline = Pipeline
create_pipeline = create_detection_pipeline
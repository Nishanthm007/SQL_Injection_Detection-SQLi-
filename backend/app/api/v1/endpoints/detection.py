"""
Detection endpoint for SQL injection analysis.
Handles /api/v1/detect and related endpoints with database logging.
"""

import asyncio
import logging
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional

from app.models.schemas import (
    DetectionRequest,
    DetectionResponse,
    ErrorResponse,
    detection_result_to_response
)
from app.services.hybrid_detector import HybridDetector
from app.utils.model_loader import get_model_artifacts, ModelArtifacts
from app.core.config import settings
from app.db.database import get_db
from app.db import services as db_services
from app.utils.json_utils import sanitize_json  # Universal patch!

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/detect",
    tags=["Detection"],
    responses={
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)

_detector_instance = None

def get_detector() -> HybridDetector:
    global _detector_instance
    if _detector_instance is None:
        logger.info("Initializing HybridDetector...")
        artifacts = get_model_artifacts()
        _detector_instance = HybridDetector(artifacts)
        logger.info("HybridDetector initialized successfully")
    return _detector_instance

@router.post(
    "",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect SQL Injection",
    description="Analyzes a SQL query for injection attacks using hybrid CNN + rules detection."
)
async def detect_sql_injection(
    request: DetectionRequest,
    detector: HybridDetector = Depends(get_detector)
) -> JSONResponse:
    try:
        logger.info(f"Processing detection request: query_length={len(request.query)}")
        result = await detector.predict(query=request.query, metadata=request.metadata)
        response = detection_result_to_response(result)
        asyncio.create_task(db_services.log_attack_async(
            query=request.query,
            label=response.label,
            confidence=response.confidence,
            scores=response.scores,
            decision_source=response.decision_source,
            latency_ms=response.latency_ms,
            rule_matches=response.rule_matches,
            details=response.details or {},
            metadata=request.metadata
        ))
        logger.info(f"Detection complete: label={response.label}, source={response.decision_source}, latency={response.latency_ms}ms")
        # Universal patch
        return JSONResponse(content=sanitize_json(response.dict()))
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "ValidationError", "message": str(e)}
        )
    except Exception as e:
        logger.error(f"Detection error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "InternalServerError",
                    "message": "An error occurred during detection",
                    "detail": str(e) if settings.DEBUG else None}
        )

@router.get(
    "/info",
    summary="Get Detector Information",
    description="Returns detector configuration and model metadata"
)
async def get_detector_info(
    detector: HybridDetector = Depends(get_detector)
) -> JSONResponse:
    try:
        info = detector.get_detector_info()
        # Add model info from artifacts
        model_info = detector.artifacts.get_model_info()
        resp = {
            "detector": info,
            "model": model_info,
            "status": "operational"
        }
        return JSONResponse(content=sanitize_json(resp))
    except Exception as e:
        logger.error(f"Error fetching detector info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "InternalServerError", "message": str(e)}
        )

@router.get(
    "/attacks",
    summary="Get Recent Attacks",
    description="Returns recent attack logs from database"
)
def get_attacks(
    limit: int = 100,
    label: Optional[int] = None,
    db: Session = Depends(get_db)
) -> JSONResponse:
    attacks = db_services.get_recent_attacks(db, limit=limit, label_filter=label)
    resp = {
        "total": len(attacks),
        "attacks": [
            {
                "id": a.id,
                "query": a.query[:100] + "..." if len(a.query) > 100 else a.query,
                "label": a.label,
                "confidence": round(a.confidence, 4),
                "decision_source": a.decision_source,
                "rule_matches": a.rule_matches,
                "latency_ms": round(a.latency_ms, 2),
                "source_ip": a.source_ip,
                "detected_at": a.detected_at.isoformat() if a.detected_at else None
            }
            for a in attacks
        ]
    }
    return JSONResponse(content=sanitize_json(resp))

@router.get(
    "/stats",
    summary="Get Attack Statistics",
    description="Returns attack statistics for specified period"
)
def get_stats(
    days: int = 7,
    db: Session = Depends(get_db)
) -> JSONResponse:
    stats = db_services.get_attack_stats(db, days=days)
    top_patterns = db_services.get_top_attack_patterns(db, limit=5)
    stats["top_patterns"] = top_patterns
    return JSONResponse(content=sanitize_json(stats))

@router.post(
    "/batch",
    summary="Batch Detection (Future)",
    description="Batch detection endpoint - not yet implemented",
    status_code=status.HTTP_501_NOT_IMPLEMENTED
)
async def batch_detect(request: Dict[str, Any]) -> None:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"error": "NotImplemented",
                "message": "Batch detection endpoint not yet available"}
    )

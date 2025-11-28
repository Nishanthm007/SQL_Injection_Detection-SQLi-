"""
Detection endpoint for SQL injection analysis.
Handles /detect endpoints with database logging.
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

# NEW detector (YOUR updated model)
from app.services.detector import get_detector, HybridDetector

from app.core.config import settings
from app.db.database import get_db
from app.db import services as db_services
from app.utils.json_utils import sanitize_json  # Universal patch

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


# ------------------------------------------------------------
# DEPENDENCY: SINGLETON DETECTOR
# ------------------------------------------------------------
def detector_dependency() -> HybridDetector:
    """
    FastAPI-compatible dependency wrapper for get_detector().
    """
    from app.services.detector import get_detector
    return get_detector()


# ------------------------------------------------------------
# MAIN DETECTION ENDPOINT
# ------------------------------------------------------------
@router.post(
    "",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK
)
async def detect_sql_injection(
    request: DetectionRequest,
    detector: HybridDetector = Depends(detector_dependency),
    db: Session = Depends(get_db)
):
    try:
        logger.info(f"[DETECTION] Query received (length={len(request.query)})")

        # NEW detector output
        result = detector.analyze(request.query)
        """
        result = {
            "query": ...
            "cnn_prob": float
            "rule_score": float
            "matched_rules": [...]
            "final_label": 0/1
            "decision": "ALLOW/BLOCK_STRONG/..."
        }
        """

        # Build correct response payload
        response_data = {
            "query": result["query"],
            "label": result["final_label"],
            "confidence": result["cnn_prob"],
            "scores": {
                "cnn": result["cnn_prob"],
                "rules": result["rule_score"]
            },
            "rule_matches": result["matched_rules"],
            "decision_source": result["decision"],
            "latency_ms": 0.0,  # optional — can calculate later
            "details": {}
        }

        # DB logging
        asyncio.create_task(
            db_services.log_attack_async(
                query=request.query,
                label=response_data["label"],
                confidence=response_data["confidence"],
                scores=response_data["scores"],
                decision_source=response_data["decision_source"],
                latency_ms=response_data["latency_ms"],
                rule_matches=response_data["rule_matches"],
                details=response_data["details"],
                metadata=request.metadata
            )
        )

        return JSONResponse(content=sanitize_json(response_data))

    except Exception as e:
        logger.error(f"[DETECTION ERROR]: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "InternalServerError",
                "message": "An internal error occurred during detection",
                "detail": str(e) if settings.DEBUG else None
            }
        )



# ------------------------------------------------------------
# DETECTOR INFO
# ------------------------------------------------------------
@router.get(
    "/info",
    summary="Get Detector Info",
    description="Returns detector configuration and model metadata."
)
async def get_detector_info(
    detector: HybridDetector = Depends(detector_dependency)
) -> JSONResponse:
    try:
        info = {
            "status": "operational",
            "detector": "HybridDetector",
            "cnn_model_loaded": True
        }

        return JSONResponse(content=sanitize_json(info))

    except Exception as e:
        logger.error(f"[INFO] Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "InternalServerError", "message": str(e)}
        )


# ------------------------------------------------------------
# GET RECENT ATTACK LOGS
# ------------------------------------------------------------
@router.get(
    "/attacks",
    summary="Get Recent Attacks",
    description="Fetch recent attack logs from database."
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
                "query": (a.query[:100] + "...") if len(a.query) > 100 else a.query,
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


# ------------------------------------------------------------
# GET ATTACK STATISTICS
# ------------------------------------------------------------
@router.get(
    "/stats",
    summary="Get Attack Statistics",
    description="Attack statistics for the last N days."
)
def get_stats(
    days: int = 7,
    db: Session = Depends(get_db)
) -> JSONResponse:

    stats = db_services.get_attack_stats(db, days=days)
    stats["top_patterns"] = db_services.get_top_attack_patterns(db, limit=5)

    return JSONResponse(content=sanitize_json(stats))


# ------------------------------------------------------------
# BATCH API (NOT IMPLEMENTED)
# ------------------------------------------------------------
@router.post(
    "/batch",
    summary="Batch Detection (Not Implemented)",
    status_code=status.HTTP_501_NOT_IMPLEMENTED
)
async def batch_detect(request: Dict[str, Any]) -> None:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"error": "NotImplemented",
                "message": "Batch detection not implemented yet"}
    )

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
    """
    Detection endpoint that uses the HybridDetector.
    Detector.analyze() can return slightly different shapes; this endpoint
    normalizes the output into a stable API payload and logs to DB asynchronously.
    """

    try:
        logger.info(f"[DETECTION] Query received (length={len(request.query)})")

        # call detector (synchronous analyze)
        result = detector.analyze(request.query)

        # ------------------------
        # Normalization / mapping
        # ------------------------
        # Accept multiple possible keys from detector.analyze()
        p_cnn = result.get("cnn_prob", result.get("p_cnn", result.get("scores", {}).get("p_cnn", 0.0)))
        p_rule = result.get("rule_score", result.get("p_rule", result.get("scores", {}).get("p_rule", 0.0)))
        fused = result.get("fused_score", result.get("fused", result.get("scores", {}).get("fused", 0.0)))

        # detector may return final_label as int or as string; normalize
        raw_final_label = result.get("final_label", result.get("label", None))
        raw_final_label_str = result.get("label_str", None)
        decision_source = result.get("decision", result.get("decision_source", "unknown"))
        matched_rules = result.get("matched_rules", result.get("rule_matches", []))
        latency_ms = result.get("latency_ms", None)
        details = result.get("details", {}) or {}

        # Normalize label_str to always be a readable string
        if isinstance(raw_final_label_str, str) and raw_final_label_str.strip():
            label_str = raw_final_label_str
        else:
            # derive from numeric label if present
            try:
                if int(raw_final_label) == 1:
                    label_str = "malicious"
                else:
                    # fallback to decision hint
                    dec = str(decision_source or "").lower()
                    label_str = "suspicious" if "susp" in dec else "benign"
            except Exception:
                dec = str(decision_source or "").lower()
                label_str = "suspicious" if "susp" in dec else "benign"

        # Normalize numeric values with fallbacks
        try:
            p_cnn_f = float(p_cnn or 0.0)
        except Exception:
            p_cnn_f = 0.0
        try:
            p_rule_f = float(p_rule or 0.0)
        except Exception:
            p_rule_f = 0.0
        try:
            fused_f = float(fused or 0.0)
        except Exception:
            fused_f = 0.0

        # Compute latency if missing using details
        if latency_ms is None:
            try:
                latency_ms = float(details.get("cnn_latency_ms", 0.0) or 0.0) + float(details.get("rule_latency_ms", 0.0) or 0.0)
            except Exception:
                latency_ms = 0.0

        # Final integer label (DB-friendly)
        try:
            label_int = 1 if int(raw_final_label) == 1 else 0
        except Exception:
            label_int = 1 if "mal" in str(label_str).lower() else 0

        # Ensure details latencies are numeric (DB writer expects floats, not None)
        cnn_latency_val = float(details.get("cnn_latency_ms", result.get("cnn_latency_ms", 0.0) or 0.0))
        rule_latency_val = float(details.get("rule_latency_ms", result.get("rule_latency_ms", 0.0) or 0.0))
        raw_model_out_val = float(details.get("raw_model_output", result.get("raw_model_output", 0.0) or 0.0))
        timeout_occurred = bool(details.get("timeout_occurred", result.get("timeout_occurred", False)))

        # Build API response — keep stable keys expected by clients
        response_data = {
            "query": result.get("query", request.query),
            "label": int(label_int),
            "label_str": str(label_str),
            # keep modern keys (p_cnn/p_rule) for clients
            "scores": {
                "p_cnn": round(p_cnn_f, 4),
                "p_rule": round(p_rule_f, 4),
                "fused": round(fused_f, 4),
                # legacy-friendly aliases for DB writer / older consumers
                "cnn": round(p_cnn_f, 4),
                "rules": round(p_rule_f, 4)
            },
            # keep top-level convenience fields too (legacy)
            "p_cnn": round(p_cnn_f, 4),
            "p_rule": round(p_rule_f, 4),
            "fused": round(fused_f, 4),
            "decision": str(decision_source),
            "rule_matches": matched_rules or [],
            "latency_ms": round(float(latency_ms or 0.0), 3),
            "details": {
                "cnn_latency_ms": round(cnn_latency_val, 3),
                "rule_latency_ms": round(rule_latency_val, 3),
                "raw_model_output": raw_model_out_val,
                "timeout_occurred": timeout_occurred
            }
        }

        # Fire-and-forget DB logging. log_attack_async signature:
        # async def log_attack_async(query, label, confidence, scores, decision_source, latency_ms, rule_matches, details, metadata=None)
        try:
            log_payload = {
                "query": request.query,
                "label": response_data["label"],
                "confidence": response_data["scores"]["p_cnn"],
                "scores": {
                    # pass legacy keys expected by DB layer
                    "cnn": response_data["scores"]["cnn"],
                    "rules": response_data["scores"]["rules"],
                    "fused": response_data["scores"]["fused"]
                },
                "decision_source": response_data["decision"],
                "latency_ms": response_data["latency_ms"],
                "rule_matches": response_data["rule_matches"],
                # details as DB expects
                "details": {
                    "cnn_latency_ms": response_data["details"]["cnn_latency_ms"],
                    "rule_latency_ms": response_data["details"]["rule_latency_ms"],
                    "raw_model_output": response_data["details"]["raw_model_output"],
                    "timeout_occurred": response_data["details"]["timeout_occurred"]
                },
                "metadata": getattr(request, "metadata", None)
            }
            # do not await — non-blocking
            asyncio.create_task(db_services.log_attack_async(**log_payload))
        except Exception as log_err:
            # Logging should not block the response — print for ops
            logger.exception("[DETECTION] Failed to enqueue DB log: %s", log_err)

        # Return sanitized JSON response
        return JSONResponse(content=sanitize_json(response_data))

    except Exception as e:
        logger.exception(f"[DETECTION ERROR]: {e}")
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
    description="Fetch recent attack logs from database with pagination support."
)
def get_attacks(
    limit: int = 50,
    offset: int = 0,
    label: Optional[int] = None,
    db: Session = Depends(get_db)
) -> JSONResponse:

    attacks = db_services.get_recent_attacks(db, limit=limit, offset=offset, label_filter=label)
    total = db_services.get_total_attack_count(db, label_filter=label)

    resp = {
        "total": total,
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

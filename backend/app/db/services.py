"""
Database service functions for logging and queries.
Async-compatible for non-blocking operations.
"""

import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
import hashlib
import logging
import traceback

from app.db.models import AttackLog, PerformanceMetric, FeedbackLog
from app.db.database import get_db_context

logger = logging.getLogger(__name__)


def hash_query(query: str) -> str:
    """Generate SHA256 hash of query for deduplication"""
    return hashlib.sha256(query.encode()).hexdigest()


# ---------------------------
# Async logging entrypoint
# ---------------------------
async def log_attack_async(**kwargs):
    """
    Flexible async logger entrypoint.

    Accepts either:
      - old signature (query, label, confidence, scores, decision_source, latency_ms, rule_matches, details, metadata)
      - OR new signature (query, label, label_str, fused_score, cnn_score, rule_score, decision_source,
                        rule_matches, latency_ms, meta, metadata)

    This function normalizes the inputs and delegates to the sync writer executed in a thread pool.
    """
    # Run database write in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _log_attack_sync_normalized, kwargs)


def _log_attack_sync_normalized(kwargs: Dict[str, Any]):
    """
    Normalize kwargs and call the lower-level sync writer.
    Designed to be safe to run in a thread from run_in_executor.
    """
    try:
        # Normalize high-level fields with fallbacks for old/new key names
        query = kwargs.get("query") or kwargs.get("q") or ""
        label = kwargs.get("label")
        label_str = kwargs.get("label_str") or kwargs.get("labelString") or None

        # Scores: either given as a dict or as separate keys
        scores_arg = kwargs.get("scores")  # old style
        # new-style individual score fields
        fused_score = kwargs.get("fused_score", kwargs.get("fused", None))
        cnn_score = kwargs.get("cnn_score", kwargs.get("p_cnn", kwargs.get("cnn_score", None)))
        rule_score = kwargs.get("rule_score", kwargs.get("p_rule", kwargs.get("rules_score", kwargs.get("rule_score", None))))

        # If old 'scores' dict provided, prefer those values when present
        if isinstance(scores_arg, dict):
            cnn_score = cnn_score if cnn_score is not None else scores_arg.get("cnn")
            rule_score = rule_score if rule_score is not None else scores_arg.get("rules")
            fused_score = fused_score if fused_score is not None else scores_arg.get("fused")

        # Confidence: old callers passed 'confidence' - keep for backward compat
        confidence = kwargs.get("confidence", None)
        if confidence is None:
            # if fused present and confidence missing, set confidence to fused_score as approximation
            confidence = fused_score if fused_score is not None else cnn_score if cnn_score is not None else 0.0

        decision_source = kwargs.get("decision_source", kwargs.get("decision", kwargs.get("decisionSource", None)))
        latency_ms = kwargs.get("latency_ms", kwargs.get("latency", kwargs.get("latencyMs", 0.0)))

        # rule matches / meta / details
        rule_matches = kwargs.get("rule_matches", kwargs.get("rule_matches", kwargs.get("ruleMatches", []))) or []
        meta = kwargs.get("meta", kwargs.get("details", kwargs.get("details", {}))) or {}
        metadata = kwargs.get("metadata", None)

        # Build normalized scores dict for DB writer
        normalized_scores = {
            "cnn": float(cnn_score) if cnn_score is not None else None,
            "rules": float(rule_score) if rule_score is not None else 0.0,
            "fused": float(fused_score) if fused_score is not None else None
        }

        # Build normalized details dict
        normalized_details = {
            "cnn_latency_ms": meta.get("cnn_latency_ms") if isinstance(meta, dict) else None,
            "rule_latency_ms": meta.get("rule_latency_ms") if isinstance(meta, dict) else None,
            "timeout_occurred": meta.get("timeout_occurred", False) if isinstance(meta, dict) else False,
            "raw_model_output": meta.get("raw_model_output") if isinstance(meta, dict) else None
        }

        # Ensure numeric types
        try:
            latency_ms = float(latency_ms) if latency_ms is not None else 0.0
        except Exception:
            latency_ms = 0.0

        try:
            label_int = int(label) if label is not None else (1 if str(label_str).lower() == "malicious" else 0)
        except Exception:
            label_int = 0

        # Final call to sync writer
        _log_attack_sync(
            query=query,
            label=label_int,
            confidence=float(confidence) if confidence is not None else 0.0,
            scores=normalized_scores,
            decision_source=decision_source or "unknown",
            latency_ms=latency_ms,
            rule_matches=rule_matches,
            details=normalized_details,
            metadata=metadata
        )
    except Exception as e:
        logger.error("[DB SERVICES] Exception in _log_attack_sync_normalized:\n%s\n%s", str(e), traceback.format_exc())


def _log_attack_sync(
    query: str,
    label: int,
    confidence: float,
    scores: Dict[str, Optional[float]],
    decision_source: str,
    latency_ms: float,
    rule_matches: List[str],
    details: Dict[str, Any],
    metadata: Optional[Dict[str, Any]] = None
):
    """Synchronous database write (called from executor)"""
    try:
        # Defensive normalization of scores:
        # Support legacy and new key names that may be present depending on endpoint version
        def pick_score(*keys, default=0.0):
            for k in keys:
                if scores is None:
                    continue
                v = scores.get(k)
                if v is None:
                    continue
                try:
                    return float(v)
                except Exception:
                    continue
            return float(default)

        # Extract cnn / rule / fused with fallbacks
        cnn_val = pick_score("cnn", "p_cnn", "p_attack", "confidence", default=confidence or 0.0)
        rule_val = pick_score("rules", "p_rule", "rule_score", default=0.0)
        fused_val = pick_score("fused", "fused_score", default=(cnn_val * 0.0 + rule_val * 0.0))

        # Ensure details latencies are numeric and not None
        cnn_latency = 0.0
        rule_latency = 0.0
        try:
            if details:
                cnn_latency = float(details.get("cnn_latency_ms", details.get("cnn_latency", 0.0) or 0.0))
                rule_latency = float(details.get("rule_latency_ms", details.get("rule_latency", 0.0) or 0.0))
        except Exception:
            cnn_latency = 0.0
            rule_latency = 0.0

        timeout_flag = bool(details.get("timeout_occurred", False)) if details else False

        with get_db_context() as db:
            attack_log = AttackLog(
                query=query,
                query_hash=hash_query(query),
                label=label,
                confidence=confidence,
                cnn_score=cnn_val,
                rule_score=rule_val,
                fused_score=fused_val,
                decision_source=decision_source,
                rule_matches=rule_matches if rule_matches else [],
                latency_ms=float(latency_ms or (cnn_latency + rule_latency) or 0.0),
                cnn_latency_ms=cnn_latency,
                rule_latency_ms=rule_latency,
                timeout_occurred=timeout_flag,
                source_ip=metadata.get("ip_address") if metadata else None,
                user_agent=metadata.get("user_agent") if metadata else None,
                request_metadata=metadata
            )
            db.add(attack_log)
            logger.debug(
                "Logged attack: label=%s, confidence=%.4f, cnn=%.4f, rules=%.4f, fused=%.4f, cnn_lat=%.3f, rule_lat=%.3f",
                label, confidence or 0.0, cnn_val, rule_val, fused_val, cnn_latency, rule_latency
            )
    except Exception as e:
        logger.error(f"Failed to log attack to database: {e}")




# ---------------------------
# Query helpers (unchanged)
# ---------------------------
def get_recent_attacks(
    db: Session,
    limit: int = 100,
    label_filter: Optional[int] = None
) -> List[AttackLog]:
    """
    Get recent attack logs.

    Args:
        db: Database session
        limit: Maximum number of records
        label_filter: Filter by label (0 or 1), None for all

    Returns:
        List of AttackLog objects
    """
    query = db.query(AttackLog)

    if label_filter is not None:
        query = query.filter(AttackLog.label == label_filter)

    return query.order_by(desc(AttackLog.detected_at)).limit(limit).all()


def get_attack_stats(db: Session, days: int = 7) -> Dict[str, Any]:
    """
    Get attack statistics for the last N days.

    Args:
        db: Database session
        days: Number of days to analyze

    Returns:
        Dict with statistics
    """
    cutoff = datetime.utcnow() - timedelta(days=days)

    total = db.query(func.count(AttackLog.id)).filter(
        AttackLog.detected_at >= cutoff
    ).scalar()

    attacks = db.query(func.count(AttackLog.id)).filter(
        AttackLog.detected_at >= cutoff,
        AttackLog.label == 1
    ).scalar()

    avg_latency = db.query(func.avg(AttackLog.latency_ms)).filter(
        AttackLog.detected_at >= cutoff
    ).scalar()

    timeouts = db.query(func.count(AttackLog.id)).filter(
        AttackLog.detected_at >= cutoff,
        AttackLog.timeout_occurred == True
    ).scalar()

    return {
        "total_requests": total or 0,
        "attacks_detected": attacks or 0,
        "attack_rate": round((attacks / total * 100), 2) if total else 0,
        "avg_latency_ms": round(float(avg_latency), 2) if avg_latency else 0,
        "timeout_count": timeouts or 0,
        "period_days": days
    }


def get_top_attack_patterns(db: Session, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get most common attack patterns.

    Args:
        db: Database session
        limit: Number of patterns to return

    Returns:
        List of dicts with query_hash, count, sample_query
    """
    results = db.query(
        AttackLog.query_hash,
        func.count(AttackLog.id).label('count'),
        func.min(AttackLog.query).label('sample_query')
    ).filter(
        AttackLog.label == 1
    ).group_by(
        AttackLog.query_hash
    ).order_by(
        desc('count')
    ).limit(limit).all()

    return [
        {
            "query_hash": r.query_hash,
            "count": r.count,
            "sample_query": r.sample_query[:100] + "..." if len(r.sample_query) > 100 else r.sample_query
        }
        for r in results
    ]

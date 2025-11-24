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

from app.db.models import AttackLog, PerformanceMetric, FeedbackLog
from app.db.database import get_db_context

logger = logging.getLogger(__name__)


def hash_query(query: str) -> str:
    """Generate SHA256 hash of query for deduplication"""
    return hashlib.sha256(query.encode()).hexdigest()


async def log_attack_async(
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
    """
    Log attack detection asynchronously (non-blocking).
    
    Args:
        query: SQL query string
        label: Detection label (0 or 1)
        confidence: Confidence score
        scores: Dict with cnn, rules, fused scores
        decision_source: 'hybrid' or 'rules_fallback'
        latency_ms: Total detection time
        rule_matches: List of matched rule names
        details: Dict with cnn_latency_ms, rule_latency_ms, timeout_occurred
        metadata: Optional request metadata (IP, user agent, etc.)
    """
    # Run database write in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        _log_attack_sync,
        query, label, confidence, scores, decision_source,
        latency_ms, rule_matches, details, metadata
    )


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
        with get_db_context() as db:
            attack_log = AttackLog(
                query=query,
                query_hash=hash_query(query),
                label=label,
                confidence=confidence,
                cnn_score=scores.get("cnn"),
                rule_score=scores.get("rules", 0.0),
                fused_score=scores.get("fused"),
                decision_source=decision_source,
                rule_matches=rule_matches if rule_matches else [],
                latency_ms=latency_ms,
                cnn_latency_ms=details.get("cnn_latency_ms"),
                rule_latency_ms=details.get("rule_latency_ms"),
                timeout_occurred=details.get("timeout_occurred", False),
                source_ip=metadata.get("ip_address") if metadata else None,
                user_agent=metadata.get("user_agent") if metadata else None,
                request_metadata=metadata
            )
            db.add(attack_log)
            logger.debug(f"Logged attack: label={label}, confidence={confidence:.3f}")
    except Exception as e:
        logger.error(f"Failed to log attack to database: {e}")


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

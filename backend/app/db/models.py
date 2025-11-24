"""
SQLAlchemy ORM models for database tables.
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from datetime import datetime

from app.db.database import Base


class AttackLog(Base):
    """
    Logs all detected SQL injection attacks.
    """
    __tablename__ = "attack_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Query details
    query = Column(Text, nullable=False)
    query_hash = Column(String(64), index=True)  # SHA256 for deduplication
    
    # Detection results
    label = Column(Integer, nullable=False)  # 0 = benign, 1 = attack
    confidence = Column(Float, nullable=False)
    
    # Scores breakdown
    cnn_score = Column(Float, nullable=True)
    rule_score = Column(Float, nullable=False)
    fused_score = Column(Float, nullable=True)
    
    # Decision metadata
    decision_source = Column(String(50), nullable=False)  # 'hybrid' or 'rules_fallback'
    rule_matches = Column(JSON, nullable=True)  # List of matched rule names
    
    # Performance metrics
    latency_ms = Column(Float, nullable=False)
    cnn_latency_ms = Column(Float, nullable=True)
    rule_latency_ms = Column(Float, nullable=True)
    timeout_occurred = Column(Boolean, default=False)
    
    # Request metadata
    source_ip = Column(String(45), nullable=True, index=True)  # IPv4/IPv6
    user_agent = Column(String(500), nullable=True)
    request_metadata = Column(JSON, nullable=True)
    
    # Timestamps
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<AttackLog(id={self.id}, label={self.label}, confidence={self.confidence:.3f})>"


class PerformanceMetric(Base):
    """
    Tracks API performance metrics over time.
    """
    __tablename__ = "performance_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Request identification
    endpoint = Column(String(100), nullable=False, index=True)
    
    # Latency breakdown
    total_latency_ms = Column(Float, nullable=False)
    detection_latency_ms = Column(Float, nullable=True)
    db_latency_ms = Column(Float, nullable=True)
    
    # Resource usage
    memory_mb = Column(Float, nullable=True)
    cpu_percent = Column(Float, nullable=True)
    
    # Status
    status_code = Column(Integer, nullable=False)
    error_occurred = Column(Boolean, default=False)
    error_type = Column(String(100), nullable=True)
    
    # Timestamp
    recorded_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<Metric(endpoint={self.endpoint}, latency={self.total_latency_ms:.2f}ms)>"


class FeedbackLog(Base):
    """
    Stores human feedback on predictions for model improvement.
    """
    __tablename__ = "feedback_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Reference to original detection
    attack_log_id = Column(Integer, nullable=True, index=True)
    query = Column(Text, nullable=False)
    
    # Original prediction
    original_label = Column(Integer, nullable=False)
    original_confidence = Column(Float, nullable=False)
    
    # Human correction
    corrected_label = Column(Integer, nullable=False)  # 0 or 1
    feedback_type = Column(String(50), nullable=False)  # 'false_positive', 'false_negative', 'correct'
    
    # Reviewer details
    reviewer = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<Feedback(id={self.id}, type={self.feedback_type})>"

"""
Pydantic schemas for API request/response validation.
Auto-generates OpenAPI documentation and ensures type safety.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime


# ============================================================
# DETECTION ENDPOINT SCHEMAS
# ============================================================

class DetectionRequest(BaseModel):
    """
    Request schema for SQL injection detection.
    
    Example:
        {
            "query": "SELECT * FROM users WHERE id = 1 OR 1=1",
            "metadata": {
                "user_agent": "Mozilla/5.0...",
                "ip_address": "192.168.1.1"
            }
        }
    """
    
    query: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="SQL query string to analyze",
        examples=["SELECT * FROM users WHERE id = 1"]
    )
    
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional metadata (user agent, IP, session ID, etc.)"
    )
    
    @field_validator('query')
    @classmethod
    def query_not_empty(cls, v: str) -> str:
        """Validate query is not just whitespace"""
        if not v or not v.strip():
            raise ValueError("Query cannot be empty or whitespace only")
        return v.strip()
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "query": "SELECT * FROM users WHERE id = 1",
                    "metadata": {
                        "user_agent": "Mozilla/5.0",
                        "ip_address": "192.168.1.100"
                    }
                }
            ]
        }
    }


class DetectionResponse(BaseModel):
    """
    Response schema for detection results.
    
    Example:
        {
            "label": 1,
            "prediction": "attack",
            "confidence": 0.85,
            "scores": {
                "cnn": 0.92,
                "rules": 0.65,
                "fused": 0.85
            },
            "decision_source": "hybrid",
            "latency_ms": 45.3,
            "rule_matches": ["Tautology OR 1=1", "Comment-Based Evasion"],
            "timestamp": "2025-11-24T17:47:00Z"
        }
    """
    
    label: int = Field(
        ...,
        ge=0,
        le=1,
        description="Binary label: 0 = benign, 1 = attack"
    )
    
    prediction: str = Field(
        ...,
        description="Human-readable prediction: 'benign' or 'attack'"
    )
    
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall confidence score (0-1)"
    )
    
    scores: Dict[str, Optional[float]] = Field(
        ...,
        description="Individual model scores (cnn, rules, fused)"
    )
    
    decision_source: str = Field(
        ...,
        description="Detection source: 'hybrid' or 'rules_fallback'"
    )
    
    latency_ms: float = Field(
        ...,
        gt=0,
        description="Total detection latency in milliseconds"
    )
    
    rule_matches: List[str] = Field(
        default_factory=list,
        description="List of matched rule names"
    )
    
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="Response timestamp (ISO 8601 UTC)"
    )
    
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional debug information (optional)"
    )


# ============================================================
# HEALTH CHECK SCHEMAS
# ============================================================

class HealthResponse(BaseModel):
    """
    Health check response.
    
    Example:
        {
            "status": "healthy",
            "timestamp": "2025-11-24T17:47:00Z",
            "version": "1.0.0",
            "uptime_seconds": 3600
        }
    """
    
    status: str = Field(
        ...,
        description="Service status: 'healthy' or 'unhealthy'"
    )
    
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    
    version: str = Field(
        ...,
        description="API version"
    )
    
    uptime_seconds: Optional[float] = Field(
        default=None,
        description="Service uptime in seconds"
    )
    
    components: Optional[Dict[str, str]] = Field(
        default=None,
        description="Component health status"
    )


# ============================================================
# MODEL INFO SCHEMAS
# ============================================================

class ModelInfoResponse(BaseModel):
    """
    Model metadata response.
    
    Example:
        {
            "model_version": "1.0.0",
            "model_type": "tf_savedmodel",
            "accuracy": 0.9988,
            "threshold": 0.5,
            "rule_count": 74
        }
    """
    
    model_version: str = Field(..., description="Model version")
    model_type: str = Field(..., description="Model format")
    accuracy: Optional[float] = Field(None, description="Test accuracy")
    f1_score: Optional[float] = Field(None, description="Test F1 score")
    precision: Optional[float] = Field(None, description="Test precision")
    recall: Optional[float] = Field(None, description="Test recall")
    threshold: float = Field(..., description="Classification threshold")
    rule_count: int = Field(..., description="Number of loaded rules")
    fusion_weights: Dict[str, float] = Field(..., description="CNN/Rule weights")


# ============================================================
# EXPLAINABILITY SCHEMAS
# ============================================================

class ExplainRequest(BaseModel):
    """
    Request schema for model explainability.
    
    Example:
        {
            "query": "SELECT * FROM users WHERE id = 1 OR 1=1",
            "method": "shap"
        }
    """
    
    query: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="SQL query to explain"
    )
    
    method: str = Field(
        default="rules",
        description="Explanation method: 'rules' or 'shap'"
    )
    
    @field_validator('method')
    @classmethod
    def valid_method(cls, v: str) -> str:
        """Validate explanation method"""
        allowed = ["rules", "shap", "lime"]
        if v.lower() not in allowed:
            raise ValueError(f"Method must be one of: {allowed}")
        return v.lower()


class ExplainResponse(BaseModel):
    """
    Response schema for explainability.
    
    Example:
        {
            "query": "SELECT * FROM users WHERE id = 1 OR 1=1",
            "prediction": "attack",
            "explanation": {
                "matched_rules": [...],
                "feature_importance": {...}
            }
        }
    """
    
    query: str = Field(..., description="Original query")
    prediction: str = Field(..., description="Prediction label")
    confidence: float = Field(..., description="Prediction confidence")
    
    explanation: Dict[str, Any] = Field(
        ...,
        description="Explanation details"
    )
    
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )


# ============================================================
# ERROR SCHEMAS
# ============================================================

class ErrorResponse(BaseModel):
    """
    Standard error response.
    
    Example:
        {
            "error": "ValidationError",
            "message": "Query exceeds maximum length",
            "detail": {...},
            "timestamp": "2025-11-24T17:47:00Z"
        }
    """
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    detail: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )


# ============================================================
# BATCH DETECTION SCHEMAS (Optional - for future)
# ============================================================

class BatchDetectionRequest(BaseModel):
    """
    Request schema for batch detection.
    
    Example:
        {
            "queries": [
                "SELECT * FROM users",
                "SELECT * FROM users WHERE id = 1 OR 1=1"
            ]
        }
    """
    
    queries: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of SQL queries (max 100)"
    )
    
    @field_validator('queries')
    @classmethod
    def validate_queries(cls, v: List[str]) -> List[str]:
        """Validate each query in batch"""
        if not v:
            raise ValueError("Queries list cannot be empty")
        
        for i, query in enumerate(v):
            if not query or not query.strip():
                raise ValueError(f"Query at index {i} is empty")
            if len(query) > 4096:
                raise ValueError(f"Query at index {i} exceeds max length")
        
        return [q.strip() for q in v]


class BatchDetectionResponse(BaseModel):
    """
    Response schema for batch detection.
    
    Example:
        {
            "results": [
                {"label": 0, "prediction": "benign", ...},
                {"label": 1, "prediction": "attack", ...}
            ],
            "total": 2,
            "total_latency_ms": 120.5
        }
    """
    
    results: List[DetectionResponse] = Field(
        ...,
        description="Detection results for each query"
    )
    
    total: int = Field(..., description="Total number of queries processed")
    
    total_latency_ms: float = Field(
        ...,
        description="Total processing time in milliseconds"
    )
    
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def detection_result_to_response(result: Dict[str, Any]) -> DetectionResponse:
    """
    Convert hybrid detector result to API response schema.
    
    Args:
        result: Dict from HybridDetector.predict()
    
    Returns:
        DetectionResponse: Validated response object
    """
    return DetectionResponse(
        label=result['label'],
        prediction="attack" if result['label'] == 1 else "benign",
        confidence=result.get('fused_score') or result.get('p_rule', 0.0),
        scores={
            "cnn": result.get('p_cnn'),
            "rules": result.get('p_rule'),
            "fused": result.get('fused_score')
        },
        decision_source=result['decision_source'],
        latency_ms=result['latency_ms'],
        rule_matches=result.get('rule_matches', []),
        details={
            "cnn_latency_ms": result.get('cnn_latency_ms'),
            "rule_latency_ms": result.get('rule_latency_ms'),
            "timeout_occurred": result.get('timeout_occurred', False)
        }
    )

"""
Core configuration module for Phase 8 API.
Loads paths to Phase 7 artifacts and environment variables.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings with automatic environment variable loading.
    All paths are computed relative to project root—no hardcoding.
    """
    
    # ============================================================
    # PROJECT STRUCTURE
    # ============================================================
    
    # Auto-detect project root (assumes backend/ is 1 level deep)
    PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent.parent
    
    # Phase 7 artifact directories
    MODELS_DIR: Path = PROJECT_ROOT / "models"
    RULES_DIR: Path = PROJECT_ROOT / "rules"
    DATA_DIR: Path = PROJECT_ROOT / "data"
    LOGS_DIR: Path = PROJECT_ROOT / "logs"
    
    # ============================================================
    # PHASE 7 ARTIFACTS (Critical paths)
    # ============================================================
    
    # CNN fusion model
    FUSION_MODEL_PATH: Path = MODELS_DIR / "fusion_model_best.h5"
    
    # Rule engine JSON
    RULES_JSON_PATH: Path = RULES_DIR / "rules_machine.json"
    
    # Metrics (contains threshold, version, etc.)
    METRICS_JSON_PATH: Path = MODELS_DIR / "hybrid_metrics_test.json"
    
    # Optional: Preprocessing artifacts (tokenizers, encoders, etc.)
    PREPROCESSOR_DIR: Optional[Path] = DATA_DIR / "processed"
    
    # ============================================================
    # API SETTINGS
    # ============================================================
    
    # API metadata
    API_TITLE: str = "SQL Injection Detection API"
    API_VERSION: str = "1.0.0"
    API_DESCRIPTION: str = "Hybrid CNN + Rules SQL Injection Detector (Phase 8)"
    
    # Server config
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # CORS settings
    CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:8000"]
    
    # ============================================================
    # MODEL SETTINGS (From Phase 7)
    # ============================================================
    
    # Fusion weights (from Phase 7 spec)
    CNN_WEIGHT: float = 0.7
    RULE_WEIGHT: float = 0.3
    
    # Default threshold (overridden by metrics.json if exists)
    DEFAULT_THRESHOLD: float = 0.5
    
    # CNN timeout for fallback (milliseconds)
    CNN_TIMEOUT_MS: int = 100
    
    # ============================================================
    # DATABASE SETTINGS (SQLite for MVP, PostgreSQL for prod)
    # ============================================================
    
    DATABASE_URL: str = f"sqlite:///{PROJECT_ROOT}/logs/attack_patterns.db"
    # For production: "postgresql://user:pass@host:5432/dbname"
    
    # Connection pool settings
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    
    # ============================================================
    # LOGGING SETTINGS
    # ============================================================
    
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Path = LOGS_DIR / "api.log"
    LOG_FORMAT: str = "json"  # "json" or "text"
    
    # ============================================================
    # SECURITY SETTINGS
    # ============================================================
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # API key (for production, use env var)
    API_KEY: Optional[str] = None
    
    # ============================================================
    # MONITORING & OBSERVABILITY
    # ============================================================
    
    # Enable Prometheus metrics endpoint
    ENABLE_METRICS: bool = True
    
    # Health check interval (seconds)
    HEALTH_CHECK_INTERVAL: int = 30
    
    class Config:
        """Pydantic config: load from .env file if exists"""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings singleton.
    Called once at startup, reused across requests.
    """
    settings = Settings()
    
    # Validation: Check critical paths exist
    critical_paths = {
        "Models directory": settings.MODELS_DIR,
        "Rules directory": settings.RULES_DIR,
        "Logs directory": settings.LOGS_DIR,
    }
    
    for name, path in critical_paths.items():
        if not path.exists():
            raise FileNotFoundError(
                f"{name} not found at {path}. "
                f"Ensure Phase 7 artifacts are in place."
            )
    
    return settings


# Convenience: Export singleton for easy import
settings = get_settings()


# ============================================================
# STARTUP VALIDATION FUNCTION
# ============================================================

def validate_phase7_artifacts() -> dict:
    """
    Validates all Phase 7 artifacts exist and are loadable.
    Returns dict with validation results.
    
    Called during API startup to fail-fast if artifacts missing.
    """
    results = {
        "valid": True,
        "errors": [],
        "artifacts": {}
    }
    
    artifacts_to_check = {
        "fusion_model": settings.FUSION_MODEL_PATH,
        "rules_json": settings.RULES_JSON_PATH,
        "metrics_json": settings.METRICS_JSON_PATH,
    }
    
    for name, path in artifacts_to_check.items():
        if path.exists():
            size_mb = path.stat().st_size / (1024 * 1024)
            results["artifacts"][name] = {
                "path": str(path),
                "exists": True,
                "size_mb": round(size_mb, 2)
            }
        else:
            results["valid"] = False
            results["errors"].append(f"Missing: {name} at {path}")
            results["artifacts"][name] = {
                "path": str(path),
                "exists": False,
                "size_mb": 0
            }
    
    return results


if __name__ == "__main__":
    """Test configuration loading"""
    print("="*60)
    print("CONFIGURATION TEST")
    print("="*60)
    print(f"Project Root: {settings.PROJECT_ROOT}")
    print(f"Models Dir: {settings.MODELS_DIR}")
    print(f"Fusion Model: {settings.FUSION_MODEL_PATH}")
    print(f"Rules JSON: {settings.RULES_JSON_PATH}")
    print(f"Database URL: {settings.DATABASE_URL}")
    print("\n" + "="*60)
    print("ARTIFACT VALIDATION")
    print("="*60)
    
    validation = validate_phase7_artifacts()
    
    if validation["valid"]:
        print("✓ All Phase 7 artifacts found")
        for name, info in validation["artifacts"].items():
            print(f"  • {name}: {info['size_mb']} MB")
    else:
        print("✗ Validation failed:")
        for error in validation["errors"]:
            print(f"  • {error}")

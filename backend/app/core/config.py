"""
Core configuration module for Phase 8 API.
Loads paths to Phase 7 artifacts and environment variables.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


def find_project_root() -> Path:
    """
    Walk up from this file until we find the root project directory.
    Looks for 'notebooks' and 'backend' folders as markers.
    """
    current = Path(__file__).resolve().parent
    
    # Walk up max 10 levels
    for _ in range(10):
        # Check if this is the root (has both notebooks and backend)
        if (current / "notebooks").exists() and (current / "backend").exists():
            return current
        
        parent = current.parent
        if parent == current:
            break
        current = parent
    
    raise FileNotFoundError(
        "Could not find project root. Ensure 'notebooks/' and 'backend/' "
        "folders exist in the same parent directory."
    )


class Settings(BaseSettings):
    """
    Application settings with automatic environment variable loading.
    All paths are computed relative to project root—no hardcoding.
    """
    
    # ============================================================
    # PROJECT STRUCTURE
    # ============================================================
    
    # Auto-detect project root
    PROJECT_ROOT: Path = find_project_root()
    
    # Phase 7 artifact directories (from notebooks)
    PHASE7_OUTPUTS_DIR: Path = PROJECT_ROOT / "notebooks" / "phase7a_results" / "hybrid_outputs"
    PHASE7_MODEL_DIR: Path = PROJECT_ROOT / "notebooks" / "phase7a_results" / "fusion_model_savedmodel"
    
    # Project-level directories
    RULES_DIR: Path = PROJECT_ROOT / "rules"
    DATA_DIR: Path = PROJECT_ROOT / "data"
    LOGS_DIR: Path = PROJECT_ROOT / "logs"
    NOTEBOOKS_DIR: Path = PROJECT_ROOT / "notebooks"
    
    # ============================================================
    # PHASE 7 ARTIFACTS (Critical paths - from notebooks)
    # ============================================================
    
    # CNN fusion model (TensorFlow SavedModel format - directory)
    FUSION_MODEL_PATH: Path = PHASE7_MODEL_DIR
    
    # Rule engine JSON (project root level)
    RULES_JSON_PATH: Path = RULES_DIR / "rules_merged.json"
    
    # Metrics (from Phase 7a outputs)
    METRICS_JSON_PATH: Path = PHASE7_OUTPUTS_DIR / "hybrid_metrics_test.json"
    
    # Optional: Preprocessing artifacts
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
    CNN_TIMEOUT_MS: int = 5000
    
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
    
    # Pydantic V2 config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings singleton.
    Called once at startup, reused across requests.
    """
    settings = Settings()
    
    # Validation: Check critical paths exist
    critical_paths = {
        "Phase 7 outputs directory": settings.PHASE7_OUTPUTS_DIR,
        "Phase 7 model directory": settings.PHASE7_MODEL_DIR,
        "Rules directory": settings.RULES_DIR,
        "Logs directory": settings.LOGS_DIR,
    }
    
    missing = []
    for name, path in critical_paths.items():
        if not path.exists():
            missing.append(f"{name}: {path}")
    
    if missing:
        print("\n[WARNING] Some directories are missing:")
        for item in missing:
            print(f"  - {item}")
        
        # Auto-create logs directory if missing
        if not settings.LOGS_DIR.exists():
            print("\nCreating logs directory...")
            settings.LOGS_DIR.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ Created: {settings.LOGS_DIR}")
    
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
    
    # Check for SavedModel directory (TensorFlow format)
    if settings.FUSION_MODEL_PATH.exists() and settings.FUSION_MODEL_PATH.is_dir():
        # Check for saved_model.pb inside
        pb_file = settings.FUSION_MODEL_PATH / "saved_model.pb"
        if pb_file.exists():
            # Calculate total size of SavedModel directory
            total_size = sum(
                f.stat().st_size 
                for f in settings.FUSION_MODEL_PATH.rglob("*") 
                if f.is_file()
            )
            size_mb = total_size / (1024 * 1024)
            
            results["artifacts"]["fusion_model"] = {
                "path": str(settings.FUSION_MODEL_PATH),
                "exists": True,
                "size_mb": round(size_mb, 2),
                "format": "TensorFlow SavedModel"
            }
        else:
            results["valid"] = False
            results["errors"].append(
                f"SavedModel directory found but missing saved_model.pb at {settings.FUSION_MODEL_PATH}"
            )
            results["artifacts"]["fusion_model"] = {
                "path": str(settings.FUSION_MODEL_PATH),
                "exists": False,
                "size_mb": 0,
                "format": "Unknown"
            }
    else:
        results["valid"] = False
        results["errors"].append(f"Fusion model not found at {settings.FUSION_MODEL_PATH}")
        results["artifacts"]["fusion_model"] = {
            "path": str(settings.FUSION_MODEL_PATH),
            "exists": False,
            "size_mb": 0,
            "format": "Unknown"
        }
    
    # Check other artifacts (rules, metrics)
    other_artifacts = {
        "rules_json": settings.RULES_JSON_PATH,
        "metrics_json": settings.METRICS_JSON_PATH,
    }
    
    for name, path in other_artifacts.items():
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
    print("\n" + "="*60)
    print("CONFIGURATION TEST")
    print("="*60)
    print(f"Project Root: {settings.PROJECT_ROOT}")
    print(f"Phase 7 Outputs: {settings.PHASE7_OUTPUTS_DIR}")
    print(f"Phase 7 Model Dir: {settings.PHASE7_MODEL_DIR}")
    print(f"Rules Dir: {settings.RULES_DIR}")
    print(f"Data Dir: {settings.DATA_DIR}")
    print(f"Logs Dir: {settings.LOGS_DIR}")
    print(f"\nFusion Model: {settings.FUSION_MODEL_PATH}")
    print(f"Rules JSON: {settings.RULES_JSON_PATH}")
    print(f"Metrics JSON: {settings.METRICS_JSON_PATH}")
    print(f"Database URL: {settings.DATABASE_URL}")
    
    print("\n" + "="*60)
    print("ARTIFACT VALIDATION")
    print("="*60)
    
    validation = validate_phase7_artifacts()
    
    if validation["valid"]:
        print("✓ All Phase 7 artifacts found\n")
        for name, info in validation["artifacts"].items():
            print(f"  • {name:20s}: {info['size_mb']:6.2f} MB")
            if "format" in info:
                print(f"    Format: {info['format']}")
            print(f"    Path: {info['path']}")
            print()
    else:
        print("✗ Validation failed:\n")
        for error in validation["errors"]:
            print(f"  • {error}")
        
        print("\n" + "="*60)
        print("DEBUGGING INFO")
        print("="*60)
        
        # Show what's actually in the model directory
        if settings.PHASE7_MODEL_DIR.exists():
            print(f"\nContents of {settings.PHASE7_MODEL_DIR}:")
            for item in sorted(settings.PHASE7_MODEL_DIR.rglob("*")):
                if item.is_file():
                    rel_path = item.relative_to(settings.PHASE7_MODEL_DIR)
                    size_kb = item.stat().st_size / 1024
                    print(f"  • {rel_path} ({size_kb:.1f} KB)")
        
        # Show what's in hybrid outputs
        if settings.PHASE7_OUTPUTS_DIR.exists():
            print(f"\nContents of {settings.PHASE7_OUTPUTS_DIR}:")
            for item in sorted(settings.PHASE7_OUTPUTS_DIR.glob("*")):
                if item.is_file():
                    size_kb = item.stat().st_size / 1024
                    print(f"  • {item.name} ({size_kb:.1f} KB)")

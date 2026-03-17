"""
Simplified configuration for Phase 8 SQLi API
(Compatible with NEW CNN + Rules Detector)
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


def find_project_root() -> Path:
    """
    Walk up from this file until we find the backend directory.
    """
    current = Path(__file__).resolve().parent

    for _ in range(10):
        if (current / "backend").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    raise FileNotFoundError("Project root not found.")


class Settings(BaseSettings):

    # ============================================================
    # PROJECT ROOT
    # ============================================================
    PROJECT_ROOT: Path = find_project_root()
    BACKEND_DIR: Path = PROJECT_ROOT / "backend"
    MODEL_TRAINING_DIR: Path = PROJECT_ROOT / "model_training"

    # ============================================================
    # MODEL (CNN + RULES)
    # ============================================================
    CNN_MODEL_PATH: Path = MODEL_TRAINING_DIR / "best_model.h5"
    VOCAB_PATH: Path = MODEL_TRAINING_DIR / "vocab.json"
    WORD_TYPES_PATH: Path = MODEL_TRAINING_DIR / "word_types.json"
    RULES_JSON_PATH: Path = PROJECT_ROOT / "rules" / "rules.json"

    # ============================================================
    # API SETTINGS
    # ============================================================
    API_TITLE: str = "SQLi Detector API"
    API_VERSION: str = "1.0.0"
    API_DESCRIPTION: str = "Hybrid CNN + Rules SQL Injection Detection API (Phase 8)"

    DEBUG: bool = True   # Enable full trace errors during development

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]

    # ============================================================
    # FUSION WEIGHTS (tuned)
    # ============================================================
    # Balanced weights between CNN and rules for hybrid detection
    CNN_WEIGHT: float = 0.55      # CNN provides learned pattern detection
    RULE_WEIGHT: float = 0.45     # Rules provide explicit attack signatures
    DEFAULT_THRESHOLD: float = 0.5

    # Additional thresholds used by detector code (kept for compatibility/tuning)
    FUSION_HIGH: float = 0.80
    FUSION_MED: float = 0.55

    # Safety overrides & decision parameters (used by detector)
    HIGH_CNN_BLOCK: float = 0.98  # Very high confidence threshold to avoid false positives
    HIGH_RULE_BLOCK: float = 0.75

    # Risky-rule and suspicious floors (used by detector tuning)
    RISKY_RULE_THRESHOLD: float = 0.30
    SUSPICIOUS_LOWER: float = 0.35

    # CNN timeout for fallback (ms)
    CNN_TIMEOUT_MS: int = 2000

    # ============================================================
    # DATABASE
    # ============================================================
    LOGS_DIR: Path = PROJECT_ROOT / "logs"
    DATABASE_URL: str = f"sqlite:///{PROJECT_ROOT}/logs/events.db"

    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10

    # ============================================================
    # LOGGING
    # ============================================================
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Path = LOGS_DIR / "api.log"

    # ============================================================
    # Pydantic
    # ============================================================
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )


@lru_cache()
def get_settings():
    s = Settings()

    # Ensure logs directory exists
    s.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Warn if model artifacts are missing
    missing = []
    for name, path in {
        "CNN_MODEL_PATH": s.CNN_MODEL_PATH,
        "VOCAB_PATH": s.VOCAB_PATH,
        "WORD_TYPES_PATH": s.WORD_TYPES_PATH
    }.items():
        if not path.exists():
            missing.append(f"{name} missing → {path}")

    if missing:
        print("\n[CONFIG WARNING]")
        for m in missing:
            print(" •", m)
        print("Check your model_training folder.\n")

    return s


# Export singleton
settings = get_settings()

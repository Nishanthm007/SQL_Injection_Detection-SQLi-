"""
FastAPI main application.
SQL Injection Detection API - Phase 8 (New CNN + Rules System)
"""

import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app.core.config import settings
from app.api.v1.endpoints import detection
from app.models.schemas import HealthResponse, ErrorResponse

app = FastAPI(
    title="SQLi Detector API",
    version="1.0.0",
)

# -----------------------------------------------------------
# LOGGING
# -----------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("app.main")


# ============================================================
# LIFESPAN STARTUP/SHUTDOWN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup & Shutdown for Phase-8 API."""
    logger.info("=" * 60)
    logger.info("SQL INJECTION DETECTION API (PHASE 8) - STARTING")
    logger.info("=" * 60)

    # ============================================================
    # 1. VALIDATE ALL REQUIRED FILES
    # ============================================================
    logger.info("Checking Phase-8 model + vocabulary...")

    if not settings.CNN_MODEL_PATH.exists():
        raise RuntimeError(f"Missing CNN model: {settings.CNN_MODEL_PATH}")

    if not settings.VOCAB_PATH.exists():
        raise RuntimeError(f"Missing vocab.json: {settings.VOCAB_PATH}")

    if not settings.WORD_TYPES_PATH.exists():
        raise RuntimeError(f"Missing word_types.json: {settings.WORD_TYPES_PATH}")

    logger.info("✓ Model + vocabulary verified")

    # ============================================================
    # 2. ⭐ PRELOAD MODEL + PREPROCESSOR + DETECTOR
    # ============================================================
    try:
        logger.info("[STARTUP] Preloading Preprocessor + CNN Model + Detector...")

        # IMPORTANT: import here only
        from app.utils.model_loader import get_model_loader
        from app.services.detector import get_detector

        # Load SINGLETON instances NOW (not during requests)
        _ = get_model_loader()   # loads best_model.h5 only once
        _ = get_detector()       # loads HybridDetector only once

        logger.info("✓ Detector and CNN model initialized successfully")

    except Exception as e:
        logger.error(f"FATAL: Detector initialization failed → {e}")
        raise

    # ============================================================
    # 3. OPTIONAL: DATABASE INITIALIZATION
    # ============================================================
    try:
        from app.db.database import init_db
        logger.info("Initializing database...")
        init_db()
        logger.info("✓ Database initialized")
    except Exception as e:
        logger.warning(f"[WARNING] Database init skipped/failed → {e}")

    # ============================================================
    # 4. MARK API AS READY
    # ============================================================
    app.state.startup_time = time.time()
    logger.info(f"API Version: {settings.API_VERSION}")
    logger.info(f"Debug Mode: {settings.DEBUG}")
    logger.info("=" * 60)
    logger.info("✓ API READY")
    logger.info("=" * 60)

    # ============================================================
    # YIELD TO SERVER
    # ============================================================
    yield

    # ============================================================
    # SHUTDOWN
    # ============================================================
    logger.info("=" * 60)
    logger.info("SQLI DETECTOR API - SHUTDOWN")
    logger.info("=" * 60)



# ============================================================
# CREATE APP
# ============================================================

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description=settings.API_DESCRIPTION,
    lifespan=lifespan,
)


# ============================================================
# MIDDLEWARE
# ============================================================

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# Logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    logger.info(f"→ {request.method} {request.url.path}")

    response = await call_next(request)

    duration = (time.time() - start) * 1000
    logger.info(f"← {request.method} {request.url.path} [{response.status_code}] {duration:.2f}ms")
    return response


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="ValidationError",
            message="Invalid request",
            detail=exc.errors()
        ).model_dump()
    )


@app.exception_handler(Exception)
async def global_error(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected error occurred",
            detail={"error": str(exc)} if settings.DEBUG else None
        ).model_dump()
    )




# ============================================================
# ROUTES
# ============================================================

@app.get("/", summary="API Root")
async def root():
    return {
        "status": "operational",
        "version": settings.API_VERSION,
        "endpoints": {
            "detect": "/api/v1/detect",
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health():
    uptime = time.time() - app.state.startup_time
    return HealthResponse(
        status="healthy",
        version=settings.API_VERSION,
        uptime_seconds=uptime,
        components={"model": "operational", "rules": "operational"}
    )


# Register the SQLi detection router
app.include_router(detection.router, prefix="/api/v1", tags=["Detection"])


# ============================================================
# DEV SERVER RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )

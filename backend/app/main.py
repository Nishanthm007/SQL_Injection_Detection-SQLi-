"""
FastAPI main application.
SQL Injection Detection API - Phase 8 Production Server.
"""

import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings, validate_phase7_artifacts
from app.api.v1.endpoints import detection
from app.models.schemas import HealthResponse, ErrorResponse


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================
# LIFESPAN CONTEXT MANAGER (Startup/Shutdown)
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("="*60)
    logger.info("SQL INJECTION DETECTION API - STARTING")
    logger.info("="*60)
    
    # Validate Phase 7 artifacts
    logger.info("Validating Phase 7 artifacts...")
    validation = validate_phase7_artifacts()
    
    if validation["valid"]:
        logger.info("✓ All Phase 7 artifacts validated")
        for name, info in validation["artifacts"].items():
            logger.info(f"  - {name}: {info['size_mb']} MB")
    else:
        logger.error("✗ Artifact validation failed:")
        for error in validation["errors"]:
            logger.error(f"  - {error}")
        raise RuntimeError("Cannot start API without required artifacts")
    
    # Initialize database
    logger.info("Initializing database...")
    from app.db.database import init_db
    init_db()
    
    # Store startup time
    app.state.startup_time = time.time()
    
    logger.info(f"API Version: {settings.API_VERSION}")
    logger.info(f"Host: {settings.HOST}:{settings.PORT}")
    logger.info(f"Debug Mode: {settings.DEBUG}")
    logger.info("="*60)
    logger.info("✓ API READY")
    logger.info("="*60)
    
    yield
    
    # Shutdown
    logger.info("="*60)
    logger.info("SQL INJECTION DETECTION API - SHUTTING DOWN")
    logger.info("="*60)


# ============================================================
# CREATE FASTAPI APP
# ============================================================

app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)


# ============================================================
# MIDDLEWARE
# ============================================================

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with timing"""
    start_time = time.time()
    
    # Log request
    logger.info(f"→ {request.method} {request.url.path}")
    
    # Process request
    response = await call_next(request)
    
    # Log response
    duration = (time.time() - start_time) * 1000
    logger.info(
        f"← {request.method} {request.url.path} "
        f"[{response.status_code}] {duration:.2f}ms"
    )
    
    return response


# ============================================================
# EXCEPTION HANDLERS
# ============================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors"""
    errors = exc.errors()
    
    logger.warning(f"Validation error on {request.url.path}: {errors}")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error="ValidationError",
            message="Request validation failed",
            detail={"errors": errors}
        ).model_dump()
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all uncaught exceptions"""
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected error occurred",
            detail=str(exc) if settings.DEBUG else None
        ).model_dump()
    )


# ============================================================
# ROOT ENDPOINTS
# ============================================================

@app.get(
    "/",
    summary="API Root",
    description="Returns API information and available endpoints"
)
async def root():
    """API root endpoint"""
    return {
        "name": settings.API_TITLE,
        "version": settings.API_VERSION,
        "description": settings.API_DESCRIPTION,
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "detect": "/api/v1/detect",
            "detector_info": "/api/v1/detect/info"
        },
        "status": "operational"
    }


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Returns service health status and uptime"
)
async def health_check():
    """Health check endpoint for monitoring"""
    uptime = time.time() - app.state.startup_time if hasattr(app.state, "startup_time") else None
    
    return HealthResponse(
        status="healthy",
        version=settings.API_VERSION,
        uptime_seconds=uptime,
        components={
            "model_loader": "operational",
            "detector": "operational",
            "database": "not_configured"
        }
    )


# ============================================================
# REGISTER ROUTERS
# ============================================================

app.include_router(
    detection.router,
    prefix="/api/v1",
    tags=["Detection"]
)


# ============================================================
# DEV SERVER (for testing only)
# ============================================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*60)
    print("STARTING DEVELOPMENT SERVER")
    print("="*60)
    print(f"API: {settings.API_TITLE} v{settings.API_VERSION}")
    print(f"Host: http://{settings.HOST}:{settings.PORT}")
    print(f"Docs: http://{settings.HOST}:{settings.PORT}/docs")
    print("="*60 + "\n")
    
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

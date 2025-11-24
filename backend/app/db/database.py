"""
Database configuration and session management.
Uses SQLite for development, easy PostgreSQL swap for production.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# Create SQLAlchemy engine
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    pool_pre_ping=True,
    echo=False  # Set True for SQL query logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()


def get_db() -> Session:
    """
    Dependency function for FastAPI endpoints.
    Provides database session with automatic cleanup.
    
    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database sessions outside FastAPI.
    
    Usage:
        with get_db_context() as db:
            db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """
    Initialize database tables.
    Called during application startup.
    """
    logger.info("Initializing database...")
    
    # Import models to register them with Base
    from app.db import models
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    logger.info(f"✓ Database initialized: {settings.DATABASE_URL}")
    
    # Log table names
    tables = Base.metadata.tables.keys()
    logger.info(f"  Tables created: {', '.join(tables)}")


def reset_db():
    """
    Drop and recreate all tables.
    WARNING: This deletes all data!
    """
    logger.warning("Resetting database (dropping all tables)...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    logger.info("✓ Database reset complete")

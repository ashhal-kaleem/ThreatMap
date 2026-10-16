"""
Database Configuration & Engine for ThreatMap Lite.
Module: Database + Pipeline + Report Management
Owner: Aqsa (Implemented with Ashhal integration support)

Supports:
- PostgreSQL with pgvector when DATABASE_URL is set (Production)
- SQLite fallback with JSON-compatible serialization (Local Development & Testing)
"""

import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Resolve default SQLite database path if DATABASE_URL is not set
BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_PATH = BACKEND_DIR / "threatmap.db"

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Use SQLite for local development and standalone testing
    DATABASE_URL = f"sqlite:///{DEFAULT_SQLITE_PATH}"

# Connect args specific to SQLite for multithreading
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency to yield database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

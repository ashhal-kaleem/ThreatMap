"""
ThreatMap Lite — FastAPI Application Entrypoint.
Module: ThreatMap Lite Application Backend
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import APP_VERSION, CORS_ORIGINS, MAX_UPLOAD_SIZE_MB
from backend.app.database import Base, engine
from backend.app.routers import reports

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Auto-create tables for SQLite / local development if not already present
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ThreatMap Lite API",
    description="Deterministic PDF & IOC Intelligence and Threat Extraction API",
    version=APP_VERSION,
)

# Configure CORS for local React/Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(reports.router)


@app.get("/health", tags=["system"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "ok",
        "service": "threatmap-lite-backend",
        "version": APP_VERSION,
        "max_upload_mb": MAX_UPLOAD_SIZE_MB,
    }

"""
ThreatMap Lite — FastAPI Application Entrypoint.
Module: ThreatMap Lite Application Backend
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
    version="1.2.0",
)

# Configure CORS for local React/Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(reports.router)


@app.get("/health", tags=["system"])
def health_check():
    """System health check endpoint."""
    return {"status": "ok", "service": "threatmap-lite-backend", "version": "1.2.0"}

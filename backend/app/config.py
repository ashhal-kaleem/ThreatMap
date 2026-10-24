"""
Central runtime configuration for ThreatMap Lite, read from environment / backend/.env.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

APP_VERSION = "1.2.0"

# Maximum accepted upload size in megabytes (shared with the frontend via /health)
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))

# Comma-separated list of allowed browser origins for CORS
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if o.strip()
]

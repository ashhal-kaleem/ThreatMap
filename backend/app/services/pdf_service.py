"""
PDF Processing Service for ThreatMap Lite.
Module: PDF Processing & IOC Intelligence

Responsibilities:
- Validate PDF files (%PDF- magic bytes, 50MB file size limit).
- Sanitize filenames to prevent path traversal.
- Store uploaded files in the private backend/uploads/ directory.
- Extract page-by-page text using PyMuPDF in an isolated subprocess with a 120s timeout.
- Gracefully handle corrupted, password-protected, empty, and scanned/image-only PDFs.
"""

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional, TypedDict

# Global Configuration
MAGIC_BYTES = b"%PDF-"
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_TIMEOUT_SECONDS = 120

# Directory paths
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent.parent
DEFAULT_UPLOADS_DIR = BACKEND_DIR / "uploads"
WORKER_SCRIPT = CURRENT_DIR / "pdf_worker.py"


class PageText(TypedDict):
    page_number: int
    page_text: str  # Matches report_pages.page_text schema
    text: str       # Alias for backward compatibility


def validate_pdf_bytes(content: bytes) -> None:
    """
    Validates in-memory PDF binary content.
    Enforces the 50MB limit and validates the %PDF- magic bytes header.
    Raises ValueError on violation.
    """
    if not content:
        raise ValueError("Uploaded file is empty.")

    if len(content) > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File size ({len(content)} bytes) exceeds the maximum allowed limit of 50MB "
            f"({MAX_FILE_SIZE_BYTES} bytes)."
        )

    if not content.startswith(MAGIC_BYTES):
        raise ValueError("Invalid file format: missing %PDF- magic bytes.")


def validate_pdf_file(path: Path | str) -> Path:
    """
    Validates a file on disk before processing.
    Ensures the file exists, is within the size limit, and begins with %PDF-.
    """
    file_path = Path(path).resolve()
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = file_path.stat().st_size
    if file_size == 0:
        raise ValueError("File is empty (0 bytes).")

    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File size ({file_size} bytes) exceeds the maximum allowed limit of 50MB."
        )

    with open(file_path, "rb") as f:
        header = f.read(5)
        if header != MAGIC_BYTES:
            raise ValueError("Invalid file format: missing %PDF- magic bytes.")

    return file_path


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes uploaded filenames to prevent path traversal attacks and filesystem corruption.
    - Extracts only the base name using pathlib.Path.
    - Strips directory separators, null bytes, and traversal patterns (..).
    - Prevents Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
    - Preserves safe alphanumeric characters, underscores, dashes, and periods.
    - Ensures the filename ends with .pdf.
    """
    if not filename or not filename.strip():
        return f"report_{uuid.uuid4().hex[:8]}.pdf"

    # Extract base name to strip any relative or absolute paths
    base_name = Path(filename).name

    # Remove null bytes and control characters
    base_name = re.sub(r"[\x00-\x1f\x7f]", "", base_name)

    # Remove path traversal tokens
    base_name = base_name.replace("..", "").replace("/", "").replace("\\", "").strip()

    # Replace spaces and unusual characters with underscores
    base_name = re.sub(r"[^\w.\-]", "_", base_name)

    # Strip leading dots or hyphens
    base_name = re.sub(r"^[.\-_]+", "", base_name)

    # Prevent Windows reserved device names
    stem = Path(base_name).stem.upper()
    reserved_names = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
    if stem in reserved_names:
        base_name = f"safe_{base_name}"

    if not base_name or base_name == ".pdf":
        base_name = f"report_{uuid.uuid4().hex[:8]}.pdf"

    # Ensure .pdf extension
    if not base_name.lower().endswith(".pdf"):
        base_name = f"{base_name}.pdf"

    return base_name


def save_upload_file(
    file_content: bytes,
    filename: str,
    upload_dir: Optional[Path] = None,
) -> Path:
    """
    Validates, sanitizes, and writes uploaded PDF bytes into the private uploads directory.
    Prepends a unique UUID to prevent file collisions.
    Returns the resolved absolute path to the stored PDF file.
    """
    validate_pdf_bytes(file_content)

    target_dir = upload_dir or DEFAULT_UPLOADS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    clean_filename = sanitize_filename(filename)
    unique_prefix = uuid.uuid4().hex[:12]
    destination_path = target_dir / f"{unique_prefix}_{clean_filename}"

    with open(destination_path, "wb") as f:
        f.write(file_content)

    return destination_path.resolve()


def extract_pages(
    pdf_path: Path | str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[PageText]:
    """
    Extracts text page by page from a validated PDF using PyMuPDF in an isolated subprocess.
    Enforces a strict timeout (default 120 seconds).
    
    Returns:
        list[PageText]: A list of dicts with 1-based page_number and extracted text.
        
    Raises:
        FileNotFoundError: If the PDF does not exist.
        ValueError: If the file is not a valid PDF, corrupted, password protected, empty,
                    or contains no extractable text.
        TimeoutError: If subprocess extraction exceeds the configured timeout.
    """
    validated_path = validate_pdf_file(pdf_path)

    # Prepare subprocess execution
    cmd = [sys.executable, str(WORKER_SCRIPT), str(validated_path)]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR.parent)

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"PDF text extraction timed out after {timeout} seconds for {validated_path.name}"
        ) from exc
    except Exception as exc:
        raise ValueError(f"Failed to execute PDF extraction worker: {str(exc)}") from exc

    raw_stdout = process.stdout.strip()

    if not raw_stdout:
        err = process.stderr.strip() or "No output returned from worker process."
        raise ValueError(f"PDF extraction worker failed with code {process.returncode}: {err}")

    # Extract JSON substring in case warnings are emitted
    json_start = raw_stdout.find("{")
    json_end = raw_stdout.rfind("}")
    if json_start == -1 or json_end == -1 or json_end < json_start:
        raise ValueError(f"Failed to parse PDF worker JSON output: {raw_stdout[:200]}")

    json_payload = raw_stdout[json_start : json_end + 1]

    try:
        result = json.loads(json_payload)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Failed to parse PDF worker JSON output: {json_payload[:200]}"
        ) from exc

    if result.get("status") != "success":
        error_msg = result.get("message", "Unknown PDF processing error occurred.")
        raise ValueError(error_msg)

    pages = result.get("pages", [])
    if not pages:
        raise ValueError("PDF contains no extractable pages.")

    return pages

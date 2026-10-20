"""
Unit and Integration Tests for PDF Processing Service.
Module: PDF Processing & IOC Intelligence
"""

import os
import shutil
import tempfile
from pathlib import Path

import fitz  # PyMuPDF
import pytest

from backend.app.services.pdf_service import (
    MAGIC_BYTES,
    MAX_FILE_SIZE_BYTES,
    PageText,
    extract_pages,
    sanitize_filename,
    save_upload_file,
    validate_pdf_bytes,
    validate_pdf_file,
)


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="threatmap_pdf_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def create_sample_pdf(path: Path, page_texts: list[str]) -> Path:
    """Helper to create a multi-page test PDF with PyMuPDF."""
    doc = fitz.open()
    for text in page_texts:
        page = doc.new_page()
        page.insert_text((50, 72), text)
    doc.save(str(path))
    doc.close()
    return path


def test_magic_bytes_valid():
    valid_content = b"%PDF-1.7\nSample content"
    # Should not raise
    validate_pdf_bytes(valid_content)


def test_magic_bytes_invalid():
    invalid_content = b"PK\x03\x04ZipFile disguised as pdf"
    with pytest.raises(ValueError, match="missing %PDF- magic bytes"):
        validate_pdf_bytes(invalid_content)


def test_magic_bytes_empty():
    with pytest.raises(ValueError, match="empty"):
        validate_pdf_bytes(b"")


def test_size_limit_enforcement():
    oversized_content = b"%PDF-" + b"A" * (MAX_FILE_SIZE_BYTES + 10)
    with pytest.raises(ValueError, match="exceeds the maximum allowed limit of 50MB"):
        validate_pdf_bytes(oversized_content)


def test_filename_sanitization():
    # Path traversal attempts
    assert sanitize_filename("../../etc/passwd") == "passwd.pdf"
    assert sanitize_filename("..\\..\\windows\\system32\\calc.exe") == "calc.exe.pdf"
    assert sanitize_filename("../../../malicious_report.pdf") == "malicious_report.pdf"

    # Spaces and special characters
    assert sanitize_filename("Threat Report 2026 #1!.pdf") == "Threat_Report_2026__1_.pdf"

    # Empty or whitespace filename defaults safely
    fallback = sanitize_filename("   ")
    assert fallback.startswith("report_") and fallback.endswith(".pdf")

    # Null bytes
    assert sanitize_filename("safe_report\x00_hidden.pdf") == "safe_report_hidden.pdf"

    # Windows reserved device names
    assert sanitize_filename("CON.pdf") == "safe_CON.pdf"
    assert sanitize_filename("NUL.pdf") == "safe_NUL.pdf"


def test_save_upload_file(temp_dir):
    content = b"%PDF-1.5 Valid PDF Stream Content"
    saved_path = save_upload_file(content, "../../apt29_report.pdf", upload_dir=temp_dir)

    assert saved_path.exists()
    assert saved_path.is_file()
    assert saved_path.name.endswith("_apt29_report.pdf")
    assert saved_path.read_bytes() == content


def test_extract_pages_valid_multipage(temp_dir):
    pdf_path = temp_dir / "test_report.pdf"
    texts = [
        "Executive Summary: Threat actor APT29 compromised multiple accounts.",
        "Technical Analysis: PowerShell commands were executed on the DC.",
        "Indicators: C2 communication identified to 185.141.63.15.",
    ]
    create_sample_pdf(pdf_path, texts)

    pages = extract_pages(pdf_path)

    assert len(pages) == 3
    # Check both page_text and text contract fields
    assert pages[0]["page_number"] == 1
    assert "APT29" in pages[0]["page_text"]
    assert pages[0]["page_text"] == pages[0]["text"]

    assert pages[1]["page_number"] == 2
    assert "PowerShell" in pages[1]["page_text"]
    assert pages[1]["page_text"] == pages[1]["text"]

    assert pages[2]["page_number"] == 3
    assert "185.141.63.15" in pages[2]["page_text"]
    assert pages[2]["page_text"] == pages[2]["text"]


def test_extract_pages_encrypted_pdf(temp_dir):
    pdf_path = temp_dir / "encrypted.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Confidential content")
    # Encrypt with password
    doc.save(
        str(pdf_path),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        user_pw="password123",
        owner_pw="admin123",
    )
    doc.close()

    with pytest.raises(ValueError, match="Password-protected or encrypted PDFs are not supported"):
        extract_pages(pdf_path)


def test_extract_pages_image_only_no_text(temp_dir):
    pdf_path = temp_dir / "blank_pages.pdf"
    doc = fitz.open()
    doc.new_page()  # Blank page without text
    doc.new_page()
    doc.save(str(pdf_path))
    doc.close()

    with pytest.raises(ValueError, match="contains no extractable text"):
        extract_pages(pdf_path)


def test_extract_pages_corrupted_pdf(temp_dir):
    pdf_path = temp_dir / "corrupted.pdf"
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\nCorrupted content without valid xref or trailer")

    with pytest.raises(ValueError, match="Corrupted or malformed PDF"):
        extract_pages(pdf_path)


def test_extract_pages_nonexistent_file(temp_dir):
    nonexistent = temp_dir / "missing.pdf"
    with pytest.raises(FileNotFoundError):
        extract_pages(nonexistent)



def test_windows_path_traversal_sanitized():
    from backend.app.services.pdf_service import sanitize_filename
    assert sanitize_filename("C:\\Users\\x\\..\\report.pdf") == "report.pdf"

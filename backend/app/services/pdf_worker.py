"""
PDF Worker Subprocess for ThreatMap Lite.
Executes in an isolated subprocess with timeout to prevent memory leaks or process crashes.
"""

import json
import sys
import warnings
from pathlib import Path

# Suppress deprecation warnings from third-party libraries so stdout remains clean
warnings.filterwarnings("ignore")

try:
    import pymupdf as fitz
except ImportError:
    try:
        import fitz
    except ImportError:
        fitz = None


def process_pdf(pdf_path_str: str) -> dict:
    if fitz is None:
        return {
            "status": "error",
            "error_type": "dependency_error",
            "message": "PyMuPDF (pymupdf/fitz) is not installed in the environment.",
        }

    path = Path(pdf_path_str)
    if not path.is_file():
        return {
            "status": "error",
            "error_type": "file_not_found",
            "message": f"PDF file not found: {pdf_path_str}",
        }

    # Verify magic bytes before opening with fitz
    try:
        with open(path, "rb") as f:
            header = f.read(5)
            if header != b"%PDF-":
                return {
                    "status": "error",
                    "error_type": "invalid_magic_bytes",
                    "message": "Invalid file format: missing %PDF- magic bytes.",
                }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "read_error",
            "message": f"Unable to read file: {str(e)}",
        }

    try:
        doc = fitz.open(str(path))
    except Exception as e:
        return {
            "status": "error",
            "error_type": "corrupted",
            "message": f"Corrupted or malformed PDF file: {str(e)}",
        }

    try:
        if doc.is_encrypted or doc.needs_pass:
            doc.close()
            return {
                "status": "error",
                "error_type": "encrypted",
                "message": "Password-protected or encrypted PDFs are not supported.",
            }

        page_count = doc.page_count
        if page_count == 0:
            doc.close()
            return {
                "status": "error",
                "error_type": "empty",
                "message": "PDF contains zero pages.",
            }

        pages = []
        total_extracted_text = []
        failed_pages = []

        for page_num in range(page_count):
            try:
                page = doc.load_page(page_num)
                page_text = page.get_text("text") or ""
            except Exception:
                # Keep page numbering intact, but report the failure instead of hiding it
                page_text = ""
                failed_pages.append(page_num + 1)

            pages.append({
                "page_number": page_num + 1,
                "page_text": page_text,
            })
            total_extracted_text.append(page_text.strip())

        # Check if the PDF has any extractable text across all pages
        if not "".join(total_extracted_text):
            return {
                "status": "error",
                "error_type": "no_text",
                "message": "PDF contains no extractable text (scanned or image-only PDFs are not supported in MVP).",
            }

        return {
            "status": "success",
            "page_count": page_count,
            "pages": pages,
            "failed_pages": failed_pages,
        }

    except Exception as e:
        return {
            "status": "error",
            "error_type": "processing_error",
            "message": f"Error extracting text from PDF: {str(e)}",
        }
    finally:
        try:
            doc.close()
        except Exception:
            pass


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "status": "error",
            "error_type": "missing_argument",
            "message": "Usage: python -m backend.app.services.pdf_worker <path_to_pdf>",
        }))
        sys.exit(1)

    result = process_pdf(sys.argv[1])
    # Ensure stdout outputs clean utf-8 JSON
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()

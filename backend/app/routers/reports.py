"""
FastAPI Router for Report Ingestion, Status, and IOC APIs.
Adheres strictly to architecture.md Section 6 and phases.md contracts.
"""

from pathlib import Path
from typing import List, Optional
import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.db_models import Report, ReportPage, IOC
from backend.app.schemas.schemas import (
    IOCResponse,
    ReportListItem,
    ReportResultsResponse,
    ReportStatusResponse,
    ReportUploadResponse,
)
from backend.app.services.pdf_service import (
    extract_pages,
    save_upload_file,
    validate_pdf_bytes,
    MAX_FILE_SIZE_BYTES,
)
from backend.app.config import MAX_UPLOAD_SIZE_MB
from backend.app.services.ioc_service import extract_iocs

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


def process_report_pipeline(report_id: str, saved_path: Path, db: Session):
    """
    Executes the deterministic PDF and IOC extraction pipeline.
    Populates report_pages and iocs tables and finalizes report status.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        return

    try:
        # Step 1: Text extraction page-by-page
        pages = extract_pages(saved_path)
        report.page_count = len(pages)

        for page in pages:
            db_page = ReportPage(
                report_id=report.id,
                page_number=page["page_number"],
                page_text=page["page_text"],
            )
            db.add(db_page)

        db.flush()

        # Step 2: Deterministic IOC extraction & defanging
        extracted_iocs = extract_iocs(pages)

        for item in extracted_iocs:
            db_ioc = IOC(
                report_id=report.id,
                ioc_type=item["type"],
                ioc_value=item["value"],
                source_page=item["source_page"],
                evidence=item["evidence"],
            )
            db.add(db_ioc)

        # Step 3: Complete processing
        report.status = "complete"
        report.error_msg = None
        db.commit()

    except Exception as e:
        logger.exception(f"Pipeline failure for report {report_id}: {e}")
        db.rollback()
        # Reload report instance
        report = db.query(Report).filter(Report.id == report_id).first()
        if report:
            report.status = "failed"
            # PDF/validation errors are written for users; anything else stays in the server log
            report.error_msg = str(e) if isinstance(e, (ValueError, TimeoutError)) else "Internal error while processing the report."
            db.commit()


@router.post("/upload", response_model=ReportUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Accepts multipart/form-data PDF file.
    Validates magic bytes (%PDF-) and file size (<= 50MB).
    Saves file, stores report record, and executes extraction pipeline.
    """
    # Read in 1 MB chunks and stop as soon as the 50MB limit is exceeded,
    # so oversized uploads are never fully loaded into memory.
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds the maximum allowed limit of {MAX_UPLOAD_SIZE_MB}MB.",
                )
            chunks.append(chunk)
        content = b"".join(chunks)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to read uploaded file")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file.",
        )

    # Validate PDF content (%PDF- header and 50MB size limit)
    try:
        validate_pdf_bytes(content)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )

    # Save to uploads directory with sanitized name
    original_filename = file.filename or "uploaded_report.pdf"
    try:
        saved_path = save_upload_file(content, original_filename)
    except Exception:
        logger.exception("Could not save uploaded file to disk")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not save the uploaded file.",
        )

    # Initialize report record
    report = Report(
        file_name=saved_path.name,
        status="processing",
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # Run extraction pipeline
    process_report_pipeline(report.id, saved_path, db)
    db.refresh(report)

    return ReportUploadResponse(
        report_id=report.id,
        status=report.status,
    )


@router.get("/{report_id}/status", response_model=ReportStatusResponse)
def get_report_status(report_id: str, db: Session = Depends(get_db)):
    """
    Returns pipeline execution status for polling UI.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    step = "complete" if report.status == "complete" else ("failed" if report.status == "failed" else "processing")
    return ReportStatusResponse(
        status=report.status,
        current_step=step,
        error_msg=report.error_msg,
    )


@router.get("/{report_id}/iocs", response_model=List[IOCResponse])
def get_report_iocs(report_id: str, db: Session = Depends(get_db)):
    """
    Returns deterministic IOC extractions for a given report.
    Adheres strictly to architecture.md contract:
    list[{ "type": str, "value": str, "source_page": int, "evidence": str }]
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    iocs = (
        db.query(IOC)
        .filter(IOC.report_id == report_id)
        .order_by(IOC.source_page.asc(), IOC.ioc_type.asc())
        .all()
    )

    return [
        IOCResponse(
            type=ioc.ioc_type,
            value=ioc.ioc_value,
            source_page=ioc.source_page,
            evidence=ioc.evidence,
        )
        for ioc in iocs
    ]


@router.get("/{report_id}/results", response_model=ReportResultsResponse)
def get_report_results(report_id: str, db: Session = Depends(get_db)):
    """
    Returns complete report payload: metadata, IOCs, summary statistics, and AI cache.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    iocs = (
        db.query(IOC)
        .filter(IOC.report_id == report_id)
        .order_by(IOC.source_page.asc(), IOC.ioc_type.asc())
        .all()
    )

    ioc_list = [
        IOCResponse(
            type=ioc.ioc_type,
            value=ioc.ioc_value,
            source_page=ioc.source_page,
            evidence=ioc.evidence,
        )
        for ioc in iocs
    ]

    # Compute summary counts per IOC type
    ioc_summary: dict[str, int] = {}
    for ioc in ioc_list:
        ioc_summary[ioc.type] = ioc_summary.get(ioc.type, 0) + 1

    return ReportResultsResponse(
        report_id=report.id,
        file_name=report.file_name,
        page_count=report.page_count,
        status=report.status,
        created_at=report.created_at,
        iocs=ioc_list,
        ioc_summary=ioc_summary,
    )


@router.get("", response_model=List[ReportListItem])
def list_reports(db: Session = Depends(get_db)):
    """
    Lists all processed threat reports with summary counts.
    """
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    items = []
    for r in reports:
        ioc_count = db.query(IOC).filter(IOC.report_id == r.id).count()
        items.append(
            ReportListItem(
                id=r.id,
                file_name=r.file_name,
                page_count=r.page_count,
                status=r.status,
                created_at=r.created_at,
                ioc_count=ioc_count,
            )
        )
    return items


@router.delete("/{report_id}", status_code=status.HTTP_200_OK)
def delete_report(report_id: str, db: Session = Depends(get_db)):
    """
    Cascades deletion of report record, pages, and IOCs.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    db.delete(report)
    db.commit()
    return {"deleted": True, "report_id": report_id}

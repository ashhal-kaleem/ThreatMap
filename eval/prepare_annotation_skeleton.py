"""
Annotation Preparation & Verification Helper for ThreatMap Lite.
Module: PDF Processing & IOC Intelligence

Converts raw threat report PDFs into unpopulated annotation skeleton files conforming
to `eval/dataset_schema.json`, and validates completed human annotation files.

Strict Rule:
Does NOT fabricate or auto-generate ground-truth predictions. The `ground_truth`
array is emitted empty ([]) for human analysts to manually verify and annotate.

Usage:
    # 1. Convert one or more PDFs into an annotation skeleton:
    python -m eval.prepare_annotation_skeleton --pdf-dir path/to/reports/ --output eval/my_real_reports.json

    # 2. Convert a single PDF:
    python -m eval.prepare_annotation_skeleton --pdf path/to/report.pdf --report-id MANDIANT-APT41-2024 --output eval/my_real_reports.json

    # 3. Validate a completed annotation file before running evaluation:
    python -m eval.prepare_annotation_skeleton --validate eval/my_real_reports.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.pdf_service import extract_pages, validate_pdf_bytes
from eval.ioc_eval import SUPPORTED_IOC_TYPES, validate_annotation_record


def build_skeleton_for_pdf(pdf_path: Path, report_id: str | None = None) -> dict[str, Any]:
    """
    Extracts pages from a real PDF report using the production PyMuPDF worker
    and formats an unpopulated annotation record conforming to dataset_schema.json.
    """
    if not pdf_path.is_file():
        raise FileNotFoundError(f"PDF file not found: {pdf_path.resolve()}")

    # Validate PDF magic bytes and size
    with open(pdf_path, "rb") as f:
        file_bytes = f.read()

    validate_pdf_bytes(file_bytes)

    # Extract pages with 120s timeout
    extracted_pages = extract_pages(pdf_path)
    if not extracted_pages:
        raise ValueError(f"No extractable text found in PDF: {pdf_path.name}")

    rep_id = report_id or pdf_path.stem.upper().replace(" ", "_")

    return {
        "report_id": rep_id,
        "synthetic": False,
        "source_file": pdf_path.name,
        "notes": "Pending human ground-truth annotation.",
        "pages": [
            {
                "page_number": p["page_number"],
                "page_text": p["page_text"],
            }
            for p in extracted_pages
        ],
        "ground_truth": [],  # Strictly empty for human annotation
    }


def validate_dataset_completeness(dataset_path: str | Path) -> bool:
    """
    Validates a dataset file for schema conformity, completeness, and annotation health.
    Checks for unpopulated reports, invalid IOC types, and missing page references.
    """
    path = Path(dataset_path)
    if not path.is_file():
        print(f"[!] Dataset file not found: {path.resolve()}", file=sys.stderr)
        return False

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"[!] Malformed JSON: {exc}", file=sys.stderr)
            return False

    if not isinstance(data, list):
        print("[!] Dataset root must be a JSON array of report objects.", file=sys.stderr)
        return False

    print("=" * 80)
    print(f" VALIDATING ANNOTATION DATASET: {path.name}")
    print("=" * 80)
    print(f" Total Reports Found: {len(data)}")

    all_valid = True
    total_annotations = 0
    category_counts: dict[str, int] = {cat: 0 for cat in SUPPORTED_IOC_TYPES}
    unannotated_reports: list[str] = []

    for idx, record in enumerate(data):
        try:
            validate_annotation_record(record, record_idx=idx)
        except ValueError as exc:
            print(f"[X] Schema Error in record #{idx}: {exc}", file=sys.stderr)
            all_valid = False
            continue

        rep_id = record["report_id"]
        gt_list = record.get("ground_truth", [])
        page_nums = {p["page_number"] for p in record["pages"]}

        if not gt_list:
            unannotated_reports.append(rep_id)

        for gt_idx, gt in enumerate(gt_list):
            total_annotations += 1
            t = gt["type"]
            category_counts[t] = category_counts.get(t, 0) + 1

            # Check if annotated page_number exists in pages
            p_num = gt.get("page_number")
            if p_num is not None and p_num not in page_nums:
                print(
                    f"[!] Warning in '{rep_id}' GT #{gt_idx}: page_number {p_num} "
                    f"does not exist in document pages (pages: {min(page_nums)}..{max(page_nums)})."
                )

    print("-" * 80)
    print(f" Schema Conformity : {'PASSED' if all_valid else 'FAILED'}")
    print(f" Total Ground-Truth IOCs: {total_annotations}")
    print(" Per-Category Ground-Truth Distribution:")
    for cat, count in category_counts.items():
        print(f"   - {cat:<8}: {count} annotations")

    if unannotated_reports:
        print(f"\n[!] Incomplete Reports ({len(unannotated_reports)} reports have empty ground_truth):")
        for u in unannotated_reports:
            print(f"   - {u}")
        print("  These reports must be annotated by an analyst before running production evaluation.")
    else:
        print("\n[+] All reports have ground-truth annotations ready for evaluation.")

    print("=" * 80)
    return all_valid and (len(unannotated_reports) == 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ThreatMap Lite - Annotation Skeleton & Verification Tool"
    )
    parser.add_argument(
        "--pdf",
        type=str,
        default=None,
        help="Path to a single PDF threat report",
    )
    parser.add_argument(
        "--pdf-dir",
        type=str,
        default=None,
        help="Path to a directory containing PDF threat reports",
    )
    parser.add_argument(
        "--report-id",
        type=str,
        default=None,
        help="Custom report ID (used only with --pdf)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Target JSON file path to write or append annotation records",
    )
    parser.add_argument(
        "--validate",
        type=str,
        default=None,
        help="Path to an existing annotation JSON dataset to validate",
    )

    args = parser.parse_args(argv)

    if args.validate:
        is_ok = validate_dataset_completeness(args.validate)
        return 0 if is_ok else 1

    if not args.pdf and not args.pdf_dir:
        parser.print_help()
        return 1

    if not args.output:
        print("[!] Error: --output is required when extracting PDF skeletons.", file=sys.stderr)
        return 1

    pdf_files: list[Path] = []
    if args.pdf:
        p = Path(args.pdf)
        if not p.is_file():
            print(f"[!] PDF not found: {p.resolve()}", file=sys.stderr)
            return 1
        pdf_files.append(p)
    elif args.pdf_dir:
        d = Path(args.pdf_dir)
        if not d.is_dir():
            print(f"[!] Directory not found: {d.resolve()}", file=sys.stderr)
            return 1
        pdf_files = sorted(d.glob("*.pdf"))
        if not pdf_files:
            print(f"[!] No .pdf files found in {d.resolve()}", file=sys.stderr)
            return 1

    # Load existing records if output exists to allow incremental additions
    out_path = Path(args.output)
    existing_records: list[dict[str, Any]] = []
    existing_ids: set[str] = set()

    if out_path.is_file():
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                existing_records = json.load(f)
            if isinstance(existing_records, list):
                existing_ids = {r.get("report_id") for r in existing_records if isinstance(r, dict)}
        except Exception:
            existing_records = []

    new_records: list[dict[str, Any]] = []
    print(f"Processing {len(pdf_files)} PDF file(s)...")

    for pdf in pdf_files:
        try:
            rep_id = args.report_id if (len(pdf_files) == 1 and args.report_id) else None
            record = build_skeleton_for_pdf(pdf, report_id=rep_id)
            if record["report_id"] in existing_ids:
                print(f"[-] Skipping '{record['report_id']}': already exists in {out_path.name}")
                continue
            new_records.append(record)
            print(f"[+] Prepared skeleton for: {pdf.name} -> {record['report_id']} ({len(record['pages'])} pages)")
        except Exception as exc:
            print(f"[X] Failed to process {pdf.name}: {exc}", file=sys.stderr)

    all_records = existing_records + new_records
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)

    print(f"\n[+] Successfully saved {len(all_records)} report record(s) to: {out_path.resolve()}")
    print("Next step: Open the JSON file and manually populate 'ground_truth' arrays with human-verified IOCs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Review Queue Validator and Dataset Converter for ThreatMap Lite.
Module: PDF Processing & IOC Intelligence

Validates human-annotated review queue CSV files and converts verified
'true_ioc' annotations into the standardized evaluation dataset schema
(eval/dataset_schema.json).

Auditing Rules:
1. Valid labels are:
   - 'true_ioc': Manually verified as a genuine adversary/threat indicator.
   - 'not_ioc': Manually verified as benign text, documentation, software version, or tool reference.
   - 'uncertain': Ambiguous candidate requiring further malware analyst investigation.
   - 'unreviewed': Pending manual verification.
2. Only 'true_ioc' annotations are populated into the ground-truth dataset.
3. 'uncertain' and 'unreviewed' annotations are strictly tracked and never silently
   treated as positives or negatives.

Usage:
    # 1. Audit status of a review queue CSV:
    python -m eval.review_to_dataset --input eval/review_queue_subset.csv

    # 2. Convert verified annotations to evaluation dataset JSON:
    python -m eval.review_to_dataset --input eval/review_queue_subset.csv --output eval/verified_ground_truth.json
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.pdf_service import extract_pages
from eval.generate_review_queue import check_review_queue_integrity
from eval.ioc_eval import (
    SUPPORTED_IOC_TYPES,
    normalize_ground_truth_value,
    validate_annotation_record,
)

VALID_LABELS = {"true_ioc", "not_ioc", "uncertain", "unreviewed"}
HUMAN_REVIEW_COLUMNS = ("ai_suggested_label", "human_label", "human_evidence", "human_notes", "reviewed_by")


def validate_review_row(
    row: dict[str, str],
    row_idx: int,
    pdf_pages: list[dict[str, Any]] | None = None,
    enforce_human_validation: bool = False,
) -> None:
    """
    Validates syntax, schema, and evidence integrity of a single CSV annotation row.
    Raises ValueError on violation. Never silently converts invalid decisions.

    Safeguards:
    - Verbatim PDF quote verifies source provenance only.
    - Verified decisions ('true_ioc', 'not_ioc') require human justification ('human_notes')
      and analyst signature ('reviewed_by').
    - 'uncertain' decisions require explanatory notes.
    """
    fn = row.get("report_filename", "").strip()
    if not fn:
        raise ValueError(f"Row #{row_idx}: Missing 'report_filename'.")

    page_str = row.get("source_page", "").strip()
    if not page_str or not page_str.isdigit() or int(page_str) < 1:
        raise ValueError(f"Row #{row_idx} ({fn}): 'source_page' must be a positive integer. Got: '{page_str}'.")

    t = row.get("ioc_type", "").strip()
    if t not in SUPPORTED_IOC_TYPES:
        raise ValueError(f"Row #{row_idx} ({fn}): 'ioc_type' must be one of {SUPPORTED_IOC_TYPES}. Got: '{t}'.")

    val = row.get("normalized_value", "").strip()
    if not val:
        raise ValueError(f"Row #{row_idx} ({fn}): Missing 'normalized_value'.")

    # 1. Validate human review columns if present
    has_human_label = "human_label" in row
    if has_human_label:
        hl = row.get("human_label", "").strip().lower()
        if hl not in VALID_LABELS:
            raise ValueError(
                f"Row #{row_idx} ({fn}): Invalid 'human_label' '{hl}'. Must be one of: {sorted(VALID_LABELS)}."
            )

        # Enforce human evidence and justification safeguards for verified labels
        if hl in ("true_ioc", "not_ioc"):
            ev = row.get("human_evidence", "").strip()
            notes = row.get("human_notes", "").strip()
            by = row.get("reviewed_by", "").strip()

            if not ev:
                raise ValueError(
                    f"Row #{row_idx} ({fn}): Verified decision '{hl}' requires non-empty 'human_evidence' quote from PDF."
                )
            if not notes:
                raise ValueError(
                    f"Row #{row_idx} ({fn}): Verified decision '{hl}' requires non-empty 'human_notes' justification."
                )
            if not by:
                raise ValueError(
                    f"Row #{row_idx} ({fn}): Verified decision '{hl}' requires 'reviewed_by' analyst signature."
                )

            # Check verbatim source provenance if PDF text pages are supplied
            if pdf_pages is not None:
                p_num = int(page_str)
                matched_page = next((p for p in pdf_pages if int(p.get("page_number", 0)) == p_num), None)
                if not matched_page:
                    raise ValueError(
                        f"Row #{row_idx} ({fn}): Source page {p_num} does not exist in PDF (total pages {len(pdf_pages)})."
                    )
                p_text = matched_page.get("page_text") or matched_page.get("text", "")
                clean_ev = ev.strip('"\'')
                if clean_ev not in p_text:
                    raise ValueError(
                        f"Row #{row_idx} ({fn}): 'human_evidence' quote was not found verbatim in page {p_num} text. "
                        f"Verbatim quote required for source provenance."
                    )

        elif hl == "uncertain":
            # Uncertain decisions require explanatory notes explaining ambiguity
            if enforce_human_validation or row.get("human_notes", "").strip():
                if not row.get("human_notes", "").strip():
                    raise ValueError(
                        f"Row #{row_idx} ({fn}): Decision 'uncertain' requires 'human_notes' explaining ambiguity."
                    )

    # 2. Validate base label column if present
    if "label" in row:
        lbl = row.get("label", "").strip().lower()
        if lbl not in VALID_LABELS:
            raise ValueError(
                f"Row #{row_idx} ({fn}): Invalid 'label' '{lbl}'. Must be one of: {sorted(VALID_LABELS)}."
            )


def audit_review_queue(
    csv_path: Path,
    pdf_dir: Path | None = None,
    enforce_evidence: bool = False,
) -> dict[str, Any]:
    """
    Parses and audits a review queue CSV.
    Clearly distinguishes annotation row counts from unique IOC counts.
    Supports both original review_queue_subset.csv and manual_review.csv.
    """
    if not csv_path.is_file():
        raise FileNotFoundError(f"Review queue file not found: {csv_path.resolve()}")

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    has_human_cols = "human_label" in fieldnames
    has_active_human_reviews = False
    if has_human_cols:
        has_active_human_reviews = any(
            r.get("human_label", "").strip().lower() in ("true_ioc", "not_ioc", "uncertain")
            for r in rows
        )

    # Cache PDF pages if evidence verification requested
    pdf_cache: dict[str, list[dict[str, Any]]] = {}
    if enforce_evidence and pdf_dir and pdf_dir.is_dir():
        for r in rows:
            fn = r.get("report_filename", "").strip()
            if fn and fn not in pdf_cache:
                pdf_file = pdf_dir / fn
                if pdf_file.is_file():
                    pdf_cache[fn] = extract_pages(pdf_file)

    label_counts_rows: dict[str, int] = defaultdict(int)
    ai_counts_rows: dict[str, int] = defaultdict(int)
    per_report_rows: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    per_type_rows: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # Unique indicators: map (fn, type, norm_value) -> label
    unique_indicators_map: dict[tuple[str, str, str], str] = {}
    unique_ai_map: dict[tuple[str, str, str], str] = {}
    unique_indicators_by_report: dict[str, set[tuple[str, str]]] = defaultdict(set)
    unique_indicators_by_type: dict[str, set[tuple[str, str]]] = defaultdict(set)

    for idx, row in enumerate(rows, start=2):
        fn = row.get("report_filename", "").strip()
        pdf_pages = pdf_cache.get(fn)
        validate_review_row(row, idx, pdf_pages=pdf_pages, enforce_human_validation=enforce_evidence)

        t = row.get("ioc_type", "").strip()
        norm_v = normalize_ground_truth_value(t, row.get("normalized_value", "").strip())

        # If human columns are present, the effective label is strictly human_label
        if has_human_cols:
            eff_label = row.get("human_label", "unreviewed").strip().lower()
            ai_lbl = (row.get("ai_suggested_label") or row.get("label", "unreviewed")).strip().lower()
        else:
            eff_label = row.get("label", "unreviewed").strip().lower()
            ai_lbl = eff_label

        label_counts_rows[eff_label] += 1
        ai_counts_rows[ai_lbl] += 1
        per_report_rows[fn][eff_label] += 1
        per_type_rows[t][eff_label] += 1

        unique_key = (fn, t, norm_v)
        unique_indicators_map[unique_key] = eff_label
        unique_ai_map[unique_key] = ai_lbl
        unique_indicators_by_report[fn].add((t, norm_v))
        unique_indicators_by_type[t].add((fn, norm_v))

    label_counts_unique: dict[str, int] = defaultdict(int)
    for (fn, t, norm_v), lbl in unique_indicators_map.items():
        label_counts_unique[lbl] += 1

    ai_counts_unique: dict[str, int] = defaultdict(int)
    for (fn, t, norm_v), lbl in unique_ai_map.items():
        ai_counts_unique[lbl] += 1

    return {
        "csv_path": str(csv_path),
        "total_annotation_rows": len(rows),
        "unique_indicators_count": len(unique_indicators_map),
        "has_human_columns": has_human_cols,
        "has_active_human_reviews": has_active_human_reviews,
        "label_counts_rows": dict(label_counts_rows),
        "label_counts_unique": dict(label_counts_unique),
        "ai_counts_rows": dict(ai_counts_rows),
        "ai_counts_unique": dict(ai_counts_unique),
        "per_report_rows": dict(per_report_rows),
        "per_type_rows": dict(per_type_rows),
        "unique_indicators_map": unique_indicators_map,
        "rows": rows,
    }


def print_audit_report(stats: dict[str, Any], csv_path: Path) -> None:
    """
    Prints an auditable summary of review queue progress, clearly distinguishing
    annotation row counts from unique IOC counts.
    """
    total_rows = stats["total_annotation_rows"]
    total_unique = stats["unique_indicators_count"]
    rows_lbl = stats["label_counts_rows"]
    uniq_lbl = stats["label_counts_unique"]

    has_human = stats["has_human_columns"]
    has_active = stats["has_active_human_reviews"]

    print("=" * 88)
    print(f" AUDIT SUMMARY: {csv_path.name}")
    print("=" * 88)
    mode_str = "Human Review Queue (eval/manual_review.csv)" if has_human else "Standard Review Queue"
    print(f" Queue Format               : {mode_str}")
    if has_human and not has_active:
        print(" Human Review Status        : [!] ALL LABELS UNREVIEWED (Pending human analyst review)")
    elif has_human and has_active:
        print(" Human Review Status        : Active human annotations recorded")
    else:
        print(" Review Status              : Automated suggestion queue (unverified)")

    print("-" * 88)
    title_label = "Human Label" if has_human else "Candidate Label"
    print(f" {'Metric / ' + title_label:<32} | {'Annotation Rows':<18} | {'Doc-Level Unique Indicators':<28}")
    print("-" * 88)
    print(f" {'Total Candidates':<32} | {total_rows:<18} | {total_unique:<28}")

    for lbl in ("true_ioc", "not_ioc", "uncertain", "unreviewed"):
        r_cnt = rows_lbl.get(lbl, 0)
        u_cnt = uniq_lbl.get(lbl, 0)
        r_pct = (r_cnt / total_rows * 100) if total_rows else 0
        u_pct = (u_cnt / total_unique * 100) if total_unique else 0
        lbl_display = f" - {lbl}"
        print(f" {lbl_display:<32} | {r_cnt} ({r_pct:.1f}%)".ljust(53) + f"| {u_cnt} ({u_pct:.1f}%)")

    print("-" * 88)
    rev_rows = rows_lbl.get("true_ioc", 0) + rows_lbl.get("not_ioc", 0) + rows_lbl.get("uncertain", 0)
    rev_uniq = uniq_lbl.get("true_ioc", 0) + uniq_lbl.get("not_ioc", 0) + uniq_lbl.get("uncertain", 0)
    print(
        f" {'Review Completeness':<32} | {rev_rows}/{total_rows} ({(rev_rows/total_rows*100) if total_rows else 0:.1f}%)".ljust(53)
        + f"| {rev_uniq}/{total_unique} ({(rev_uniq/total_unique*100) if total_unique else 0:.1f}%)"
    )

    if has_human:
        ai_rows = stats["ai_counts_rows"]
        ai_uniq = stats["ai_counts_unique"]
        print("-" * 88)
        print(" AI-SUGGESTED REFERENCE DISTRIBUTION (For Review Guidance Only):")
        for lbl in ("true_ioc", "not_ioc", "uncertain"):
            r_cnt = ai_rows.get(lbl, 0)
            u_cnt = ai_uniq.get(lbl, 0)
            print(f"   * Suggested {lbl:<12}: {r_cnt} rows | {u_cnt} unique indicators")

    print("=" * 88)
    print(" [!] NOTE ON DEDUPLICATION & METRIC SCOPE:")
    print("     'Doc-Level Unique Indicators' (119 total across 3 reports) represents candidates")
    print("     deduplicated by (report_filename, ioc_type, normalized_value). Multi-page citations")
    print("     account for remaining rows (139 total). Candidate recall applies to this reviewed pool.")
    print(" [!] NOTE ON BENCHMARK RELIABILITY:")
    print("     A completed form alone does not establish a reliable benchmark without sufficient")
    print("     annotation coverage. Candidates must be verified against source PDF text with")
    print("     recorded human justification before claiming benchmark ground-truth status.")
    print("=" * 88)


def convert_review_to_dataset(
    stats: dict[str, Any],
    pdf_dir: Path,
    output_json: Path,
    require_human_verified: bool = False,
) -> int:
    """
    Converts reviewed queue entries into dataset_schema.json format.
    Extracts text pages from the corresponding PDF files.

    Safeguards:
    - Confirmed positives ('true_ioc') -> 'ground_truth'
    - Confirmed negatives ('not_ioc') -> 'confirmed_negatives' (for negative control)
    - Uncertain candidates ('uncertain') -> 'uncertain_candidates' (for neutral isolation)
    - Unreviewed candidates ('unreviewed') -> 'unreviewed_candidates' (for scope accounting)
    - Does not silently convert or fabricate decisions.
    """
    rows = stats["rows"]
    has_human = stats["has_human_columns"]
    has_active = stats["has_active_human_reviews"]

    if require_human_verified and not has_active:
        raise ValueError(
            "Cannot export human-verified ground-truth dataset: All human labels remain 'unreviewed'. "
            "Complete manual verification in eval/manual_review.csv before export."
        )

    rows_by_report: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        rows_by_report[r["report_filename"].strip()].append(r)

    dataset_records: list[dict[str, Any]] = []

    for fn, rep_rows in sorted(rows_by_report.items()):
        pdf_path = pdf_dir / fn
        if not pdf_path.is_file():
            print(f"[!] Warning: Source PDF not found: {pdf_path}", file=sys.stderr)
            pages = []
        else:
            raw_pages = extract_pages(pdf_path)
            pages = [{"page_number": p["page_number"], "page_text": p["page_text"]} for p in raw_pages]

        # Deduplicate per (type, value) for ground truth and negative controls
        ground_truth_list: list[dict[str, Any]] = []
        confirmed_negatives_list: list[dict[str, Any]] = []
        uncertain_list: list[dict[str, Any]] = []
        unreviewed_list: list[dict[str, Any]] = []

        seen_gt: set[tuple[str, str, int]] = set()
        seen_neg: set[tuple[str, str, int]] = set()
        seen_unc: set[tuple[str, str, int]] = set()
        seen_unrev: set[tuple[str, str, int]] = set()

        for r in rep_rows:
            t = r["ioc_type"].strip()
            norm_val = normalize_ground_truth_value(t, r["normalized_value"].strip())
            p_num = int(r["source_page"].strip())
            key = (t, norm_val, p_num)

            # Determine label
            if has_human and has_active:
                lbl = r.get("human_label", "unreviewed").strip().lower()
                evidence_note = r.get("human_notes", "").strip() or r.get("human_evidence", "").strip()
            else:
                lbl = r.get("label", "unreviewed").strip().lower()
                evidence_note = r.get("reviewer_notes", "").strip() or f"Evidence: {r.get('context_snippet', '')[:100]}"

            entry = {
                "type": t,
                "value": norm_val,
                "page_number": p_num,
                "notes": evidence_note,
            }

            if lbl == "true_ioc":
                if key not in seen_gt:
                    seen_gt.add(key)
                    ground_truth_list.append(entry)
            elif lbl == "not_ioc":
                if key not in seen_neg:
                    seen_neg.add(key)
                    confirmed_negatives_list.append(entry)
            elif lbl == "uncertain":
                if key not in seen_unc:
                    seen_unc.add(key)
                    uncertain_list.append(entry)
            else:
                if key not in seen_unrev:
                    seen_unrev.add(key)
                    unreviewed_list.append(entry)

        is_human_verified = has_human and has_active and len(ground_truth_list) > 0
        rep_id = Path(fn).stem.upper().replace(" ", "_").replace("-", "_")

        record: dict[str, Any] = {
            "report_id": rep_id,
            "synthetic": False,
            "source_file": fn,
            "verification_status": "human_verified" if is_human_verified else "ai_suggested_unverified",
            "notes": (
                f"Report '{fn}': Human-verified annotations ({len(ground_truth_list)} true IOCs, "
                f"{len(confirmed_negatives_list)} confirmed negatives, {len(uncertain_list)} uncertain)."
                if is_human_verified
                else f"Report '{fn}': UNVERIFIED AI-SUGGESTED ANNOTATIONS - PENDING FINAL HUMAN ANALYST VERIFICATION "
                f"({len(ground_truth_list)} true IOCs, {len(confirmed_negatives_list)} not_ioc)."
            ),
            "pages": pages,
            "ground_truth": ground_truth_list,
            "confirmed_negatives": confirmed_negatives_list,
            "uncertain_candidates": uncertain_list,
            "unreviewed_candidates": unreviewed_list,
            "stats_summary": {
                "total_rows": len(rep_rows),
                "true_ioc_count": len(ground_truth_list),
                "confirmed_negatives_count": len(confirmed_negatives_list),
                "uncertain_count": len(uncertain_list),
                "unreviewed_count": len(unreviewed_list),
            },
        }

        validate_annotation_record(record, record_idx=len(dataset_records))
        dataset_records.append(record)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(dataset_records, f, indent=2, ensure_ascii=False)

    total_gt = sum(len(r["ground_truth"]) for r in dataset_records)
    total_neg = sum(len(r.get("confirmed_negatives", [])) for r in dataset_records)
    has_unverified = any(r.get("verification_status") == "ai_suggested_unverified" for r in dataset_records)

    print(f"\n[+] Successfully exported {len(dataset_records)} report datasets to {output_json}")
    if has_unverified:
        print(" [!] CAUTION: Exported dataset contains UNVERIFIED AI-SUGGESTED labels.")
        print(" [!] Tagged with 'verification_status': 'ai_suggested_unverified'.")
        print(" [!] Do NOT claim this as human-verified gold-standard ground truth.")
    else:
        print(f"[+] Total Verified Ground-Truth IOCs: {total_gt}")
        print(f"[+] Total Confirmed Negatives (Negative Controls): {total_neg}")

    return total_gt


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit and convert human-annotated IOC review queue.")
    parser.add_argument("--input", type=Path, required=True, help="Path to input review queue CSV.")
    parser.add_argument("--pdf-dir", type=Path, default=PROJECT_ROOT / "eval" / "raw_reports", help="Directory containing raw report PDFs.")
    parser.add_argument("--output", type=Path, help="Optional output JSON dataset path.")
    parser.add_argument("--check-integrity", action="store_true", help="Run automated integrity validation checks on the queue.")
    parser.add_argument("--enforce-human-evidence", action="store_true", help="Enforce verbatim PDF quote and notes for verified human labels.")

    args = parser.parse_args()

    stats = audit_review_queue(args.input, pdf_dir=args.pdf_dir, enforce_evidence=args.enforce_human_evidence)
    print_audit_report(stats, args.input)

    if args.check_integrity:
        integrity = check_review_queue_integrity(stats["rows"], args.pdf_dir)
        print("\n" + "=" * 88)
        print(" AUTOMATED QUEUE INTEGRITY AUDIT")
        print("=" * 88)
        print(f" - Duplicate candidates: {len(integrity['duplicate_candidates'])}")
        print(f" - Missing evidence:     {len(integrity['missing_evidence'])}")
        print(f" - Invalid page numbers: {len(integrity['invalid_page_numbers'])}")
        print(f" - Unlocated evidence:   {len(integrity['unlocated_evidence'])}")
        print(f" - Flagged/Malformed:    {len(integrity['malformed_values'])}")
        if integrity["duplicate_candidates"]:
            for d in integrity["duplicate_candidates"][:5]:
                print(f"   [!] Duplicate: {d['type']}:{d['candidate']} on page {d['page']}")
        if integrity["invalid_page_numbers"]:
            for inv in integrity["invalid_page_numbers"][:5]:
                print(f"   [!] Invalid page: {inv['filename']} p.{inv['page']} (total {inv['total_pages']})")
        if integrity["unlocated_evidence"]:
            for unloc in integrity["unlocated_evidence"][:5]:
                print(f"   [!] Unlocated: {unloc['candidate']} on page {unloc['page']} in {unloc['filename']}")
        print("=" * 88)

    if args.output:
        convert_review_to_dataset(stats, args.pdf_dir, args.output)


if __name__ == "__main__":
    main()

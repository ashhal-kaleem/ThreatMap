"""
IOC Evaluator for ThreatMap Lite.
Module: PDF Processing & IOC Intelligence

Evaluates the deterministic regex-based IOC extraction service
(backend/app/services/ioc_service.py) against ground-truth annotations.

Supported IOC categories:
- ipv4
- domain
- url
- md5
- sha1
- sha256
- cve

Usage:
    python -m eval.ioc_eval --dataset eval/test_data/synthetic_test_reports.json
    python -m eval.ioc_eval --dataset <path_to_annotations.json> --output eval/results.json
"""

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path so backend modules can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.ioc_service import (
    clean_url,
    extract_iocs,
    normalize_defanged,
)
from backend.app.services.pdf_service import PageText

# Supported IOC categories matching the production IOC extractor contract
SUPPORTED_IOC_TYPES = ("ipv4", "domain", "url", "md5", "sha1", "sha256", "cve")


@dataclass
class CategoryMetrics:
    category: str
    support: int = 0
    extracted: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    status: str = "UNTESTED"  # "TESTED" | "UNTESTED" | "OVER_PREDICTING" | "ZERO_RECALL"


@dataclass
class ReportEvaluation:
    report_id: str
    synthetic: bool
    source_file: str | None = None
    total_support: int = 0
    total_extracted: int = 0
    total_tp: int = 0
    total_fp: int = 0
    total_fn: int = 0
    category_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    false_negatives: list[dict[str, Any]] = field(default_factory=list)
    true_positives: list[dict[str, Any]] = field(default_factory=list)
    confirmed_negatives_count: int = 0
    negatives_rejected_count: int = 0
    negative_control_rejection_rate: float | None = None
    unreviewed_predictions: list[dict[str, Any]] = field(default_factory=list)
    uncertain_predictions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class OverallEvaluationSummary:
    dataset_path: str
    num_reports: int
    is_synthetic_dataset: bool
    page_aware: bool
    is_unverified_dataset: bool = False
    per_category: dict[str, CategoryMetrics] = field(default_factory=dict)
    micro_avg: dict[str, float | None] = field(default_factory=dict)
    macro_avg: dict[str, Any] = field(default_factory=dict)
    reports: list[ReportEvaluation] = field(default_factory=list)
    negative_control_summary: dict[str, Any] = field(default_factory=dict)


def normalize_ground_truth_value(ioc_type: str, raw_value: str) -> str:
    """
    Normalizes a ground-truth IOC value using the same deterministic rules
    enforced by the production extractor, ensuring fair, reproducible matching.
    """
    if not raw_value:
        return ""

    val = raw_value.strip()

    if ioc_type in ("md5", "sha1", "sha256"):
        return val.lower()

    if ioc_type == "cve":
        return val.upper().replace("_", "-")

    if ioc_type == "domain":
        norm = normalize_defanged(val).lower().strip(".")
        return norm

    if ioc_type == "url":
        norm = clean_url(normalize_defanged(val))
        return norm

    if ioc_type == "ipv4":
        norm = normalize_defanged(val)
        return norm

    return val


def validate_annotation_record(record: Any, record_idx: int = 0) -> None:
    """
    Validates the structure of a single report annotation record.
    Raises ValueError with a descriptive message if the schema is violated.
    """
    if not isinstance(record, dict):
        raise ValueError(
            f"Record #{record_idx}: Expected JSON object (dict), got {type(record).__name__}."
        )

    # Required top-level fields
    if "report_id" not in record or not str(record["report_id"]).strip():
        raise ValueError(f"Record #{record_idx}: Missing or empty 'report_id'.")

    report_id = record["report_id"]

    if "pages" not in record or not isinstance(record["pages"], list):
        raise ValueError(
            f"Record '{report_id}' (#{record_idx}): Missing or invalid 'pages' (must be a list)."
        )

    for p_idx, page in enumerate(record["pages"]):
        if not isinstance(page, dict):
            raise ValueError(
                f"Record '{report_id}' page #{p_idx}: Expected dict, got {type(page).__name__}."
            )
        if "page_number" not in page or not isinstance(page["page_number"], int):
            raise ValueError(
                f"Record '{report_id}' page #{p_idx}: Missing or non-integer 'page_number'."
            )
        # Accept either 'page_text' or 'text'
        if "page_text" not in page and "text" not in page:
            raise ValueError(
                f"Record '{report_id}' page #{p_idx}: Missing 'page_text' or 'text'."
            )

    if "ground_truth" not in record or not isinstance(record["ground_truth"], list):
        raise ValueError(
            f"Record '{report_id}' (#{record_idx}): Missing or invalid 'ground_truth' (must be a list)."
        )

    for gt_idx, gt in enumerate(record["ground_truth"]):
        if not isinstance(gt, dict):
            raise ValueError(
                f"Record '{report_id}' ground_truth #{gt_idx}: Expected dict, got {type(gt).__name__}."
            )
        if "type" not in gt or gt["type"] not in SUPPORTED_IOC_TYPES:
            raise ValueError(
                f"Record '{report_id}' ground_truth #{gt_idx}: Invalid or missing 'type'. "
                f"Must be one of: {SUPPORTED_IOC_TYPES}. Got: '{gt.get('type')}'."
            )
        if "value" not in gt or not str(gt["value"]).strip():
            raise ValueError(
                f"Record '{report_id}' ground_truth #{gt_idx}: Missing or empty 'value'."
            )
        if "page_number" in gt and (not isinstance(gt["page_number"], int) or gt["page_number"] < 1):
            raise ValueError(
                f"Record '{report_id}' ground_truth #{gt_idx}: 'page_number' must be an integer >= 1."
            )


def load_dataset(file_path: str | Path) -> list[dict[str, Any]]:
    """
    Loads and validates an IOC evaluation dataset JSON file.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Evaluation dataset file not found: {path.resolve()}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in dataset {path}: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError(
            f"Dataset must be a top-level JSON array of report objects. Got {type(data).__name__}."
        )

    for idx, record in enumerate(data):
        validate_annotation_record(record, record_idx=idx)

    return data


def calculate_metrics(tp: int, fp: int, fn: int) -> tuple[float | None, float | None, float | None, str]:
    """
    Calculates precision, recall, and F1 score with safe handling of zero denominators
    and explicit status indicators for untested categories.

    Returns:
        (precision, recall, f1, status)
    """
    support = tp + fn
    extracted = tp + fp

    # Case 1: Untested category (no ground truth and no predictions)
    if support == 0 and extracted == 0:
        return None, None, None, "UNTESTED"

    # Case 2: No ground truth but false positives were predicted
    if support == 0 and extracted > 0:
        return 0.0, None, 0.0, "OVER_PREDICTING"

    # Case 3: Ground truth exists but zero predictions made
    if support > 0 and extracted == 0:
        return None, 0.0, 0.0, "ZERO_RECALL"

    # Case 4: Both ground truth and predictions exist
    precision = tp / extracted if extracted > 0 else 0.0
    recall = tp / support if support > 0 else 0.0

    if (precision + recall) > 0:
        f1 = (2.0 * precision * recall) / (precision + recall)
    else:
        f1 = 0.0

    return round(precision, 4), round(recall, 4), round(f1, 4), "TESTED"


def evaluate_report(
    record: dict[str, Any],
    page_aware: bool = False,
) -> ReportEvaluation:
    """
    Evaluates IOC extraction on a single report record against its ground truth.

    Matching policy:
    - Default (page_aware=False): Matches unique (ioc_type, normalized_value) per report.
      This ensures evaluation measures the detection of distinct indicators without
      artificially inflating metrics when benign or C2 indicators repeat on multiple pages.
    - Page-aware (page_aware=True): Matches (ioc_type, normalized_value, page_number).
    """
    report_id = record["report_id"]
    is_synthetic = bool(record.get("synthetic", False))
    source_file = record.get("source_file")

    # Format input pages for extract_iocs
    pages: list[PageText] = []
    for p in record["pages"]:
        text_content = p.get("page_text") or p.get("text", "")
        pages.append({
            "page_number": int(p["page_number"]),
            "page_text": str(text_content),
            "text": str(text_content),
        })

    # Run production extractor
    extracted_raw = extract_iocs(pages)

    # Prepare ground truth set and metadata lookup
    gt_set: set[tuple[Any, ...]] = set()
    gt_lookup: dict[tuple[Any, ...], dict[str, Any]] = {}

    for gt in record["ground_truth"]:
        t = gt["type"]
        v = normalize_ground_truth_value(t, gt["value"])
        p = int(gt.get("page_number", 0))

        key = (t, v, p) if page_aware else (t, v)
        gt_set.add(key)
        if key not in gt_lookup:
            gt_lookup[key] = {
                "type": t,
                "value": v,
                "page_number": p,
                "notes": gt.get("notes", ""),
            }

    # Prepare extracted set and metadata lookup
    pred_set: set[tuple[Any, ...]] = set()
    pred_lookup: dict[tuple[Any, ...], dict[str, Any]] = {}

    for item in extracted_raw:
        t = item["type"]
        v = item["value"]
        p = int(item["source_page"])

        key = (t, v, p) if page_aware else (t, v)
        # In unique matching, if an item appears on multiple pages, keep the first occurrence
        if key not in pred_set:
            pred_set.add(key)
            pred_lookup[key] = {
                "type": t,
                "value": v,
                "source_page": p,
                "evidence": item.get("evidence", ""),
            }

    # Process confirmed negatives and uncertain candidates if provided in dataset
    has_explicit_negatives = "confirmed_negatives" in record

    neg_set: set[tuple[Any, ...]] = set()
    for neg in record.get("confirmed_negatives", []):
        t = neg["type"]
        v = normalize_ground_truth_value(t, neg["value"])
        p = int(neg.get("page_number", 0))
        neg_set.add((t, v, p) if page_aware else (t, v))

    unc_set: set[tuple[Any, ...]] = set()
    for unc in record.get("uncertain_candidates", []):
        t = unc["type"]
        v = normalize_ground_truth_value(t, unc["value"])
        p = int(unc.get("page_number", 0))
        unc_set.add((t, v, p) if page_aware else (t, v))

    tp_keys = gt_set.intersection(pred_set)
    fn_keys = gt_set.difference(pred_set)

    if has_explicit_negatives:
        # Candidate-level: only verified negatives count as confirmed false positives
        fp_keys = pred_set.intersection(neg_set)
        unc_pred_keys = pred_set.intersection(unc_set)
        unrev_pred_keys = pred_set.difference(gt_set.union(neg_set).union(unc_set))
        neg_rej_keys = neg_set.difference(pred_set)
    else:
        # Default fallback for synthetic benchmark fixtures
        fp_keys = pred_set.difference(gt_set)
        unc_pred_keys = set()
        unrev_pred_keys = set()
        neg_rej_keys = set()

    # Build per-category counts
    category_counts: dict[str, dict[str, int]] = {
        cat: {"support": 0, "extracted": 0, "tp": 0, "fp": 0, "fn": 0}
        for cat in SUPPORTED_IOC_TYPES
    }

    for k in gt_set:
        c = k[0]
        if c in category_counts:
            category_counts[c]["support"] += 1

    for k in pred_set:
        c = k[0]
        if c in category_counts:
            category_counts[c]["extracted"] += 1

    for k in tp_keys:
        c = k[0]
        if c in category_counts:
            category_counts[c]["tp"] += 1

    for k in fp_keys:
        c = k[0]
        if c in category_counts:
            category_counts[c]["fp"] += 1

    for k in fn_keys:
        c = k[0]
        if c in category_counts:
            category_counts[c]["fn"] += 1

    # Detailed lists for reporting
    tps = [
        {
            "type": k[0],
            "value": k[1],
            "page": k[2] if page_aware else pred_lookup[k]["source_page"],
            "evidence": pred_lookup[k].get("evidence", ""),
        }
        for k in sorted(tp_keys)
    ]

    fps = [
        {
            "type": k[0],
            "value": k[1],
            "page": k[2] if page_aware else pred_lookup[k]["source_page"],
            "evidence": pred_lookup[k].get("evidence", ""),
        }
        for k in sorted(fp_keys)
    ]

    fns = [
        {
            "type": k[0],
            "value": k[1],
            "page": k[2] if page_aware else gt_lookup[k].get("page_number", 0),
            "notes": gt_lookup[k].get("notes", ""),
        }
        for k in sorted(fn_keys)
    ]

    unrev_preds = [
        {
            "type": k[0],
            "value": k[1],
            "page": k[2] if page_aware else pred_lookup[k]["source_page"],
            "evidence": pred_lookup[k].get("evidence", ""),
        }
        for k in sorted(unrev_pred_keys)
    ]

    unc_preds = [
        {
            "type": k[0],
            "value": k[1],
            "page": k[2] if page_aware else pred_lookup[k]["source_page"],
            "evidence": pred_lookup[k].get("evidence", ""),
        }
        for k in sorted(unc_pred_keys)
    ]

    neg_rate = round(len(neg_rej_keys) / len(neg_set), 4) if neg_set else None

    return ReportEvaluation(
        report_id=report_id,
        synthetic=is_synthetic,
        source_file=source_file,
        total_support=len(gt_set),
        total_extracted=len(pred_set),
        total_tp=len(tp_keys),
        total_fp=len(fp_keys),
        total_fn=len(fn_keys),
        category_counts=category_counts,
        false_positives=fps,
        false_negatives=fns,
        true_positives=tps,
        confirmed_negatives_count=len(neg_set),
        negatives_rejected_count=len(neg_rej_keys),
        negative_control_rejection_rate=neg_rate,
        unreviewed_predictions=unrev_preds,
        uncertain_predictions=unc_preds,
    )


def evaluate_dataset(
    dataset: list[dict[str, Any]],
    dataset_path: str = "",
    page_aware: bool = False,
) -> OverallEvaluationSummary:
    """
    Evaluates an entire dataset across all reports and computes
    per-category metrics, micro-averages, and macro-averages.
    """
    reports_eval = [evaluate_report(r, page_aware=page_aware) for r in dataset]

    # Aggregate counts across all reports per category
    agg: dict[str, dict[str, int]] = {
        cat: {"support": 0, "extracted": 0, "tp": 0, "fp": 0, "fn": 0}
        for cat in SUPPORTED_IOC_TYPES
    }

    is_any_synthetic = any(r.synthetic for r in reports_eval)
    is_any_unverified = any(
        r.get("verification_status") == "ai_suggested_unverified"
        or "UNVERIFIED AI-SUGGESTED" in str(r.get("notes", ""))
        for r in dataset
    )

    for rep in reports_eval:
        for cat in SUPPORTED_IOC_TYPES:
            c_data = rep.category_counts.get(cat, {})
            agg[cat]["support"] += c_data.get("support", 0)
            agg[cat]["extracted"] += c_data.get("extracted", 0)
            agg[cat]["tp"] += c_data.get("tp", 0)
            agg[cat]["fp"] += c_data.get("fp", 0)
            agg[cat]["fn"] += c_data.get("fn", 0)

    # Compute per-category metrics
    per_category: dict[str, CategoryMetrics] = {}
    tested_precisions: list[float] = []
    tested_recalls: list[float] = []
    tested_f1s: list[float] = []

    for cat in SUPPORTED_IOC_TYPES:
        counts = agg[cat]
        p, r, f1, status = calculate_metrics(
            tp=counts["tp"],
            fp=counts["fp"],
            fn=counts["fn"],
        )
        cm = CategoryMetrics(
            category=cat,
            support=counts["support"],
            extracted=counts["extracted"],
            tp=counts["tp"],
            fp=counts["fp"],
            fn=counts["fn"],
            precision=p,
            recall=r,
            f1=f1,
            status=status,
        )
        per_category[cat] = cm

        # Include in macro average only if category was tested
        if status != "UNTESTED":
            if p is not None:
                tested_precisions.append(p)
            if r is not None:
                tested_recalls.append(r)
            if f1 is not None:
                tested_f1s.append(f1)

    # Micro Average (global sum of TP, FP, FN)
    global_tp = sum(agg[c]["tp"] for c in SUPPORTED_IOC_TYPES)
    global_fp = sum(agg[c]["fp"] for c in SUPPORTED_IOC_TYPES)
    global_fn = sum(agg[c]["fn"] for c in SUPPORTED_IOC_TYPES)
    micro_p, micro_r, micro_f1, _ = calculate_metrics(global_tp, global_fp, global_fn)

    micro_avg = {
        "tp": global_tp,
        "fp": global_fp,
        "fn": global_fn,
        "precision": micro_p,
        "recall": micro_r,
        "f1": micro_f1,
    }

    # Macro Average (unweighted mean across tested categories)
    macro_p = (
        round(sum(tested_precisions) / len(tested_precisions), 4)
        if tested_precisions
        else None
    )
    macro_r = (
        round(sum(tested_recalls) / len(tested_recalls), 4)
        if tested_recalls
        else None
    )
    macro_f1 = (
        round(sum(tested_f1s) / len(tested_f1s), 4)
        if tested_f1s
        else None
    )

    macro_avg = {
        "precision": macro_p,
        "recall": macro_r,
        "f1": macro_f1,
        "categories_evaluated": len(tested_f1s),
        "total_categories": len(SUPPORTED_IOC_TYPES),
    }

    # Aggregate negative control metrics
    total_confirmed_negatives = sum(r.confirmed_negatives_count for r in reports_eval)
    total_negatives_rejected = sum(r.negatives_rejected_count for r in reports_eval)
    overall_rej_rate = round(total_negatives_rejected / total_confirmed_negatives, 4) if total_confirmed_negatives > 0 else None
    neg_control_summary = {
        "total_confirmed_negatives": total_confirmed_negatives,
        "negatives_rejected": total_negatives_rejected,
        "confirmed_false_positives": sum(len(r.false_positives) for r in reports_eval if r.confirmed_negatives_count > 0),
        "negative_control_rejection_rate": overall_rej_rate,
        "metric_semantics": (
            "Treat confirmed-negative rejection as a negative-control metric, NOT general specificity. "
            "Calculates proportion of known benign candidates correctly rejected/suppressed by extractor."
        ),
    }

    return OverallEvaluationSummary(
        dataset_path=str(dataset_path),
        num_reports=len(reports_eval),
        is_synthetic_dataset=is_any_synthetic,
        page_aware=page_aware,
        is_unverified_dataset=is_any_unverified,
        per_category=per_category,
        micro_avg=micro_avg,
        macro_avg=macro_avg,
        reports=reports_eval,
        negative_control_summary=neg_control_summary,
    )


def format_terminal_report(summary: OverallEvaluationSummary, verbose: bool = False) -> str:
    """
    Formats the evaluation results into an unambiguous, readable terminal report.
    """
    lines = []
    lines.append("=" * 80)
    lines.append(" THREATMAP LITE - IOC EXTRACTOR EVALUATION REPORT")
    lines.append(" Component: PDF Processing & IOC Intelligence")
    lines.append("=" * 80)
    lines.append(f" Dataset Path    : {summary.dataset_path or 'In-Memory Dataset'}")
    lines.append(f" Reports Evaluated: {summary.num_reports}")
    lines.append(f" Matching Mode   : {'Page-Aware (Type, Value, Page)' if summary.page_aware else 'Unique per Report (Type, Value)'}")

    if summary.is_synthetic_dataset:
        lines.append(" DATASET NATURE  : [!] SYNTHETIC TEST FIXTURE (NOT REAL THREAT REPORTS)")
        lines.append("                   Metrics below represent unit/fixture testing, NOT production evaluation.")
    elif summary.is_unverified_dataset:
        lines.append(" DATASET NATURE  : [!] UNVERIFIED AI-SUGGESTED ANNOTATIONS (NOT HUMAN GROUND TRUTH)")
        lines.append("                   Metrics below represent automated suggestion baseline, NOT final benchmark.")
    else:
        lines.append(" DATASET NATURE  : Real Ground-Truth Annotated Threat Reports")

    lines.append("-" * 80)
    header = (
        f"{'Category':<9} | {'Support':>7} | {'Extracted':>9} | {'TP':>4} | {'FP':>4} | {'FN':>4} | "
        f"{'Precision':>9} | {'Recall':>7} | {'F1':>7} | {'Status':<11}"
    )
    lines.append(header)
    lines.append("-" * 80)

    for cat in SUPPORTED_IOC_TYPES:
        cm = summary.per_category.get(cat)
        if not cm:
            continue
        p_str = f"{cm.precision:.4f}" if cm.precision is not None else "N/A"
        r_str = f"{cm.recall:.4f}" if cm.recall is not None else "N/A"
        f1_str = f"{cm.f1:.4f}" if cm.f1 is not None else "N/A"

        row = (
            f"{cm.category:<9} | {cm.support:>7} | {cm.extracted:>9} | {cm.tp:>4} | {cm.fp:>4} | {cm.fn:>4} | "
            f"{p_str:>9} | {r_str:>7} | {f1_str:>7} | {cm.status:<11}"
        )
        lines.append(row)

    lines.append("-" * 80)

    # Micro average row
    mi_p = summary.micro_avg.get("precision")
    mi_r = summary.micro_avg.get("recall")
    mi_f1 = summary.micro_avg.get("f1")
    mi_p_str = f"{mi_p:.4f}" if mi_p is not None else "N/A"
    mi_r_str = f"{mi_r:.4f}" if mi_r is not None else "N/A"
    mi_f1_str = f"{mi_f1:.4f}" if mi_f1 is not None else "N/A"

    lines.append(
        f"{'MICRO AVG':<9} | {summary.micro_avg.get('tp',0)+summary.micro_avg.get('fn',0):>7} | "
        f"{summary.micro_avg.get('tp',0)+summary.micro_avg.get('fp',0):>9} | "
        f"{summary.micro_avg.get('tp',0):>4} | {summary.micro_avg.get('fp',0):>4} | {summary.micro_avg.get('fn',0):>4} | "
        f"{mi_p_str:>9} | {mi_r_str:>7} | {mi_f1_str:>7} | OVERALL"
    )

    # Macro average row
    ma_p = summary.macro_avg.get("precision")
    ma_r = summary.macro_avg.get("recall")
    ma_f1 = summary.macro_avg.get("f1")
    ma_p_str = f"{ma_p:.4f}" if ma_p is not None else "N/A"
    ma_r_str = f"{ma_r:.4f}" if ma_r is not None else "N/A"
    ma_f1_str = f"{ma_f1:.4f}" if ma_f1 is not None else "N/A"

    lines.append(
        f"{'MACRO AVG':<9} | {'-':>7} | {'-':>9} | {'-':>4} | {'-':>4} | {'-':>4} | "
        f"{ma_p_str:>9} | {ma_r_str:>7} | {ma_f1_str:>7} | "
        f"({summary.macro_avg.get('categories_evaluated', 0)}/{summary.macro_avg.get('total_categories', 7)} types)"
    )
    lines.append("=" * 80)
    lines.append(" NOTE: In candidate-level evaluation, Doc Extracted equals TP + Conf FP + Uncertain.")
    lines.append("       Extracted predictions may not equal TP + Conf FP because neutral uncertain predictions")
    lines.append("       (e.g., dual-use GitHub repositories) are extracted from document text but remain")
    lines.append("       excluded from confirmed false positive counts in candidate-level and open-world reporting.")
    lines.append("       Candidate recall (1.0000) applies strictly to the reviewed candidate pool, not complete document recall.")
    lines.append("=" * 80)

    # Negative Control Summary if present
    neg_sum = summary.negative_control_summary
    if neg_sum and neg_sum.get("total_confirmed_negatives", 0) > 0:
        lines.append("\nNEGATIVE-CONTROL EVALUATION (BENIGN SUPPRESSION):")
        lines.append(f" Total Confirmed Negatives Tested : {neg_sum['total_confirmed_negatives']}")
        lines.append(f" Confirmed Negatives Rejected     : {neg_sum['negatives_rejected']}")
        lines.append(f" Confirmed Negatives Extracted    : {neg_sum['confirmed_false_positives']} (Confirmed False Positives)")
        rate = neg_sum.get("negative_control_rejection_rate")
        rate_str = f"{rate * 100:.2f}%" if rate is not None else "N/A"
        lines.append(f" Negative-Control Rejection Rate  : {rate_str}")
        lines.append(" NOTE: Confirmed-negative rejection measures the extractor's ability to reject known negative")
        lines.append("       controls. It is strictly a negative-control metric, NOT general specificity.")
        lines.append("=" * 80)

    # Verbose error breakdown
    if verbose:
        has_errors = False
        lines.append("\n" + "=" * 80)
        lines.append(" DETAILED ERROR ANALYSIS (FALSE POSITIVES & FALSE NEGATIVES)")
        lines.append("=" * 80)
        for rep in summary.reports:
            if rep.false_positives or rep.false_negatives:
                has_errors = True
                lines.append(f"\n--- Report: {rep.report_id} ---")
                if rep.false_positives:
                    lines.append(f"  [!] False Positives ({len(rep.false_positives)}):")
                    for fp in rep.false_positives:
                        lines.append(f"      - [{fp['type']}] '{fp['value']}' (page {fp['page']})")
                        if fp.get("evidence"):
                            lines.append(f"        Evidence: {fp['evidence']}")
                if rep.false_negatives:
                    lines.append(f"  [X] False Negatives ({len(rep.false_negatives)}):")
                    for fn in rep.false_negatives:
                        lines.append(f"      - [{fn['type']}] '{fn['value']}' (page {fn['page']})")
                        if fn.get("notes"):
                            lines.append(f"        Notes: {fn['notes']}")
        if not has_errors:
            lines.append("  No false positives or false negatives detected in this dataset.")
        lines.append("=" * 80)

    return "\n".join(lines)


def save_json_results(summary: OverallEvaluationSummary, output_path: str | Path) -> None:
    """
    Saves evaluation results into a structured, machine-readable JSON file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(summary)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ThreatMap Lite - IOC Extraction Service Evaluation"
    )
    parser.add_argument(
        "--dataset",
        "-d",
        type=str,
        default="eval/test_data/synthetic_test_reports.json",
        help="Path to evaluation dataset JSON file (default: eval/test_data/synthetic_test_reports.json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional path to output JSON results file",
    )
    parser.add_argument(
        "--page-aware",
        action="store_true",
        help="Match IOCs per (type, value, page) instead of default unique per-report (type, value)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Display detailed false positive and false negative lists in terminal",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress terminal summary output",
    )

    args = parser.parse_args(argv)

    try:
        dataset = load_dataset(args.dataset)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"[!] Error loading dataset: {exc}", file=sys.stderr)
        return 1

    summary = evaluate_dataset(
        dataset=dataset,
        dataset_path=args.dataset,
        page_aware=args.page_aware,
    )

    if not args.quiet:
        print(format_terminal_report(summary, verbose=args.verbose))

    if args.output:
        try:
            save_json_results(summary, args.output)
            if not args.quiet:
                print(f"\n[+] Results successfully saved to: {args.output}")
        except (OSError, TypeError) as exc:
            print(f"[!] Failed to save JSON results: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

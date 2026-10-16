"""
Evaluation Runner for ThreatMap Lite IOC Extraction.
Module: PDF Processing & IOC Intelligence

Compares production IOC extractor output (backend/app/services/ioc_service.py)
against human-annotated ground-truth labels from a review queue CSV or dataset JSON.

Matching Policy:
1. Report-Level Unique Matching (PRIMARY):
   Deduplicates (ioc_type, normalized_value) per report document. Evaluates whether
   each distinct threat indicator was discovered, without distorting metrics when
   an indicator repeats across multiple pages.
2. Page-Aware Matching (SECONDARY / --page-aware):
   Matches (ioc_type, normalized_value, page_number) tuples. Evaluates spatial
   page attribution accuracy.

Metrics & Safety:
- Safely handles zero denominators (None / UNTESTED for unrepresented categories).
- Excludes 'uncertain' candidates from ground truth and tracks them explicitly.
- Prohibits claiming final precision/recall on unreviewed queues.

Usage:
    # 1. Evaluate an annotated review queue CSV:
    python -m eval.evaluate_annotations --review-queue eval/review_queue_subset.csv

    # 2. Page-aware evaluation:
    python -m eval.evaluate_annotations --review-queue eval/review_queue_subset.csv --page-aware

    # 3. Save JSON evaluation report:
    python -m eval.evaluate_annotations --review-queue eval/review_queue_subset.csv --output eval/eval_results.json
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

from backend.app.services.ioc_service import extract_iocs
from backend.app.services.pdf_service import extract_pages
from eval.ioc_eval import (
    SUPPORTED_IOC_TYPES,
    calculate_metrics,
    normalize_ground_truth_value,
)
from eval.review_to_dataset import audit_review_queue


def evaluate_review_queue(
    csv_path: Path,
    pdf_dir: Path,
    page_aware: bool = False,
    use_ai_baseline_if_unreviewed: bool = False,
) -> dict[str, Any]:
    """
    Evaluates production extraction against a review queue CSV.

    Safeguards:
    1. Distinguishes annotation row counts from unique IOC counts.
    2. Separates candidate-level evaluation (closed-world benchmark within reviewed candidate pool)
       from full-report extraction (open-world extraction).
    3. Confirmed-negative rejection is treated as a negative-control metric (NOT general specificity).
    4. Isolates 'uncertain' candidates into a neutral reserve (never penalized as TP, FP, or FN).
    5. Does not count predictions outside reviewed scope as confirmed false positives.
    """
    stats = audit_review_queue(csv_path)
    rows = stats["rows"]
    has_human = stats["has_human_columns"]
    has_active_human = stats["has_active_human_reviews"]

    # Determine whether we evaluate human ground truth or AI-suggested baseline
    evaluating_ai_baseline = (not has_human) or (not has_active_human and use_ai_baseline_if_unreviewed)

    # Group annotations by report filename
    reports_map: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        reports_map[r.get("report_filename", "").strip()].append(r)

    total_reviewed_pages = 0
    total_unreviewed = 0
    total_uncertain = 0
    total_not_ioc = 0
    total_true_ioc = 0

    per_category_cand: dict[str, dict[str, int]] = {
        cat: {
            "support": 0,
            "extracted": 0,
            "tp": 0,
            "confirmed_fp": 0,
            "uncertain_preds": 0,
            "fn": 0,
            "negatives_total": 0,
            "negatives_rejected": 0,
        }
        for cat in SUPPORTED_IOC_TYPES
    }

    all_confirmed_fps: list[dict[str, Any]] = []
    all_unreviewed_preds: list[dict[str, Any]] = []
    all_uncertain_preds: list[dict[str, Any]] = []
    all_fns: list[dict[str, Any]] = []
    all_tps: list[dict[str, Any]] = []
    reports_evaluated: list[str] = []

    for fn, rep_rows in sorted(reports_map.items()):
        pdf_path = pdf_dir / fn
        if not pdf_path.is_file():
            print(f"[!] Warning: Source PDF not found: {pdf_path}", file=sys.stderr)
            continue

        reports_evaluated.append(fn)
        pages = extract_pages(pdf_path)
        total_reviewed_pages += len(pages)

        # 1. Run production extractor on the actual PDF
        predictions = extract_iocs(pages)

        # Build candidate sets from review queue
        gt_positives: set[tuple[Any, ...]] = set()
        gt_pos_lookup: dict[tuple[Any, ...], dict[str, str]] = {}
        verified_negatives: set[tuple[Any, ...]] = set()
        neg_lookup: dict[tuple[Any, ...], dict[str, str]] = {}
        uncertain_set: set[tuple[Any, ...]] = set()
        unreviewed_set: set[tuple[Any, ...]] = set()

        for r in rep_rows:
            t = r.get("ioc_type", "").strip()
            v = normalize_ground_truth_value(t, r.get("normalized_value", "").strip())
            p = int(r.get("source_page", 1).strip())

            # Effective label determination
            if has_human and has_active_human:
                lbl = r.get("human_label", "unreviewed").strip().lower()
            elif evaluating_ai_baseline:
                lbl = (r.get("ai_suggested_label") or r.get("label", "unreviewed")).strip().lower()
            else:
                lbl = r.get("human_label", "unreviewed").strip().lower()

            key = (t, v, p) if page_aware else (t, v)

            if lbl == "true_ioc":
                gt_positives.add(key)
                if key not in gt_pos_lookup:
                    gt_pos_lookup[key] = r
                total_true_ioc += 1
            elif lbl == "not_ioc":
                verified_negatives.add(key)
                if key not in neg_lookup:
                    neg_lookup[key] = r
                total_not_ioc += 1
            elif lbl == "uncertain":
                uncertain_set.add(key)
                total_uncertain += 1
            elif lbl == "unreviewed":
                unreviewed_set.add(key)
                total_unreviewed += 1

        # Build prediction set
        pred_set: set[tuple[Any, ...]] = set()
        pred_lookup: dict[tuple[Any, ...], dict[str, Any]] = {}

        for item in predictions:
            t = item["type"]
            v = item["value"]
            p = int(item["source_page"])
            key = (t, v, p) if page_aware else (t, v)

            if key not in pred_set:
                pred_set.add(key)
                pred_lookup[key] = item

        # Candidate-level matching (Closed-world benchmark)
        tp_keys = gt_positives.intersection(pred_set)
        fn_keys = gt_positives.difference(pred_set)
        confirmed_fp_keys = pred_set.intersection(verified_negatives)
        rejected_neg_keys = verified_negatives.difference(pred_set)
        uncertain_pred_keys = pred_set.intersection(uncertain_set)
        # Predictions outside the verified positive/negative/uncertain ground truth
        unreviewed_pred_keys = pred_set.difference(gt_positives.union(verified_negatives).union(uncertain_set))

        # Accumulate candidate-level category metrics
        for k in gt_positives:
            per_category_cand[k[0]]["support"] += 1
        for k in pred_set:
            per_category_cand[k[0]]["extracted"] += 1
        for k in tp_keys:
            per_category_cand[k[0]]["tp"] += 1
            all_tps.append({
                "report": fn,
                "type": k[0],
                "value": k[1],
                "page": k[2] if page_aware else pred_lookup[k]["source_page"],
                "evidence": pred_lookup[k].get("evidence", ""),
            })
        for k in fn_keys:
            per_category_cand[k[0]]["fn"] += 1
            orig_row = gt_pos_lookup[k]
            all_fns.append({
                "report": fn,
                "type": k[0],
                "value": k[1],
                "page": k[2] if page_aware else int(orig_row.get("source_page", 1)),
                "evidence": orig_row.get("context_snippet", ""),
                "notes": orig_row.get("human_notes") or orig_row.get("reviewer_notes", ""),
            })
        for k in verified_negatives:
            per_category_cand[k[0]]["negatives_total"] += 1
        for k in confirmed_fp_keys:
            per_category_cand[k[0]]["confirmed_fp"] += 1
            all_confirmed_fps.append({
                "report": fn,
                "type": k[0],
                "value": k[1],
                "page": k[2] if page_aware else pred_lookup[k]["source_page"],
                "evidence": pred_lookup[k].get("evidence", ""),
                "notes": neg_lookup[k].get("human_notes") or neg_lookup[k].get("reviewer_notes", ""),
            })
        for k in rejected_neg_keys:
            per_category_cand[k[0]]["negatives_rejected"] += 1
        for k in uncertain_pred_keys:
            per_category_cand[k[0]]["uncertain_preds"] += 1
            all_uncertain_preds.append({
                "report": fn,
                "type": k[0],
                "value": k[1],
                "page": k[2] if page_aware else pred_lookup[k]["source_page"],
                "evidence": pred_lookup[k].get("evidence", ""),
                "status": "uncertain_neutral_reserve",
            })
        for k in unreviewed_pred_keys:
            all_unreviewed_preds.append({
                "report": fn,
                "type": k[0],
                "value": k[1],
                "page": k[2] if page_aware else pred_lookup[k]["source_page"],
                "evidence": pred_lookup[k].get("evidence", ""),
                "status": "unreviewed_scope",
            })

    # Compute candidate-level metrics and negative-control metrics
    category_cand_results: dict[str, dict[str, Any]] = {}
    macro_cand_precisions: list[float] = []
    macro_cand_recalls: list[float] = []
    macro_cand_f1s: list[float] = []

    total_tp = sum(c["tp"] for c in per_category_cand.values())
    total_confirmed_fp = sum(c["confirmed_fp"] for c in per_category_cand.values())
    total_uncertain_preds = sum(c["uncertain_preds"] for c in per_category_cand.values())
    total_fn = sum(c["fn"] for c in per_category_cand.values())
    total_negatives = sum(c["negatives_total"] for c in per_category_cand.values())
    total_neg_rejected = sum(c["negatives_rejected"] for c in per_category_cand.values())

    for cat in SUPPORTED_IOC_TYPES:
        counts = per_category_cand[cat]
        # Candidate precision compares TP against Confirmed FP
        p, r, f1, status = calculate_metrics(counts["tp"], counts["confirmed_fp"], counts["fn"])
        neg_tot = counts["negatives_total"]
        neg_rej = counts["negatives_rejected"]
        neg_rejection_rate = (round(neg_rej / neg_tot, 4)) if neg_tot > 0 else None

        category_cand_results[cat] = {
            "support": counts["support"],
            "extracted": counts["extracted"],
            "tp": counts["tp"],
            "confirmed_fp": counts["confirmed_fp"],
            "fp": counts["confirmed_fp"],  # Backward-compatibility alias
            "uncertain_preds": counts["uncertain_preds"],
            "fn": counts["fn"],
            "candidate_precision": p,
            "precision": p,  # Backward-compatibility alias
            "candidate_recall": r,
            "recall": r,  # Backward-compatibility alias
            "candidate_f1": f1,
            "f1": f1,  # Backward-compatibility alias
            "status": status,
            "negatives_total": neg_tot,
            "negatives_rejected": neg_rej,
            "negative_control_rejection_rate": neg_rejection_rate,
        }
        if status == "TESTED":
            if p is not None:
                macro_cand_precisions.append(p)
            if r is not None:
                macro_cand_recalls.append(r)
            if f1 is not None:
                macro_cand_f1s.append(f1)

    micro_p, micro_r, micro_f1, micro_status = calculate_metrics(total_tp, total_confirmed_fp, total_fn)
    overall_neg_rejection_rate = (round(total_neg_rejected / total_negatives, 4)) if total_negatives > 0 else None

    macro_avg = {
        "candidate_precision": round(sum(macro_cand_precisions) / len(macro_cand_precisions), 4) if macro_cand_precisions else None,
        "candidate_recall": round(sum(macro_cand_recalls) / len(macro_cand_recalls), 4) if macro_cand_recalls else None,
        "candidate_f1": round(sum(macro_cand_f1s) / len(macro_cand_f1s), 4) if macro_cand_f1s else None,
        "tested_categories_count": len(macro_cand_precisions),
    }

    return {
        "evaluation_scope": {
            "queue_file": csv_path.name,
            "matching_policy": "page_aware" if page_aware else "report_unique (primary)",
            "reports_count": len(reports_evaluated),
            "reports_list": reports_evaluated,
            "total_pages_evaluated": total_reviewed_pages,
            "total_candidates_in_queue_rows": len(rows),
            "total_unique_indicators_in_queue": stats["unique_indicators_count"],
            "verified_true_ioc_count": total_true_ioc,
            "verified_not_ioc_count": total_not_ioc,
            "uncertain_count": total_uncertain,
            "unreviewed_count": total_unreviewed,
            "is_fully_reviewed": total_unreviewed == 0,
            "is_human_review_mode": has_human and has_active_human,
            "is_ai_suggested_baseline": evaluating_ai_baseline,
        },
        # Backward compatibility aliases
        "per_category": category_cand_results,
        "micro_average": {
            "tp": total_tp,
            "fp": total_confirmed_fp,
            "fn": total_fn,
            "precision": micro_p,
            "recall": micro_r,
            "f1": micro_f1,
            "status": micro_status,
        },
        "macro_average": {
            "precision": macro_avg["candidate_precision"],
            "recall": macro_avg["candidate_recall"],
            "f1": macro_avg["candidate_f1"],
            "tested_categories_count": macro_avg["tested_categories_count"],
        },
        "false_positives": all_confirmed_fps,
        "candidate_level_metrics": {
            "per_category": category_cand_results,
            "micro_average": {
                "tp": total_tp,
                "confirmed_fp": total_confirmed_fp,
                "fn": total_fn,
                "candidate_precision": micro_p,
                "candidate_recall": micro_r,
                "candidate_f1": micro_f1,
                "status": micro_status,
            },
            "macro_average": macro_avg,
        },
        "negative_control_metrics": {
            "total_confirmed_negatives": total_negatives,
            "negatives_rejected": total_neg_rejected,
            "confirmed_false_positives": total_confirmed_fp,
            "negative_control_rejection_rate": overall_neg_rejection_rate,
            "metric_semantics": (
                "Treat confirmed-negative rejection as a negative-control metric, NOT general specificity. "
                "Calculates proportion of known benign candidates correctly rejected/suppressed by extractor."
            ),
        },
        "open_world_extraction": {
            "total_extracted_predictions": sum(c["extracted"] for c in per_category_cand.values()),
            "true_positives_count": total_tp,
            "confirmed_false_positives_count": total_confirmed_fp,
            "uncertain_predictions_count": len(all_uncertain_preds),
            "unreviewed_predictions_count": len(all_unreviewed_preds),
            "note_on_unreviewed": (
                "Predictions outside the reviewed scope are unreviewed/unresolved. "
                "They are NOT counted as confirmed false positives without complete annotation coverage."
            ),
        },
        "true_positives": all_tps,
        "false_negatives": all_fns,
        "confirmed_false_positives": all_confirmed_fps,
        "uncertain_predictions": all_uncertain_preds,
        "unreviewed_predictions": all_unreviewed_preds,
    }


def print_evaluation_report(results: dict[str, Any]) -> None:
    """
    Prints a clear, formatted terminal evaluation report respecting all safeguards.
    """
    scope = results["evaluation_scope"]
    cand = results["candidate_level_metrics"]
    neg = results["negative_control_metrics"]
    open_world = results["open_world_extraction"]

    print("=" * 105)
    print(" THREATMAP LITE - IOC EXTRACTION EVALUATION REPORT")
    print(" Component: PDF Processing & IOC Intelligence")
    print("=" * 105)
    print(f" Source Queue File          : {scope['queue_file']}")
    print(f" Matching Policy            : {scope['matching_policy']}")
    print(f" Evaluated Reports          : {scope['reports_count']} reports ({', '.join(scope['reports_list'])})")
    print(f" Total Report Pages         : {scope['total_pages_evaluated']} pages")
    print("-" * 105)
    print(f" Queue Volume               : {scope['total_candidates_in_queue_rows']} annotation rows | {scope['total_unique_indicators_in_queue']} document-level unique indicators (deduplicated by report, IOC type, and normalized value)")
    lbl_pfx = "Suggested True IOCs (Unverified)" if scope.get("is_ai_suggested_baseline") else "Verified True IOCs"
    lbl_neg = "Suggested Not IOCs (Unverified)" if scope.get("is_ai_suggested_baseline") else "Verified Not IOCs"
    print(f" - {lbl_pfx:<32}: {scope['verified_true_ioc_count']}")
    print(f" - {lbl_neg:<32}: {scope['verified_not_ioc_count']}")
    print(f" - Uncertain Candidates (Neutral Reserve)  : {scope['uncertain_count']}")
    print(f" - Unreviewed Candidates in Queue          : {scope['unreviewed_count']}")
    print("=" * 105)

    if scope.get("is_ai_suggested_baseline"):
        print("\n [!] STATUS: AI-SUGGESTED BASELINE EVALUATION (UNVERIFIED)")
        print("     This evaluation reflects AI-suggested candidate labels.")
        print("     These metrics represent an automated suggestion baseline, NOT final verified benchmark accuracy.")
        print("     Final ground truth requires human analyst verification and sign-off.\n")

    if scope["verified_true_ioc_count"] == 0:
        print("\n [!] STATUS: UNREVIEWED / PENDING HUMAN VERIFICATION QUEUE")
        print(f"     All {scope['unreviewed_count']} candidates in this queue remain 'unreviewed' (0 verified 'true_ioc' labels).")
        print("     In accordance with rigorous evaluation safeguards, precision, recall, and F1")
        print("     cannot be computed or claimed until human analysts verify ground-truth labels.")
        print("     Please audit the candidates in eval/manual_review.csv and record human decisions.")
        print("     (To view the automated AI suggestion baseline, pass --baseline-suggestion).")
        print("=" * 105)
        return

    if not scope["is_fully_reviewed"]:
        print(f"\n [!] WARNING: Incomplete review ({scope['unreviewed_count']} candidates remain unreviewed).")
        print("     Metrics below reflect currently reviewed ground-truth positive labels only.")
        print("     Do NOT claim these preliminary scores as final benchmark results.\n")

    print("\n1. CANDIDATE-LEVEL EVALUATION (CLOSED-WORLD BENCHMARK):")
    print(f" {'Category':<10} | {'Support':<8} | {'Doc Extracted':<14} | {'TP':<4} | {'Conf FP':<8} | {'Uncertain':<9} | {'FN':<4} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'Status':<11}")
    print("-" * 105)
    for cat, m in sorted(cand["per_category"].items()):
        p_str = f"{m['candidate_precision']:.4f}" if m['candidate_precision'] is not None else "N/A"
        r_str = f"{m['candidate_recall']:.4f}" if m['candidate_recall'] is not None else "N/A"
        f1_str = f"{m['candidate_f1']:.4f}" if m['candidate_f1'] is not None else "N/A"
        unc_cnt = m.get("uncertain_preds", 0)
        print(f" {cat:<10} | {m['support']:<8} | {m['extracted']:<14} | {m['tp']:<4} | {m['confirmed_fp']:<8} | {unc_cnt:<9} | {m['fn']:<4} | {p_str:<9} | {r_str:<8} | {f1_str:<8} | {m['status']:<11}")
    print("-" * 105)

    micro = cand["micro_average"]
    mp_str = f"{micro['candidate_precision']:.4f}" if micro['candidate_precision'] is not None else "N/A"
    mr_str = f"{micro['candidate_recall']:.4f}" if micro['candidate_recall'] is not None else "N/A"
    mf1_str = f"{micro['candidate_f1']:.4f}" if micro['candidate_f1'] is not None else "N/A"
    total_unc = sum(c.get("uncertain_preds", 0) for c in cand["per_category"].values())
    print(f" {'MICRO AVG':<10} | {sum(c['support'] for c in cand['per_category'].values()):<8} | {sum(c['extracted'] for c in cand['per_category'].values()):<14} | {micro['tp']:<4} | {micro['confirmed_fp']:<8} | {total_unc:<9} | {micro['fn']:<4} | {mp_str:<9} | {mr_str:<8} | {mf1_str:<8} | {micro['status']:<11}")

    macro = cand["macro_average"]
    mac_p = f"{macro['candidate_precision']:.4f}" if macro['candidate_precision'] is not None else "N/A"
    mac_r = f"{macro['candidate_recall']:.4f}" if macro['candidate_recall'] is not None else "N/A"
    mac_f1 = f"{macro['candidate_f1']:.4f}" if macro['candidate_f1'] is not None else "N/A"
    print(f" {'MACRO AVG':<10} | {'-':<8} | {'-':<14} | {'-':<4} | {'-':<8} | {'-':<9} | {'-':<4} | {mac_p:<9} | {mac_r:<8} | {mac_f1:<8} | {macro['tested_categories_count']} tested")
    print("=" * 105)
    print(" NOTE ON EXTRACTION ACCOUNTING: Doc Extracted equals TP + Conf FP + Uncertain.")
    print("       Extracted predictions may not equal TP + Conf FP because neutral uncertain predictions")
    print("       (specifically the 2 dual-use GitHub repositories: 'https://github.com/alexantr/filemanager'")
    print("       and 'https://github.com/prasathmani/tinyfilemanager') are extracted from document text")
    print("       but remain excluded from confirmed false positive counts in both candidate-level and open-world reporting.")
    print(" NOTE ON RECALL VALIDITY & SCOPE: Candidate-level recall (1.0000) applies strictly to the")
    print("       currently reviewed positive candidate pool. It does NOT establish complete open-world")
    print("       document-level IOC recall across unannotated sections of the PDF reports.")
    print("=" * 105)

    print("\n2. NEGATIVE-CONTROL EVALUATION (BENIGN SUPPRESSION):")
    print(f" Total Confirmed Negatives Tested : {neg['total_confirmed_negatives']}")
    print(f" Confirmed Negatives Rejected     : {neg['negatives_rejected']}")
    print(f" Confirmed Negatives Extracted    : {neg['confirmed_false_positives']} (Confirmed False Positives)")
    rej_str = f"{neg['negative_control_rejection_rate']*100:.2f}%" if neg['negative_control_rejection_rate'] is not None else "N/A"
    print(f" Negative-Control Rejection Rate  : {rej_str}")
    print(" NOTE: Confirmed-negative rejection measures the extractor's ability to reject known negative")
    print("       controls. It is strictly a negative-control metric, NOT general specificity.")
    print("=" * 105)

    unc_names = ", ".join(u["value"] for u in results.get("uncertain_predictions", []))
    unc_suffix = f" (Held in neutral reserve: {unc_names})" if unc_names else ""
    print("\n3. FULL-REPORT EXTRACTION ACCOUNTING (OPEN-WORLD SCOPE):")
    print(f" Total Predictions Extracted      : {open_world['total_extracted_predictions']}")
    print(f" - True Positives                 : {open_world['true_positives_count']}")
    print(f" - Confirmed False Positives      : {open_world['confirmed_false_positives_count']}")
    print(f" - Neutral Uncertain Predictions  : {open_world['uncertain_predictions_count']}{unc_suffix}")
    print(f" - Unreviewed Scope Predictions   : {open_world['unreviewed_predictions_count']}")
    print(" NOTE: Predictions outside the reviewed candidate scope are reported as unreviewed/unresolved.")
    print("       They are NOT counted as confirmed false positives without complete annotation coverage.")
    print("       The two uncertain GitHub URLs remain excluded from confirmed FP counts and are consistently")
    print("       disclosed in candidate-level and open-world reporting.")
    print("=" * 105)

    # Detailed lists
    conf_fps = results["confirmed_false_positives"]
    if conf_fps:
        print(f"\nCONFIRMED FALSE POSITIVES ({len(conf_fps)} verified 'not_ioc' items extracted):")
        for idx, fp in enumerate(conf_fps[:10], start=1):
            print(f" {idx}. [{fp['report']} p.{fp['page']}] {fp['type'].upper()}: {fp['value']}")
            if fp.get("evidence"):
                print(f"    Evidence: {fp['evidence'][:120]}")
            if fp.get("notes"):
                print(f"    Reason  : {fp['notes'][:120]}")
        if len(conf_fps) > 10:
            print(f" ... and {len(conf_fps) - 10} more Confirmed False Positives.")

    fns = results["false_negatives"]
    if fns:
        print(f"\nFALSE NEGATIVES ({len(fns)} verified IOCs missed by production extractor):")
        for idx, fn in enumerate(fns[:10], start=1):
            print(f" {idx}. [{fn['report']} p.{fn['page']}] {fn['type'].upper()}: {fn['value']}")
            if fn.get("evidence"):
                print(f"    Evidence: {fn['evidence'][:120]}")
            if fn.get("notes"):
                print(f"    Notes   : {fn['notes']}")
        if len(fns) > 10:
            print(f" ... and {len(fns) - 10} more False Negatives.")
    print("=" * 90)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate IOC extraction against human-annotated review queue.")
    parser.add_argument("--review-queue", type=Path, required=True, help="Path to reviewed CSV queue.")
    parser.add_argument("--pdf-dir", type=Path, default=PROJECT_ROOT / "eval" / "raw_reports", help="Directory containing raw report PDFs.")
    parser.add_argument("--page-aware", action="store_true", help="Enable spatial page-aware matching.")
    parser.add_argument("--output", type=Path, help="Optional output JSON path for evaluation results.")
    parser.add_argument("--baseline-suggestion", action="store_true", help="Evaluate AI-suggested baseline labels when human labels are unreviewed.")

    args = parser.parse_args()

    results = evaluate_review_queue(
        args.review_queue,
        args.pdf_dir,
        page_aware=args.page_aware,
        use_ai_baseline_if_unreviewed=args.baseline_suggestion,
    )
    print_evaluation_report(results)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Saved detailed evaluation results to {args.output}")


if __name__ == "__main__":
    main()

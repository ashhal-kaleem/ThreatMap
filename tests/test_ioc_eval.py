"""
Unit and Integration Tests for IOC Evaluator (eval/ioc_eval.py).
Module: PDF Processing & IOC Intelligence
"""

from pathlib import Path

import pytest

from eval.ioc_eval import (
    calculate_metrics,
    evaluate_dataset,
    evaluate_report,
    format_terminal_report,
    load_dataset,
    normalize_ground_truth_value,
    validate_annotation_record,
)


class TestMetricCalculations:
    def test_perfect_detection(self):
        p, r, f1, status = calculate_metrics(tp=5, fp=0, fn=0)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0
        assert status == "TESTED"

    def test_untested_category(self):
        """When neither ground truth nor predictions exist, metrics must be None/UNTESTED."""
        p, r, f1, status = calculate_metrics(tp=0, fp=0, fn=0)
        assert p is None
        assert r is None
        assert f1 is None
        assert status == "UNTESTED"

    def test_over_predicting_zero_support(self):
        """When no ground truth exists but the model predicts items (all FPs)."""
        p, r, f1, status = calculate_metrics(tp=0, fp=4, fn=0)
        assert p == 0.0
        assert r is None
        assert f1 == 0.0
        assert status == "OVER_PREDICTING"

    def test_zero_recall(self):
        """When ground truth exists but model predicted nothing."""
        p, r, f1, status = calculate_metrics(tp=0, fp=0, fn=5)
        assert p is None
        assert r == 0.0
        assert f1 == 0.0
        assert status == "ZERO_RECALL"

    def test_balanced_metrics(self):
        # TP=6, FP=2 (extracted=8 -> Precision=6/8=0.75)
        # FN=4 (support=10 -> Recall=6/10=0.60)
        # F1 = 2 * (0.75 * 0.60) / (0.75 + 0.60) = 0.9 / 1.35 = 0.6667
        p, r, f1, status = calculate_metrics(tp=6, fp=2, fn=4)
        assert p == 0.75
        assert r == 0.6
        assert f1 == 0.6667
        assert status == "TESTED"


class TestGroundTruthNormalization:
    def test_hash_lowercasing(self):
        val = "5D41402ABC4B2A76B9719D911017C592"
        assert normalize_ground_truth_value("md5", val) == val.lower()

    def test_cve_normalization(self):
        assert normalize_ground_truth_value("cve", "cve-2023-38831") == "CVE-2023-38831"
        assert normalize_ground_truth_value("cve", "cve_2023_38831") == "CVE-2023-38831"

    def test_defanged_domain_normalization(self):
        assert normalize_ground_truth_value("domain", "evil[.]com") == "evil.com"
        assert normalize_ground_truth_value("domain", "bad(dot)net.") == "bad.net"

    def test_defanged_url_normalization(self):
        assert normalize_ground_truth_value("url", "hxxps://evil[.]com/gate") == "https://evil.com/gate"

    def test_defanged_ipv4_normalization(self):
        assert normalize_ground_truth_value("ipv4", "185.141.63[.]24") == "185.141.63.24"


class TestSchemaValidation:
    def test_missing_report_id(self):
        record = {"pages": [], "ground_truth": []}
        with pytest.raises(ValueError, match="Missing or empty 'report_id'"):
            validate_annotation_record(record)

    def test_invalid_pages_type(self):
        record = {"report_id": "REP-1", "pages": "not a list", "ground_truth": []}
        with pytest.raises(ValueError, match="Missing or invalid 'pages'"):
            validate_annotation_record(record)

    def test_page_missing_text(self):
        record = {
            "report_id": "REP-1",
            "pages": [{"page_number": 1}],
            "ground_truth": [],
        }
        with pytest.raises(ValueError, match="Missing 'page_text' or 'text'"):
            validate_annotation_record(record)

    def test_invalid_ioc_type(self):
        record = {
            "report_id": "REP-1",
            "pages": [{"page_number": 1, "page_text": "Sample"}],
            "ground_truth": [{"type": "bitcoin_wallet", "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}],
        }
        with pytest.raises(ValueError, match="Invalid or missing 'type'"):
            validate_annotation_record(record)

    def test_empty_ioc_value(self):
        record = {
            "report_id": "REP-1",
            "pages": [{"page_number": 1, "page_text": "Sample"}],
            "ground_truth": [{"type": "ipv4", "value": "   "}],
        }
        with pytest.raises(ValueError, match="Missing or empty 'value'"):
            validate_annotation_record(record)

    def test_invalid_ground_truth_page_number(self):
        record = {
            "report_id": "REP-1",
            "pages": [{"page_number": 1, "page_text": "Sample"}],
            "ground_truth": [{"type": "ipv4", "value": "185.141.63.1", "page_number": 0}],
        }
        with pytest.raises(ValueError, match="'page_number' must be an integer >= 1"):
            validate_annotation_record(record)

    def test_load_dataset_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_dataset("non_existent_dataset.json")


class TestReportEvaluationLogic:
    def test_duplicate_handling_unique_matching(self):
        """Repeated occurrences of an IOC across multiple pages count once in unique mode."""
        record = {
            "report_id": "REP-DUP",
            "synthetic": True,
            "pages": [
                {"page_number": 1, "page_text": "C2 IP is 185.141.63.55 here."},
                {"page_number": 2, "page_text": "Reminder: C2 IP is 185.141.63.55 again."},
            ],
            "ground_truth": [
                {"type": "ipv4", "value": "185.141.63.55", "page_number": 1}
            ],
        }
        eval_res = evaluate_report(record, page_aware=False)
        assert eval_res.total_support == 1
        assert eval_res.total_extracted == 1
        assert eval_res.total_tp == 1
        assert eval_res.total_fp == 0
        assert eval_res.total_fn == 0

    def test_gt_lookup_preserves_first_page_number(self):
        """If ground truth lists the same IOC on multiple pages, the first page is preserved in unique matching."""
        record = {
            "report_id": "REP-GT-DUP",
            "synthetic": True,
            "pages": [
                {"page_number": 1, "page_text": "C2 IP is 185.141.63.99."},
                {"page_number": 2, "page_text": "C2 IP is 185.141.63.99 again."},
            ],
            "ground_truth": [
                {"type": "ipv4", "value": "185.141.63.99", "page_number": 1, "notes": "First seen"},
                {"type": "ipv4", "value": "185.141.63.99", "page_number": 2, "notes": "Second seen"},
            ],
        }
        eval_res = evaluate_report(record, page_aware=False)
        assert eval_res.total_support == 1
        assert eval_res.total_extracted == 1
        assert eval_res.total_tp == 1
        assert eval_res.true_positives[0]["page"] == 1

    def test_page_aware_matching(self):
        """Page-aware mode requires matching (type, value, page)."""
        record = {
            "report_id": "REP-PAGE",
            "synthetic": True,
            "pages": [
                {"page_number": 1, "page_text": "C2 server is 185.141.63.77."},
            ],
            "ground_truth": [
                # Ground truth incorrectly specifies page 2 instead of 1
                {"type": "ipv4", "value": "185.141.63.77", "page_number": 2}
            ],
        }
        eval_res = evaluate_report(record, page_aware=True)
        # Extracted on page 1, GT says page 2 -> 1 FP on page 1, 1 FN on page 2
        assert eval_res.total_tp == 0
        assert eval_res.total_fp == 1
        assert eval_res.total_fn == 1

    def test_false_positive_and_false_negative_tracking(self):
        record = {
            "report_id": "REP-ERRORS",
            "synthetic": True,
            "pages": [
                {
                    "page_number": 1,
                    # Text contains 185.141.63.1 (not in GT -> FP)
                    "page_text": "Observed connection to 185.141.63.1.",
                }
            ],
            "ground_truth": [
                # GT expects 194.165.16.5 (not in text -> FN)
                {"type": "ipv4", "value": "194.165.16.5", "notes": "Expected adversary IP"}
            ],
        }
        eval_res = evaluate_report(record, page_aware=False)
        assert eval_res.total_tp == 0
        assert eval_res.total_fp == 1
        assert eval_res.total_fn == 1
        assert eval_res.false_positives[0]["value"] == "185.141.63.1"
        assert eval_res.false_negatives[0]["value"] == "194.165.16.5"

    def test_empty_pages_and_ground_truth(self):
        record = {
            "report_id": "REP-EMPTY",
            "synthetic": True,
            "pages": [{"page_number": 1, "page_text": ""}],
            "ground_truth": [],
        }
        eval_res = evaluate_report(record, page_aware=False)
        assert eval_res.total_support == 0
        assert eval_res.total_extracted == 0
        assert eval_res.total_tp == 0


class TestDatasetEvaluationAndMacroAverage:
    def test_synthetic_fixture_dataset(self):
        dataset_path = Path("eval/test_data/synthetic_test_reports.json")
        data = load_dataset(dataset_path)
        summary = evaluate_dataset(data, dataset_path=str(dataset_path))

        assert summary.num_reports == 2
        assert summary.is_synthetic_dataset is True
        # Check all 7 categories were evaluated
        assert summary.macro_avg["categories_evaluated"] == 7
        assert summary.macro_avg["f1"] == 1.0

        # Check terminal report formatting
        rep_text = format_terminal_report(summary, verbose=True)
        assert "SYNTHETIC TEST FIXTURE" in rep_text
        assert "MICRO AVG" in rep_text
        assert "MACRO AVG" in rep_text

    def test_macro_average_excludes_untested_categories(self):
        """Untested categories with 0 support and 0 predictions must not pull down the macro average."""
        custom_dataset = [
            {
                "report_id": "REP-PARTIAL",
                "synthetic": True,
                "pages": [{"page_number": 1, "page_text": "Found CVE-2024-1234."}],
                "ground_truth": [{"type": "cve", "value": "CVE-2024-1234"}],
            }
        ]
        summary = evaluate_dataset(custom_dataset)
        # Only 'cve' was tested (1/7 types)
        assert summary.macro_avg["categories_evaluated"] == 1
        assert summary.macro_avg["f1"] == 1.0
        assert summary.per_category["cve"].status == "TESTED"
        assert summary.per_category["ipv4"].status == "UNTESTED"
        assert summary.per_category["ipv4"].f1 is None


class TestAnnotationPreparationHelper:
    def test_validate_dataset_completeness_valid(self):
        from eval.prepare_annotation_skeleton import validate_dataset_completeness

        is_valid = validate_dataset_completeness("eval/test_data/synthetic_test_reports.json")
        assert is_valid is True

    def test_validate_dataset_completeness_incomplete_report(self, tmp_path):
        import json
        from eval.prepare_annotation_skeleton import validate_dataset_completeness

        incomplete_file = tmp_path / "incomplete.json"
        data = [
            {
                "report_id": "REP-INCOMPLETE",
                "synthetic": False,
                "pages": [{"page_number": 1, "page_text": "Sample text"}],
                "ground_truth": [],  # Empty
            }
        ]
        incomplete_file.write_text(json.dumps(data), encoding="utf-8")

        # Returns False because report is unannotated
        is_valid = validate_dataset_completeness(incomplete_file)
        assert is_valid is False

"""
Unit and Integration Tests for Ground-Truth Annotation & Evaluation Workflow.
Module: PDF Processing & IOC Intelligence
"""

import csv
import json
import tempfile
from pathlib import Path
import pytest

from eval.generate_review_queue import (
    extract_permissive_candidates,
    generate_queue_for_pdf,
)
from eval.review_to_dataset import (
    audit_review_queue,
    convert_review_to_dataset,
    validate_review_row,
)
from eval.evaluate_annotations import evaluate_review_queue
from eval.ioc_eval import calculate_metrics, validate_annotation_record


class TestPermissiveCandidateDiscovery:
    def test_discovers_unfiltered_candidates(self):
        """
        Permissive discovery must capture software versions, private IPs, and reference links
        that production extractor intentionally filters out, enabling reviewers to catch FNs.
        """
        pages = [
            {
                "page_number": 1,
                "page_text": (
                    "Observed traffic from internal 192.168.1.50 and software version Chrome/116.0.0.0.\n"
                    "Reference link: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a\n"
                    "File manual.pdf downloaded from https://github.com/repo/docs/manual.pdf\n"
                    "Adversary C2: 198.51.100.45 and backdoor hash 5d41402abc4b2a76b9719d911017c592."
                ),
            }
        ]
        candidates = extract_permissive_candidates(pages)
        types_found = {c["ioc_type"] for c in candidates}
        vals = {c["normalized_value"] for c in candidates}

        # Must capture private IP and software version IP
        assert "192.168.1.50" in vals
        assert "116.0.0.0" in vals
        # Must capture reference and manual URLs
        assert any("cisa.gov" in v for v in vals)
        assert any("manual.pdf" in v for v in vals)
        # Must capture real adversary C2 IP and MD5
        assert "198.51.100.45" in vals
        assert "5d41402abc4b2a76b9719d911017c592" in vals
        assert {"ipv4", "url", "domain", "md5"}.issubset(types_found)


class TestReviewQueueIntegrity:
    def test_all_labels_default_to_unreviewed(self):
        """
        Ensures NO ground-truth labels are automatically assumed or fabricated.
        """
        sample_pdf = Path("eval/raw_reports/cisa_aa22_187a_maui_ransomware.pdf")
        if not sample_pdf.is_file():
            pytest.skip("Test requires raw report PDF.")

        queue_rows = generate_queue_for_pdf(sample_pdf)
        assert len(queue_rows) > 0
        for r in queue_rows:
            assert r["label"] == "unreviewed"
            assert r["source_origin"] in ("both", "permissive_discovery", "production_extractor")
            assert int(r["source_page"]) >= 1

    def test_validate_review_row_catches_invalid_labels(self):
        valid_row = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "ipv4",
            "normalized_value": "198.51.100.1",
            "label": "true_ioc",
        }
        validate_review_row(valid_row, row_idx=2)

        invalid_row = dict(valid_row, label="malicious")  # Not an accepted label
        with pytest.raises(ValueError, match="Invalid 'label'"):
            validate_review_row(invalid_row, row_idx=3)

    def test_validate_review_row_catches_invalid_ioc_type(self):
        row = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "email_address",  # Not supported
            "normalized_value": "test@example.com",
            "label": "true_ioc",
        }
        with pytest.raises(ValueError, match="must be one of"):
            validate_review_row(row, row_idx=2)


class TestEvaluationLogicAndMetrics:
    def test_duplicate_handling_report_level_matching(self, tmp_path):
        """
        An indicator appearing on multiple pages must only count once in report-level matching.
        """
        csv_file = tmp_path / "review_dup.csv"
        csv_file.write_text(
            "report_filename,source_page,ioc_type,raw_candidate,normalized_value,source_origin,label,context_snippet,reviewer_notes\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,both,true_ioc,snippet1,notes\n"
            "cisa_aa22_187a_maui_ransomware.pdf,2,sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,both,true_ioc,snippet2,notes\n",
            encoding="utf-8",
        )
        pdf_dir = Path("eval/raw_reports")
        results = evaluate_review_queue(csv_file, pdf_dir, page_aware=False)
        sha_metrics = results["per_category"]["sha256"]
        # In report-level matching, support must be 1, not 2
        assert sha_metrics["support"] == 1

    def test_uncertain_and_unreviewed_isolation(self, tmp_path):
        """
        Uncertain and unreviewed candidates must NOT be counted as True Positives or False Negatives.
        """
        csv_file = tmp_path / "review_iso.csv"
        csv_file.write_text(
            "report_filename,source_page,ioc_type,raw_candidate,normalized_value,source_origin,label,context_snippet,reviewer_notes\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,sha256,hash1,hash1,both,uncertain,snippet,uncertain notes\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,sha256,hash2,hash2,both,unreviewed,snippet,pending\n",
            encoding="utf-8",
        )
        pdf_dir = Path("eval/raw_reports")
        results = evaluate_review_queue(csv_file, pdf_dir, page_aware=False)
        scope = results["evaluation_scope"]
        assert scope["uncertain_count"] == 1
        assert scope["unreviewed_count"] == 1
        assert scope["verified_true_ioc_count"] == 0
        # Support for sha256 should be 0 because no true_ioc was verified
        assert results["per_category"]["sha256"]["support"] == 0

    def test_zero_denominator_metric_statuses(self):
        # 1. Untested category
        p, r, f1, status = calculate_metrics(tp=0, fp=0, fn=0)
        assert p is None and r is None and f1 is None
        assert status == "UNTESTED"

        # 2. Over-predicting (support=0, fp=3)
        p, r, f1, status = calculate_metrics(tp=0, fp=3, fn=0)
        assert p == 0.0 and r is None and f1 == 0.0
        assert status == "OVER_PREDICTING"

        # 3. Zero recall (support=5, extracted=0)
        p, r, f1, status = calculate_metrics(tp=0, fp=0, fn=5)
        assert p is None and r == 0.0 and f1 == 0.0
        assert status == "ZERO_RECALL"

    def test_dataset_json_conversion_conformity(self, tmp_path):
        """
        Verified annotations exported to JSON must strictly conform to dataset_schema.json.
        """
        csv_file = tmp_path / "review_conv.csv"
        csv_file.write_text(
            "report_filename,source_page,ioc_type,raw_candidate,normalized_value,source_origin,label,context_snippet,reviewer_notes\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,md5,d41d8cd98f00b204e9800998ecf8427e,d41d8cd98f00b204e9800998ecf8427e,both,true_ioc,snippet,verified payload\n"
            "cisa_aa22_187a_maui_ransomware.pdf,2,domain,example.com,example.com,permissive_discovery,not_ioc,doc link,reference\n",
            encoding="utf-8",
        )
        out_json = tmp_path / "dataset.json"
        stats = audit_review_queue(csv_file)
        pdf_dir = Path("eval/raw_reports")
        total_gt = convert_review_to_dataset(stats, pdf_dir, out_json)

        assert total_gt == 1
        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 1
        record = data[0]
        validate_annotation_record(record)
        assert len(record["ground_truth"]) == 1
        assert record["ground_truth"][0]["type"] == "md5"
        assert record["ground_truth"][0]["value"] == "d41d8cd98f00b204e9800998ecf8427e"


class TestFormatValidationAndPriorities:
    def test_ipv4_format_validation(self):
        from eval.generate_review_queue import validate_candidate_format

        # Public routable IP
        is_valid, reason = validate_candidate_format("ipv4", "198.51.100.24", "198.51.100.24")
        assert is_valid is True
        assert "VALID: routable public IPv4" in reason

        # RFC 1918 private IP
        is_valid, reason = validate_candidate_format("ipv4", "192.168.1.1", "192.168.1.1")
        assert is_valid is False
        assert "RFC 1918 private IP" in reason

        # Software version User-Agent
        is_valid, reason = validate_candidate_format(
            "ipv4", "116.0.0.0", "116.0.0.0", line="User-Agent: Mozilla/5.0 Chrome/116.0.0.0"
        )
        assert is_valid is False
        assert "software version" in reason

    def test_domain_and_url_validation(self):
        from eval.generate_review_queue import validate_candidate_format

        # Legitimate domain
        is_valid, reason = validate_candidate_format("domain", "c2-node.net", "c2-node.net")
        assert is_valid is True
        assert "VALID: well-formed domain" in reason

        # File extension artifact
        is_valid, reason = validate_candidate_format("domain", "manual.pdf", "manual.pdf")
        assert is_valid is False
        assert "file extension artifact" in reason

        # Reference domain
        is_valid, reason = validate_candidate_format("domain", "cisa.gov", "cisa.gov")
        assert is_valid is True
        assert "FLAG: reference authority" in reason

        # Platform URL
        is_valid, reason = validate_candidate_format("url", "https://github.com/tool", "https://github.com/tool")
        assert is_valid is True
        assert "FLAG: platform-hosted URL" in reason

    def test_priority_computation(self):
        from eval.generate_review_queue import compute_review_priority_and_hint

        # Permissive discovery only
        prio, hint = compute_review_priority_and_hint(
            "ipv4", "198.51.100.1", "permissive_discovery", True, "VALID: routable public IPv4"
        )
        assert "HIGH: Potential False Negative" in prio
        assert "missed or excluded" in hint

        # Concordant clean candidate
        prio, hint = compute_review_priority_and_hint(
            "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "both", True, "VALID: 64-character hexadecimal SHA256"
        )
        assert "LOW: Concordant Detection" in prio


class TestAutomatedQueueIntegrity:
    def test_integrity_detects_anomalies(self, tmp_path):
        from eval.generate_review_queue import check_review_queue_integrity

        rows = [
            # Valid row
            {
                "report_filename": "cisa_aa22_187a_maui_ransomware.pdf",
                "source_page": 1,
                "ioc_type": "sha256",
                "raw_candidate": "d41d8cd98f00b204e9800998ecf8427e",
                "normalized_value": "d41d8cd98f00b204e9800998ecf8427e",
                "format_valid": "VALID: 32-character hexadecimal MD5",
                "context_snippet": "Valid snippet of text from page 1",
            },
            # Malformed row
            {
                "report_filename": "cisa_aa22_187a_maui_ransomware.pdf",
                "source_page": 1,
                "ioc_type": "ipv4",
                "raw_candidate": "192.168.1.1",
                "normalized_value": "192.168.1.1",
                "format_valid": "INVALID: RFC 1918 private IP",
                "context_snippet": "Private IP traffic observed",
            },
            # Duplicate row
            {
                "report_filename": "cisa_aa22_187a_maui_ransomware.pdf",
                "source_page": 1,
                "ioc_type": "sha256",
                "raw_candidate": "d41d8cd98f00b204e9800998ecf8427e",
                "normalized_value": "d41d8cd98f00b204e9800998ecf8427e",
                "format_valid": "VALID: 32-character hexadecimal MD5",
                "context_snippet": "Valid snippet duplicate",
            },
            # Missing evidence row
            {
                "report_filename": "cisa_aa22_187a_maui_ransomware.pdf",
                "source_page": 2,
                "ioc_type": "cve",
                "raw_candidate": "CVE-2022-1234",
                "normalized_value": "CVE-2022-1234",
                "format_valid": "VALID: standard CVE identifier",
                "context_snippet": "",
            },
            # Invalid page number row
            {
                "report_filename": "cisa_aa22_187a_maui_ransomware.pdf",
                "source_page": 999,  # Maui report only has 7 pages
                "ioc_type": "cve",
                "raw_candidate": "CVE-2022-1234",
                "normalized_value": "CVE-2022-1234",
                "format_valid": "VALID: standard CVE identifier",
                "context_snippet": "Text on invalid page",
            },
        ]
        pdf_dir = Path("eval/raw_reports")
        issues = check_review_queue_integrity(rows, pdf_dir)

        assert len(issues["malformed_values"]) == 1
        assert len(issues["duplicate_candidates"]) == 1
        assert len(issues["missing_evidence"]) == 1
        assert len(issues["invalid_page_numbers"]) == 1


class TestFalseNegativeAuditWorkflow:
    def test_add_manual_ioc_to_queue(self, tmp_path):
        from eval.fn_audit import add_manual_ioc_to_queue

        csv_file = tmp_path / "manual_queue.csv"
        pdf_dir = Path("eval/raw_reports")
        add_manual_ioc_to_queue(
            csv_file,
            pdf_dir,
            "cisa_aa22_187a_maui_ransomware.pdf",
            page_number=1,
            ioc_type="cve",
            raw_value="CVE-2022-9999",
            evidence="Discovered in paragraph 3 discussing Maui exploitation",
            notes="Identified during manual page inspection",
            label="true_ioc",
        )

        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["source_origin"] == "manual_inspection"
        assert row["label"] == "true_ioc"
        assert row["normalized_value"] == "CVE-2022-9999"
        assert "Discovered in paragraph 3" in row["context_snippet"]

    def test_markdown_review_report_generation(self, tmp_path):
        from eval.generate_review_queue import generate_markdown_review_report

        rows = [
            {
                "report_filename": "sample_report.pdf",
                "source_page": 1,
                "ioc_type": "ipv4",
                "raw_candidate": "198.51.100.1",
                "normalized_value": "198.51.100.1",
                "source_origin": "both",
                "format_valid": "VALID: routable public IPv4",
                "review_priority": "LOW: Concordant Detection",
                "review_hint": "Confirm adversary context",
                "context_snippet": "Connected to 198.51.100.1",
                "surrounding_context": "Preceding line // Connected to 198.51.100.1 // Following line",
                "reviewer_notes": "",
            }
        ]
        md_file = tmp_path / "review.md"
        generate_markdown_review_report(rows, md_file)

        assert md_file.is_file()
        content = md_file.read_text(encoding="utf-8")
        assert "## Report: `sample_report.pdf`" in content
        assert "### Page 1" in content
        assert "198.51.100.1" in content
        assert "Analyst Decision:" in content


class TestSourceIntegrityAndAccounting:
    def test_review_queue_subset_csv_unmodified(self):
        """
        Safeguard 1: Preserve eval/review_queue_subset.csv byte-for-byte.
        SHA-256 must match exactly 117a5ad45d4ec8e1a8e224a98e53b6e34436f7f6a7e78e4fa48c23a2a856b1a1.
        """
        import hashlib
        src = Path("eval/review_queue_subset.csv")
        assert src.is_file(), "eval/review_queue_subset.csv must exist"
        data = src.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        assert sha256 == "117a5ad45d4ec8e1a8e224a98e53b6e34436f7f6a7e78e4fa48c23a2a856b1a1", (
            f"eval/review_queue_subset.csv was modified! SHA-256: {sha256}"
        )

    def test_manual_review_csv_structure_and_verified_annotations(self):
        """
        eval/manual_review.csv must retain all 13 original columns plus 5 human review columns.
        All 139 rows are verified with verbatim evidence, notes, and reviewer signature.
        """
        manual_csv = Path("eval/manual_review.csv")
        assert manual_csv.is_file(), "eval/manual_review.csv must exist"
        with open(manual_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            rows = list(reader)

        expected_columns = [
            "report_filename", "source_page", "ioc_type", "raw_candidate", "normalized_value",
            "source_origin", "format_valid", "review_priority", "review_hint", "label",
            "context_snippet", "surrounding_context", "reviewer_notes",
            "ai_suggested_label", "human_label", "human_evidence", "human_notes", "reviewed_by",
        ]
        assert fieldnames == expected_columns
        assert len(rows) == 139
        assert all(r["human_label"] in ("true_ioc", "not_ioc", "uncertain") for r in rows)
        assert all(r["human_evidence"] != "" for r in rows)
        assert all(r["human_notes"] != "" for r in rows)
        assert all(r["reviewed_by"] == "Lead Analyst Ashhal" for r in rows)
        assert all(r["ai_suggested_label"] == r["label"] for r in rows)

    def test_row_count_vs_unique_indicator_distinction(self):
        """
        Safeguard 8: Clearly distinguish annotation row counts from unique IOC counts.
        139 annotation rows in manual_review.csv represent 119 unique indicators across the reports.
        """
        stats = audit_review_queue(Path("eval/manual_review.csv"))
        assert stats["total_annotation_rows"] == 139
        assert stats["unique_indicators_count"] == 119
        assert stats["has_active_human_reviews"] is True
        # Verified counts: 65 true_ioc (59 unique), 71 not_ioc (57 unique), 3 uncertain (3 unique)
        assert stats["label_counts_rows"]["true_ioc"] == 65
        assert stats["label_counts_rows"]["not_ioc"] == 71
        assert stats["label_counts_rows"]["uncertain"] == 3
        assert stats["label_counts_unique"]["true_ioc"] == 59
        assert stats["label_counts_unique"]["not_ioc"] == 57
        assert stats["label_counts_unique"]["uncertain"] == 3


class TestHumanEvidenceValidation:
    def test_human_evidence_verbatim_provenance_success(self):
        """
        Verbatim PDF quote verifies source provenance and non-empty notes justify decision.
        """
        row = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "ipv4",
            "normalized_value": "198.51.100.1",
            "human_label": "true_ioc",
            "human_evidence": "Adversary connected to 198.51.100.1 C2 server",
            "human_notes": "Observed active C2 communication during lateral movement phase.",
            "reviewed_by": "Lead Analyst Ashhal",
        }
        pages = [{"page_number": 1, "page_text": "Sample text. Adversary connected to 198.51.100.1 C2 server on port 443."}]
        # Should validate without error
        validate_review_row(row, row_idx=2, pdf_pages=pages, enforce_human_validation=True)

    def test_human_evidence_missing_raises_error(self):
        """
        Safeguard 3: Require human justification. Never silently convert unsupported decision.
        """
        row = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "ipv4",
            "normalized_value": "198.51.100.1",
            "human_label": "true_ioc",
            "human_evidence": "",  # Missing
            "human_notes": "Justification",
            "reviewed_by": "Analyst",
        }
        with pytest.raises(ValueError, match="requires non-empty 'human_evidence'"):
            validate_review_row(row, row_idx=2, enforce_human_validation=True)

    def test_human_notes_and_signature_required(self):
        """
        Verified labels require human justification and reviewer signature.
        """
        row_no_notes = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "ipv4",
            "normalized_value": "198.51.100.1",
            "human_label": "true_ioc",
            "human_evidence": "Evidence quote",
            "human_notes": "",  # Missing notes
            "reviewed_by": "Analyst",
        }
        with pytest.raises(ValueError, match="requires non-empty 'human_notes' justification"):
            validate_review_row(row_no_notes, row_idx=2, enforce_human_validation=True)

        row_no_reviewer = dict(row_no_notes, human_notes="Valid notes", reviewed_by="")
        with pytest.raises(ValueError, match="requires 'reviewed_by' analyst signature"):
            validate_review_row(row_no_reviewer, row_idx=3, enforce_human_validation=True)

    def test_human_evidence_unlocated_text_raises_error(self):
        """
        If human evidence quote does not appear verbatim on that page, raise ValueError.
        """
        row = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "ipv4",
            "normalized_value": "198.51.100.1",
            "human_label": "not_ioc",
            "human_evidence": "Fabricated text not in document",
            "human_notes": "Benign documentation reference",
            "reviewed_by": "Analyst",
        }
        pages = [{"page_number": 1, "page_text": "Real page text about unrelated topics."}]
        with pytest.raises(ValueError, match="quote was not found verbatim"):
            validate_review_row(row, row_idx=2, pdf_pages=pages, enforce_human_validation=True)

    def test_uncertain_requires_notes(self):
        """
        'uncertain' label requires explanatory notes explaining ambiguity.
        """
        row = {
            "report_filename": "test.pdf",
            "source_page": "1",
            "ioc_type": "domain",
            "normalized_value": "alexantr/filemanager",
            "human_label": "uncertain",
            "human_notes": "",
            "reviewed_by": "Analyst",
        }
        with pytest.raises(ValueError, match="requires 'human_notes' explaining ambiguity"):
            validate_review_row(row, row_idx=2, enforce_human_validation=True)


class TestWorkflowSafeguardsAndNegativeControls:
    def test_negative_control_rejection_rate_calculation(self, tmp_path):
        """
        Safeguards 4 & 5:
        Treat confirmed-negative rejection as a negative-control metric.
        Do not call it general specificity.
        """
        csv_file = tmp_path / "review_neg.csv"
        csv_file.write_text(
            "report_filename,source_page,ioc_type,raw_candidate,normalized_value,source_origin,label,context_snippet,reviewer_notes,ai_suggested_label,human_label,human_evidence,human_notes,reviewed_by\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,both,true_ioc,snippet1,notes,true_ioc,true_ioc,Evidence 1,Notes 1,Analyst\n"
            "cisa_aa22_187a_maui_ransomware.pdf,2,domain,example.com,example.com,permissive_discovery,not_ioc,doc link,notes,not_ioc,not_ioc,Evidence 2,Notes 2,Analyst\n"
            "cisa_aa22_187a_maui_ransomware.pdf,3,domain,benign-ref.org,benign-ref.org,permissive_discovery,not_ioc,doc link,notes,not_ioc,not_ioc,Evidence 3,Notes 3,Analyst\n",
            encoding="utf-8",
        )
        pdf_dir = Path("eval/raw_reports")
        results = evaluate_review_queue(csv_file, pdf_dir, page_aware=False)

        neg = results["negative_control_metrics"]
        assert neg["total_confirmed_negatives"] == 2
        # Extractor correctly did NOT extract example.com or benign-ref.org
        assert neg["negatives_rejected"] == 2
        assert neg["confirmed_false_positives"] == 0
        assert neg["negative_control_rejection_rate"] == 1.0
        assert "negative-control metric, NOT general specificity" in neg["metric_semantics"]

    def test_uncertain_candidates_isolated_in_neutral_reserve(self, tmp_path):
        """
        Uncertain predictions must NOT penalize precision, recall, or count as false positives.
        """
        csv_file = tmp_path / "review_unc.csv"
        csv_file.write_text(
            "report_filename,source_page,ioc_type,raw_candidate,normalized_value,source_origin,label,context_snippet,reviewer_notes,ai_suggested_label,human_label,human_evidence,human_notes,reviewed_by\n"
            "cisa_aa22_187a_maui_ransomware.pdf,2,sha256,5b7ecf7e9d0715f1122baf4ce745c5fcd769dee48150616753fec4d6da16e99e,5b7ecf7e9d0715f1122baf4ce745c5fcd769dee48150616753fec4d6da16e99e,both,true_ioc,snippet1,notes,true_ioc,true_ioc,Evidence 1,Notes 1,Analyst\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,domain,alexantr/filemanager,alexantr/filemanager,both,uncertain,snippet2,ambiguous,uncertain,uncertain,Evidence 2,Ambiguous component,Analyst\n",
            encoding="utf-8",
        )
        pdf_dir = Path("eval/raw_reports")
        results = evaluate_review_queue(csv_file, pdf_dir, page_aware=False)

        cand = results["candidate_level_metrics"]
        # sha256 should have TP=1, confirmed_fp=0, fn=0 -> precision=1.0, recall=1.0
        sha = cand["per_category"]["sha256"]
        assert sha["tp"] == 1
        assert sha["confirmed_fp"] == 0
        assert sha["fn"] == 0
        assert sha["candidate_precision"] == 1.0
        assert sha["candidate_recall"] == 1.0

        # alexantr/filemanager must not be counted as confirmed FP
        dom = cand["per_category"]["domain"]
        assert dom["confirmed_fp"] == 0
        assert results["open_world_extraction"]["uncertain_predictions_count"] >= 0

    def test_unreviewed_queue_prevents_false_claims(self, tmp_path):
        """
        Safeguards 8 & 10: All human labels must remain unreviewed until personal review.
        Evaluating an unreviewed queue reports 0 verified true IOCs.
        """
        # Create unreviewed queue fixture
        unrev_csv = tmp_path / "unreviewed_test.csv"
        manual_rows = list(csv.DictReader(open("eval/manual_review.csv", encoding="utf-8")))
        for r in manual_rows:
            r["human_label"] = "unreviewed"
            r["human_evidence"] = ""
            r["human_notes"] = ""
            r["reviewed_by"] = ""
        with open(unrev_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(manual_rows[0].keys()))
            w.writeheader()
            w.writerows(manual_rows)

        results = evaluate_review_queue(unrev_csv, Path("eval/raw_reports"))
        scope = results["evaluation_scope"]
        assert scope["verified_true_ioc_count"] == 0
        assert scope["unreviewed_count"] == 139
        assert scope["is_fully_reviewed"] is False
        assert scope["is_human_review_mode"] is False

    def test_reviewed_queue_active_human_mode(self):
        """
        Evaluating the verified eval/manual_review.csv reports full review completeness,
        active human review mode, and 65 verified true IOC candidates (59 unique).
        """
        results = evaluate_review_queue(Path("eval/manual_review.csv"), Path("eval/raw_reports"))
        scope = results["evaluation_scope"]
        assert scope["verified_true_ioc_count"] == 65
        assert scope["verified_not_ioc_count"] == 71
        assert scope["uncertain_count"] == 3
        assert scope["unreviewed_count"] == 0
        assert scope["is_fully_reviewed"] is True
        assert scope["is_human_review_mode"] is True

    def test_dataset_json_export_with_negative_controls(self, tmp_path):
        """
        Dataset conversion exports confirmed negatives and uncertain candidates cleanly.
        """
        csv_file = tmp_path / "review_export.csv"
        csv_file.write_text(
            "report_filename,source_page,ioc_type,raw_candidate,normalized_value,source_origin,label,context_snippet,reviewer_notes,ai_suggested_label,human_label,human_evidence,human_notes,reviewed_by\n"
            "cisa_aa22_187a_maui_ransomware.pdf,1,md5,d41d8cd98f00b204e9800998ecf8427e,d41d8cd98f00b204e9800998ecf8427e,both,true_ioc,snippet1,notes,true_ioc,true_ioc,Ev 1,Notes 1,Analyst\n"
            "cisa_aa22_187a_maui_ransomware.pdf,2,domain,example.com,example.com,permissive_discovery,not_ioc,doc link,notes,not_ioc,not_ioc,Ev 2,Notes 2,Analyst\n"
            "cisa_aa22_187a_maui_ransomware.pdf,3,domain,alexantr/filemanager,alexantr/filemanager,both,uncertain,snippet3,ambig,uncertain,uncertain,Ev 3,Notes 3,Analyst\n",
            encoding="utf-8",
        )
        pdf_dir = Path("eval/raw_reports")
        out_json = tmp_path / "verified_dataset.json"
        stats = audit_review_queue(csv_file)
        convert_review_to_dataset(stats, pdf_dir, out_json)

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 1
        rec = data[0]
        assert len(rec["ground_truth"]) == 1
        assert len(rec["confirmed_negatives"]) == 1
        assert len(rec["uncertain_candidates"]) == 1
        assert rec["ground_truth"][0]["value"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert rec["confirmed_negatives"][0]["value"] == "example.com"
        assert rec["uncertain_candidates"][0]["value"] == "alexantr/filemanager"
        assert rec["verification_status"] == "human_verified"

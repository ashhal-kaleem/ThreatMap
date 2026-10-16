"""
Candidate Review Queue Generator for ThreatMap Lite.
Module: PDF Processing & IOC Intelligence

Generates a human-auditable CSV review queue and Markdown review report by unioning:
1. Permissive, independent regex candidate discovery (to capture potential false negatives).
2. Production extractor predictions (to capture potential false positives and true positives).

Key Capabilities:
- Evidence snippets with expanded multi-line surrounding context.
- Format validation checks for each IOC type (routable IPv4, clean domains, valid hashes, standard CVEs).
- Review-priority and review-hint fields to guide human analysts.
- Automated integrity validation (malformed candidates, duplicate rows, missing evidence, unlocated text).
- Markdown review report generation grouped by PDF and source page with decision guidelines.

STRICT RULE:
All emitted candidate rows are assigned label='unreviewed'.
Neither 'true_ioc' nor 'not_ioc' labels are ever automatically assigned.
Ambiguous candidates remain eligible for 'uncertain'.
"""

import argparse
import csv
import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.pdf_service import PageText, extract_pages
from backend.app.services.ioc_service import (
    clean_url,
    extract_iocs,
    normalize_defanged,
)
from eval.ioc_eval import SUPPORTED_IOC_TYPES, normalize_ground_truth_value

# Representative benchmark subset covering all 7 IOC categories across 30 total pages
REPRESENTATIVE_SUBSET = (
    "cisa_aa24_016a_androxgh0st_iocs.pdf",        # 13 pages: ipv4, domain, url, sha256, cve
    "cisa_aa22_152a_karakurt_data_extortion.pdf",   # 10 pages: url, sha1, sha256, cve
    "cisa_aa22_187a_maui_ransomware.pdf",          # 7 pages:  md5, sha256
)

# Reference domains and platform hosting providers
PLATFORM_HOSTING_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "pastebin.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
}
REFERENCE_DOMAINS = {
    "cisa.gov", "ncsc.gov.uk", "cert.ssi.gouv.fr", "microsoft.com",
    "mitre.org", "virustotal.com", "example.com", "iana.org",
}
FILE_EXTENSIONS = {
    "pdf", "exe", "dll", "zip", "tar", "gz", "tgz", "bin", "sh", "py",
    "php", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png",
    "jpg", "jpeg", "gif", "svg", "html", "htm", "xml", "json", "yml",
    "yaml", "css", "js", "go", "ps1", "elf", "so", "sys", "dat",
}

# Independent, permissive discovery regex patterns
PERMISSIVE_PATTERNS = {
    "cve": re.compile(r"(?i)\bCVE[-_]\d{4}[-_]\d{4,7}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "url": re.compile(r"(?:https?|hxxps?|ftp)(?::|\[:\])?//[^\s<>\"\'\)]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}(?:\.|\s*\[\.\]\s*|\s*\(\.\)\s*)){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-zA-Z0-9_\-]+(?:\.|\s*\[\.\]\s*|\s*\(\.\)\s*)+(?:[a-zA-Z0-9_\-]+\.)*[a-zA-Z]{2,}\b"),
}

CSV_FIELDNAMES = [
    "report_filename",
    "source_page",
    "ioc_type",
    "raw_candidate",
    "normalized_value",
    "source_origin",
    "format_valid",
    "review_priority",
    "review_hint",
    "label",
    "context_snippet",
    "surrounding_context",
    "reviewer_notes",
]


def validate_candidate_format(ioc_type: str, raw: str, norm: str, line: str = "") -> tuple[bool, str]:
    """
    Validates syntax and format rules for an IOC candidate string.
    Returns: (is_valid: bool, status_reason: str)
    """
    if ioc_type == "ipv4":
        octs = norm.split(".")
        if len(octs) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octs):
            return False, "INVALID: malformed octets"
        if any(len(o) > 1 and o.startswith("0") for o in octs):
            return False, "INVALID: octet with leading zero"
        try:
            addr = ipaddress.IPv4Address(norm)
            rfc1918 = (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
            if any(addr in net for net in rfc1918):
                return False, "INVALID: RFC 1918 private IP"
            if addr.is_loopback:
                return False, "INVALID: loopback address"
            if addr.is_multicast:
                return False, "INVALID: multicast address"
            if addr.is_unspecified:
                return False, "INVALID: unspecified IP (0.0.0.0)"
        except ValueError:
            return False, "INVALID: unparseable IPv4"

        # Check for version string indicators
        if re.search(r"(?:Chrome|Safari|Firefox|Edge|Edg|Version|build)/[0-9.]*$", line[:line.find(raw)] if raw in line else "", re.IGNORECASE):
            return False, "INVALID: software version or User-Agent string"

        # Subnet/broadcast boundaries
        if (octs[2] == "0" and octs[3] == "0") or (octs[2] == "255" and octs[3] == "255"):
            return False, "INVALID: /16 boundary address"

        return True, "VALID: routable public IPv4"

    if ioc_type == "domain":
        if "." not in norm:
            return False, "INVALID: missing dot"
        labels = norm.split(".")
        tld = labels[-1].lower()
        if tld in FILE_EXTENSIONS:
            return False, f"INVALID: file extension artifact (.{tld})"
        if re.search(r"\.[a-zA-Z]+\(\)", raw):
            return False, "INVALID: code method call"
        if any(norm.startswith(p) for p in ("java.", "javax.", "org.apache.", "com.sun.")):
            return False, "INVALID: programming language package prefix"
        if norm in REFERENCE_DOMAINS or any(norm.endswith(f".{rd}") for rd in REFERENCE_DOMAINS):
            return True, "FLAG: reference authority domain"
        if norm in PLATFORM_HOSTING_DOMAINS or any(norm.endswith(f".{pd}") for pd in PLATFORM_HOSTING_DOMAINS):
            return True, "FLAG: platform hosting domain"
        if not tld.isalpha() or len(tld) < 2:
            return False, "INVALID: non-alphabetic or short TLD"
        return True, "VALID: well-formed domain"

    if ioc_type == "url":
        if not re.match(r"^https?://", norm, re.IGNORECASE):
            return False, "INVALID: protocol missing or unsupported"
        host_match = re.search(r"https?://([^/:\s]+)", norm, re.IGNORECASE)
        if not host_match:
            return False, "INVALID: unparseable host in URL"
        host = host_match.group(1).lower()
        if any(rd in host for rd in REFERENCE_DOMAINS):
            return True, "FLAG: reference authority link"
        if any(pd in host for pd in PLATFORM_HOSTING_DOMAINS):
            if any(part in norm.lower() for part in ("/raw/", "/download", "/releases/download")):
                return True, "VALID: platform raw payload / download endpoint"
            return True, "FLAG: platform-hosted URL (requires threat context verification)"
        return True, "VALID: well-formed URL"

    if ioc_type == "cve":
        if not re.match(r"^CVE-\d{4}-\d{4,}$", norm):
            return False, "INVALID: non-standard CVE format"
        seq = norm.split("-")[-1]
        if len(seq) >= 6 and int(seq) > 60000:
            return True, "FLAG: possible footnote concatenation"
        return True, "VALID: standard CVE identifier"

    if ioc_type == "md5":
        if len(norm) == 32 and all(c in "0123456789abcdef" for c in norm):
            return True, "VALID: 32-character hexadecimal MD5"
        return False, "INVALID: non-hex or invalid MD5 length"

    if ioc_type == "sha1":
        if len(norm) == 40 and all(c in "0123456789abcdef" for c in norm):
            return True, "VALID: 40-character hexadecimal SHA1"
        return False, "INVALID: non-hex or invalid SHA1 length"

    if ioc_type == "sha256":
        if len(norm) == 64 and all(c in "0123456789abcdef" for c in norm):
            return True, "VALID: 64-character hexadecimal SHA256"
        return False, "INVALID: non-hex or invalid SHA256 length"

    return False, f"INVALID: unknown IOC type '{ioc_type}'"


def compute_review_priority_and_hint(
    ioc_type: str,
    norm: str,
    origin: str,
    format_valid: bool,
    format_reason: str,
    context: str = "",
) -> tuple[str, str]:
    """
    Computes a human-readable review priority and actionable review hint for analysts.
    Returns: (priority: str, hint: str)
    """
    if origin == "permissive_discovery":
        if not format_valid:
            return (
                "HIGH: Syntax Anomaly (Permissive Only)",
                f"Filtered by production extractor ({format_reason}). Confirm if benign text, version number, or artifact.",
            )
        return (
            "HIGH: Potential False Negative (Permissive Only)",
            f"Extracted by permissive regex but missed or excluded by production filters. Check if this is a genuine adversary IOC.",
        )

    if "FLAG: platform-hosted" in format_reason:
        return (
            "HIGH: Platform URL Context Audit",
            "Platform-hosted URL. Confirm if listed as an adversary tool/drop in an IOC section or an ordinary documentation link.",
        )

    if not format_valid:
        return (
            "HIGH: Potential False Positive in Production",
            f"Extracted by production service but flagged during format check: {format_reason}. Audit carefully.",
        )

    if origin == "production_extractor":
        return (
            "MEDIUM: Production Extractor Only",
            "Extracted by production extractor heuristics (e.g., line reconstruction or defanged IP). Confirm presence in source text.",
        )

    if "FLAG: reference authority" in format_reason:
        return (
            "MEDIUM: Security Reference Authority",
            "Belongs to an advisory, vendor, or standards body. Typically 'not_ioc' unless explicitly staged as target infrastructure.",
        )

    # Concordant clean candidates
    return (
        "LOW: Concordant Detection (Both Systems)",
        "Detected by both independent regex and production extractor with valid syntax. Confirm malicious intent from surrounding context.",
    )


def extract_permissive_candidates(pages: list[PageText]) -> list[dict[str, Any]]:
    """
    Performs an independent, permissive candidate discovery pass over page text.
    Captures potential False Negatives by bypassing production negative filters.
    """
    candidates: list[dict[str, Any]] = []

    for page in pages:
        page_num = int(page.get("page_number", 1))
        text = page.get("page_text") or page.get("text") or ""
        lines = text.splitlines()

        for idx, line in enumerate(lines):
            trimmed = line.strip()
            if not trimmed:
                continue

            # Multi-line surrounding context (2 lines before, current line, 2 lines after)
            ctx_start = max(0, idx - 2)
            ctx_end = min(len(lines), idx + 3)
            surrounding = " // ".join(l.strip() for l in lines[ctx_start:ctx_end] if l.strip())

            # 1. Permissive CVE
            for m in PERMISSIVE_PATTERNS["cve"].finditer(line):
                raw = m.group(0)
                norm = normalize_ground_truth_value("cve", raw)
                candidates.append({
                    "ioc_type": "cve",
                    "raw_candidate": raw,
                    "normalized_value": norm,
                    "source_page": page_num,
                    "context_snippet": trimmed[:180],
                    "surrounding_context": surrounding,
                    "matched_line": line,
                })

            # 2. Permissive SHA256
            for m in PERMISSIVE_PATTERNS["sha256"].finditer(line):
                raw = m.group(0)
                candidates.append({
                    "ioc_type": "sha256",
                    "raw_candidate": raw,
                    "normalized_value": raw.lower(),
                    "source_page": page_num,
                    "context_snippet": trimmed[:180],
                    "surrounding_context": surrounding,
                    "matched_line": line,
                })

            # 3. Permissive SHA1
            for m in PERMISSIVE_PATTERNS["sha1"].finditer(line):
                raw = m.group(0)
                candidates.append({
                    "ioc_type": "sha1",
                    "raw_candidate": raw,
                    "normalized_value": raw.lower(),
                    "source_page": page_num,
                    "context_snippet": trimmed[:180],
                    "surrounding_context": surrounding,
                    "matched_line": line,
                })

            # 4. Permissive MD5
            for m in PERMISSIVE_PATTERNS["md5"].finditer(line):
                raw = m.group(0)
                candidates.append({
                    "ioc_type": "md5",
                    "raw_candidate": raw,
                    "normalized_value": raw.lower(),
                    "source_page": page_num,
                    "context_snippet": trimmed[:180],
                    "surrounding_context": surrounding,
                    "matched_line": line,
                })

            # 5. Permissive URL
            for m in PERMISSIVE_PATTERNS["url"].finditer(line):
                raw = m.group(0)
                norm = clean_url(normalize_defanged(raw))
                candidates.append({
                    "ioc_type": "url",
                    "raw_candidate": raw,
                    "normalized_value": norm,
                    "source_page": page_num,
                    "context_snippet": trimmed[:180],
                    "surrounding_context": surrounding,
                    "matched_line": line,
                })

            # 6. Permissive IPv4
            for m in PERMISSIVE_PATTERNS["ipv4"].finditer(line):
                raw = m.group(0)
                norm = normalize_defanged(raw)
                octs = norm.split(".")
                if len(octs) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octs):
                    candidates.append({
                        "ioc_type": "ipv4",
                        "raw_candidate": raw,
                        "normalized_value": norm,
                        "source_page": page_num,
                        "context_snippet": trimmed[:180],
                        "surrounding_context": surrounding,
                        "matched_line": line,
                    })

            # 7. Permissive Domain
            mask_line = line
            for m in PERMISSIVE_PATTERNS["url"].finditer(line):
                mask_line = mask_line.replace(m.group(0), " " * len(m.group(0)))

            for m in PERMISSIVE_PATTERNS["domain"].finditer(mask_line):
                raw = m.group(0)
                norm = normalize_defanged(raw).lower().strip(".")
                if "." in norm and not all(p.isdigit() for p in norm.split(".")):
                    candidates.append({
                        "ioc_type": "domain",
                        "raw_candidate": raw,
                        "normalized_value": norm,
                        "source_page": page_num,
                        "context_snippet": trimmed[:180],
                        "surrounding_context": surrounding,
                        "matched_line": line,
                    })

    return candidates


def generate_queue_for_pdf(pdf_path: Path) -> list[dict[str, Any]]:
    """
    Extracts candidates from a PDF via permissive discovery and production extractor,
    performing format validation and review priority computation for each row.
    """
    pages = extract_pages(pdf_path)
    if not pages:
        return []

    permissive_cands = extract_permissive_candidates(pages)
    prod_iocs = extract_iocs(pages)

    merged: dict[tuple[str, str, int], dict[str, Any]] = {}

    for c in permissive_cands:
        key = (c["ioc_type"], c["normalized_value"], c["source_page"])
        is_valid, reason = validate_candidate_format(
            c["ioc_type"], c["raw_candidate"], c["normalized_value"], c.get("matched_line", "")
        )
        prio, hint = compute_review_priority_and_hint(
            c["ioc_type"], c["normalized_value"], "permissive_discovery", is_valid, reason
        )
        merged[key] = {
            "report_filename": pdf_path.name,
            "source_page": c["source_page"],
            "ioc_type": c["ioc_type"],
            "raw_candidate": c["raw_candidate"],
            "normalized_value": c["normalized_value"],
            "source_origin": "permissive_discovery",
            "format_valid": reason,
            "review_priority": prio,
            "review_hint": hint,
            "label": "unreviewed",
            "context_snippet": c["context_snippet"],
            "surrounding_context": c.get("surrounding_context", c["context_snippet"]),
            "reviewer_notes": "",
        }

    for p in prod_iocs:
        key = (p["type"], p["value"], int(p["source_page"]))
        if key in merged:
            merged[key]["source_origin"] = "both"
            # Recompute priority with concordant origin
            is_valid, reason = validate_candidate_format(p["type"], p["value"], p["value"])
            prio, hint = compute_review_priority_and_hint(p["type"], p["value"], "both", is_valid, reason)
            merged[key]["review_priority"] = prio
            merged[key]["review_hint"] = hint
            if p.get("evidence"):
                merged[key]["context_snippet"] = p["evidence"]
        else:
            is_valid, reason = validate_candidate_format(p["type"], p["value"], p["value"])
            prio, hint = compute_review_priority_and_hint(p["type"], p["value"], "production_extractor", is_valid, reason)
            merged[key] = {
                "report_filename": pdf_path.name,
                "source_page": int(p["source_page"]),
                "ioc_type": p["type"],
                "raw_candidate": p["value"],
                "normalized_value": p["value"],
                "source_origin": "production_extractor",
                "format_valid": reason,
                "review_priority": prio,
                "review_hint": hint,
                "label": "unreviewed",
                "context_snippet": p.get("evidence", ""),
                "surrounding_context": p.get("evidence", ""),
                "reviewer_notes": "",
            }

    sorted_rows = sorted(
        merged.values(),
        key=lambda r: (r["source_page"], r["ioc_type"], r["normalized_value"]),
    )
    return sorted_rows


def check_review_queue_integrity(
    queue_rows: list[dict[str, Any]],
    pdf_dir: Path,
) -> dict[str, list[dict[str, Any]]]:
    """
    Automated integrity checks on candidate queue rows:
    - malformed_values: Candidates violating syntax or validation rules.
    - duplicate_candidates: Exact duplicate candidates on the same page.
    - missing_evidence: Empty or near-empty context snippets.
    - invalid_page_numbers: Page number < 1 or exceeds total pages in source PDF.
    - unlocated_evidence: Evidence snippet or core tokens cannot be located in the PDF text.
    """
    issues: dict[str, list[dict[str, Any]]] = {
        "malformed_values": [],
        "duplicate_candidates": [],
        "missing_evidence": [],
        "invalid_page_numbers": [],
        "unlocated_evidence": [],
    }

    seen_keys: set[tuple[str, int, str, str]] = set()
    pdf_pages_cache: dict[str, list[PageText]] = {}

    for idx, row in enumerate(queue_rows, start=1):
        fn = row.get("report_filename", "").strip()
        t = row.get("ioc_type", "").strip()
        v = row.get("normalized_value", "").strip()
        raw = row.get("raw_candidate", "").strip()
        p_str = str(row.get("source_page", "")).strip()
        fmt = row.get("format_valid", "")
        ev = row.get("context_snippet", "").strip()

        # 1. Malformed check
        if fmt.startswith("INVALID"):
            issues["malformed_values"].append({"row": idx, "candidate": v, "type": t, "reason": fmt})

        # 2. Duplicate check
        key = (fn, int(p_str) if p_str.isdigit() else 0, t, v)
        if key in seen_keys:
            issues["duplicate_candidates"].append({"row": idx, "candidate": v, "type": t, "page": p_str})
        else:
            seen_keys.add(key)

        # 3. Missing evidence check
        if len(ev) < 5:
            issues["missing_evidence"].append({"row": idx, "candidate": v, "type": t})

        # 4. Page number & unlocated evidence checks
        if fn and p_str.isdigit():
            p_num = int(p_str)
            if fn not in pdf_pages_cache:
                pdf_path = pdf_dir / fn
                if pdf_path.is_file():
                    pdf_pages_cache[fn] = extract_pages(pdf_path)
                else:
                    pdf_pages_cache[fn] = []

            pages = pdf_pages_cache[fn]
            if p_num < 1 or (pages and p_num > len(pages)):
                issues["invalid_page_numbers"].append({"row": idx, "filename": fn, "page": p_num, "total_pages": len(pages)})
            elif pages:
                page_text = pages[p_num - 1].get("page_text") or pages[p_num - 1].get("text") or ""
                # Check if raw candidate or normalized core token appears on page
                core_val = v.split("://")[-1] if "://" in v else v
                norm_page_text = normalize_defanged(page_text).lower()
                found_in_text = (
                    raw.lower() in page_text.lower()
                    or core_val.lower() in page_text.lower()
                    or core_val.lower() in norm_page_text
                    or raw.lower() in norm_page_text
                    or any(part in page_text for part in core_val.split("/")[:2] if len(part) >= 4)
                )
                if not found_in_text:
                    issues["unlocated_evidence"].append({"row": idx, "candidate": raw or v, "page": p_num, "filename": fn})

    return issues


def generate_markdown_review_report(
    rows: list[dict[str, Any]],
    output_md: Path,
) -> None:
    """
    Generates a structured, human-readable Markdown review report grouped by
    source PDF filename and page number, complete with analyst decision checklists.
    """
    by_report_page: dict[str, dict[int, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        by_report_page[r["report_filename"]][int(r["source_page"])].append(r)

    lines: list[str] = [
        "# ThreatMap Lite - Human IOC Review Sheet",
        "",
        "**Purpose:** Review candidate indicators against source report pages.",
        "**Review Decision Guidelines:**",
        "- `[ ] true_ioc`: Confirmed adversary command-and-control, weaponized exploit, dropped malware payload, or threat infrastructure.",
        "- `[ ] not_ioc`: Confirmed benign prose, security advisory link, vendor scanner tool, software version, or documentation artifact.",
        "- `[ ] uncertain`: Ambiguous candidate requiring further malware reverse engineering or network traffic analysis.",
        "",
        "---",
        "",
    ]

    for rep in sorted(by_report_page.keys()):
        lines.append(f"## Report: `{rep}`")
        lines.append("")
        for page in sorted(by_report_page[rep].keys()):
            items = by_report_page[rep][page]
            lines.append(f"### Page {page} ({len(items)} candidates)")
            lines.append("")
            for idx, item in enumerate(items, start=1):
                lines.append(f"#### {idx}. `{item['ioc_type'].upper()}`: **`{item['normalized_value']}`**")
                lines.append(f"- **Raw Match:** `{item['raw_candidate']}`")
                lines.append(f"- **Origin:** `{item['source_origin']}` | **Priority:** `{item['review_priority']}`")
                lines.append(f"- **Format Validation:** `{item['format_valid']}`")
                lines.append(f"- **Review Hint:** *{item['review_hint']}*")
                lines.append(f"- **Evidence Snippet:** `{item['context_snippet']}`")
                lines.append(f"- **Surrounding Context:** *\"{item['surrounding_context']}\"*")
                lines.append(f"- **Analyst Decision:** `[ ] true_ioc` &nbsp;&nbsp; `[ ] not_ioc` &nbsp;&nbsp; `[ ] uncertain`")
                lines.append(f"- **Notes:** __________________________________________________")
                lines.append("")
            lines.append("---")
            lines.append("")

    output_md.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def build_review_queue(
    pdf_dir: Path,
    report_filenames: list[str],
    output_csv: Path,
    output_md: Path | None = None,
) -> int:
    """
    Builds the review queue CSV and optional Markdown review report.
    """
    all_rows: list[dict[str, Any]] = []

    print("=" * 80)
    print(f" GENERATING CANDIDATE REVIEW QUEUE ({len(report_filenames)} reports)")
    print("=" * 80)

    for fn in report_filenames:
        pdf_path = pdf_dir / fn
        if not pdf_path.is_file():
            print(f" [!] Warning: PDF not found: {pdf_path}", file=sys.stderr)
            continue

        print(f" -> Processing {fn} ...")
        rows = generate_queue_for_pdf(pdf_path)
        all_rows.extend(rows)
        print(f"    Extracted {len(rows)} candidates.")

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    # Automated integrity checks
    integrity = check_review_queue_integrity(all_rows, pdf_dir)
    print("\nAUTOMATED QUEUE INTEGRITY AUDIT:")
    print(f" - Duplicate candidates: {len(integrity['duplicate_candidates'])}")
    print(f" - Missing evidence:     {len(integrity['missing_evidence'])}")
    print(f" - Invalid page numbers: {len(integrity['invalid_page_numbers'])}")
    print(f" - Unlocated evidence:   {len(integrity['unlocated_evidence'])}")
    print(f" - Flagged/Malformed:    {len(integrity['malformed_values'])}")

    if output_md:
        generate_markdown_review_report(all_rows, output_md)
        print(f"\n[+] Generated readable Markdown review report: {output_md}")

    print("=" * 80)
    print(f" Successfully wrote {len(all_rows)} unreviewed candidates to: {output_csv}")
    print(" NOTE: All candidates have label='unreviewed'.")
    print(" Human reviewers must audit candidates and assign 'true_ioc', 'not_ioc', or 'uncertain'.")
    print("=" * 80)
    return len(all_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate human-auditable IOC review queue from PDFs.")
    parser.add_argument("--pdf-dir", type=Path, default=PROJECT_ROOT / "eval" / "raw_reports", help="Directory containing raw report PDFs.")
    parser.add_argument("--subset", action="store_true", help="Generate queue for the representative 3-report evaluation subset.")
    parser.add_argument("--all", action="store_true", help="Generate queue for all accepted reports.")
    parser.add_argument("--reports", nargs="+", help="Specific report filenames to process.")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "eval" / "review_queue.csv", help="Output CSV path.")
    parser.add_argument("--markdown-report", type=Path, help="Optional output Markdown review report path.")

    args = parser.parse_args()

    if args.subset:
        reports = list(REPRESENTATIVE_SUBSET)
    elif args.all:
        manifest_path = PROJECT_ROOT / "eval" / "raw_reports_manifest.csv"
        reports = []
        if manifest_path.is_file():
            with open(manifest_path, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                reports = [r["filename"] for r in reader if r.get("final_decision") == "ACCEPTED"]
        if not reports:
            reports = sorted([f.name for f in args.pdf_dir.glob("*.pdf")])
    elif args.reports:
        reports = args.reports
    else:
        reports = list(REPRESENTATIVE_SUBSET)

    build_review_queue(args.pdf_dir, reports, args.output, output_md=args.markdown_report)


if __name__ == "__main__":
    main()

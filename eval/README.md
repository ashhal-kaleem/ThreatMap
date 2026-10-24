# ThreatMap Lite - IOC Evaluation Framework

**Focus:** PDF Processing & IOC Intelligence  
**Location:** `eval/`  
**Target Service:** `backend/app/services/ioc_service.py` (`extract_iocs`)

---

## 1. Overview

The IOC Evaluation Framework provides deterministic, reproducible evaluation of ThreatMap Lite's regex-based Indicator of Compromise (IOC) extractor against annotated threat intelligence reports: a 139-row tuning set reviewed by a human (Ashhal) and a 1,028-row held-out set labelled with AI assistance and **not** human-verified (see "Held-out evaluation" below).

### Supported IOC Categories

| Category | Description | Extractor Normalization / Formatting |
| :--- | :--- | :--- |
| `ipv4` | Routable public IPv4 address | Refanged, valid octets (0–255), excludes RFC 1918 / loopback / multicast / broadcast |
| `domain` | FQDN domain name | Refanged, lowercased, stripped, excludes common file extensions (`.pdf`, `.exe`, etc.) |
| `url` | Web URL (HTTP/HTTPS) | Refanged (`hxxp` $\to$ `http`), trailing punctuation stripped, host validated |
| `md5` | 32-character hex hash | Lowercased |
| `sha1` | 40-character hex hash | Lowercased |
| `sha256` | 64-character hex hash | Lowercased |
| `cve` | Common Vulnerabilities and Exposures | Uppercased standardized format (`CVE-YYYY-NNNNN`) |

---

## 2. Evaluation Methodology & Matching Policy

### Matching Policies

1. **Unique per Report (Default)**:
   - Ground truth and predictions are deduplicated into distinct `(ioc_type, normalized_value)` pairs per report.
   - **Rationale:** Threat intelligence analysts care about identifying whether a threat indicator was discovered in the document. Counting the same IP or domain 20 times across multiple pages would artificially inflate recall or precision based on repetition frequency rather than extraction efficacy.

2. **Page-Aware (`--page-aware`)**:
   - Compares tuples of `(ioc_type, normalized_value, page_number)`.
   - **Rationale:** Useful for verifying spatial attribution when validating page citation accuracy.

### Metrics & Zero-Denominator Safety

- **True Positives (TP)**: Indicators present in both ground truth and extraction predictions.
- **False Positives (FP)**: Indicators extracted by the system that are absent from ground truth.
- **False Negatives (FN)**: Indicators present in ground truth that the system failed to extract.
- **Support**: Total ground-truth indicators ($TP + FN$).
- **Extracted**: Total predicted indicators ($TP + FP$).
- **Precision**: $\frac{TP}{TP + FP}$ (Safe handling: returns `0.0` if $TP + FP > 0$ and $TP == 0$; returns `None` if zero predictions).
- **Recall**: $\frac{TP}{TP + FN}$ (Safe handling: returns `0.0` if $TP + FN > 0$ and $TP == 0$; returns `None` if zero support).
- **F1 Score**: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$ (Safe handling: returns `0.0` when $P+R=0$; returns `None` if untested).

### Untested Category Handling

A category with zero ground truth ($Support = 0$) and zero predictions ($Extracted = 0$) is classified as **`UNTESTED`**.
- Its Precision, Recall, and F1 are reported as **`N/A` (`None`)**, **never** as $1.0$ or $100\%$.
- Untested categories are excluded from Macro-Average calculations so they do not artificially distort evaluation metrics.

### Aggregations

- **Micro Average**: Global aggregation of all $TP$, $FP$, and $FN$ across categories:
  $$\text{Micro Precision} = \frac{\sum TP}{\sum TP + \sum FP}, \quad \text{Micro Recall} = \frac{\sum TP}{\sum TP + \sum FN}$$
- **Macro Average**: Unweighted arithmetic mean of Precision, Recall, and F1 across **tested categories only** ($Support > 0 \lor Extracted > 0$).

---

## 3. Dataset Schema & Annotation Guidelines

### Ground-Truth Availability Status
> [!IMPORTANT]
> **Real ground-truth annotations across 15–20 real threat reports do not yet exist in the repository.**  
> Synthetic test fixtures in `eval/test_data/synthetic_test_reports.json` are explicitly marked `"synthetic": true` and are used solely for unit testing and CI verification. **Synthetic scores must never be claimed as production evaluation metrics.**

### Dataset Schema (`eval/dataset_schema.json`)

Each annotation file must be a JSON array of report objects:

```json
[
  {
    "report_id": "MANDIANT-APT29-2023",
    "synthetic": false,
    "source_file": "Mandiant_APT29.pdf",
    "notes": "Analyst notes on threat group campaign",
    "pages": [
      {
        "page_number": 1,
        "page_text": "Extracted text of page 1..."
      }
    ],
    "ground_truth": [
      {
        "type": "ipv4",
        "value": "198.51.100.24",
        "page_number": 1,
        "notes": "Adversary command and control IP"
      }
    ]
  }
]
```

### Manual Annotation Guidelines: Identifying Genuine IOCs

When annotating threat reports, analysts must distinguish true adversary Indicators of Compromise from benign infrastructure, technical prose, and file artifacts:

1. **IPv4 Addresses (`ipv4`)**:
   - **Annotate:** External, routable adversary IPs (e.g., C2 nodes, staging servers, scanning sources).
   - **Do NOT Annotate:** RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local (`169.254.x.x`), or multicast addresses. The production extractor automatically discards these.
   - **Normalizing:** Refang defanged octets (e.g., `198.51.100[.]24` $\to$ `198.51.100.24`).

2. **Domains (`domain`)**:
   - **Annotate:** Malicious adversary domains, dynamic DNS nodes, or phishing hostnames (e.g., `evil-update.com`, `c2-telemetry.org`).
   - **URL Host Domains:** If a malicious URL is present (e.g., `https://evil.com/payload.exe`), **also annotate `evil.com` as a domain IOC**, because the production extractor registers both the full URL and the host domain.
   - **Do NOT Annotate:** Benign security vendor sites (`cisa.gov`, `microsoft.com`, `mandiant.com`), standard protocol references, or file names mistakenly formatted like domains (`malware.exe`, `payload.bin`).

3. **URLs (`url`)**:
   - **Annotate:** Full malicious web endpoints (HTTP/HTTPS) used for malware download, exfiltration, or beaconing.
   - **Normalizing:** Refang protocols and dots (`hxxps[:]//bad[.]com/gate` $\to$ `https://bad.com/gate`). Strip trailing punctuation that belongs to sentences.

4. **Cryptographic Hashes (`md5`, `sha1`, `sha256`)**:
   - **Annotate:** Exact hashes of malware samples, dropped loaders, or webshells.
   - **Normalizing:** Lowercase all hex characters (e.g. `5D41...` $\to$ `5d41...`).
   - **Do NOT Annotate:** Trivial all-zero or all-F placeholders (e.g., `00000000...`), which the extractor discards.

5. **Vulnerabilities (`cve`)**:
   - **Annotate:** Specific CVE identifiers exploited in the campaign.
   - **Normalizing:** Standardize to uppercase `CVE-YYYY-NNNNN`.
   - **Do NOT Annotate:** Non-CVE advisory IDs (e.g. `MS17-010`, `KB5004442`), which belong to vendor bulletins rather than CVE format.

6. **Page Numbers & Deduplication**:
   - **First Appearance:** Record the page number where the indicator **first appears** in the document.
   - **Repeated Occurrences:** In unique evaluation mode (default), repeated mentions on subsequent pages are deduplicated to the first occurrence. In `--page-aware` mode, spatial attribution is checked against the specific page.

---

### Practical Checklist: Annotating 15–20 Public Threat Reports

Follow this structured workflow to establish an empirical evaluation benchmark:

- [ ] **Step 1: Curate 15–20 Public Reports**
  - Select public threat advisories (e.g. CISA Cybersecurity Advisories, Mandiant Threat Intelligence reports, Palo Alto Unit 42, Red Canary Threat Detection reports).
  - Ensure reports are publicly distributable under open government or fair-use educational licenses.
  - Save PDFs into an unversioned folder: `eval/raw_reports/`.

- [ ] **Step 2: Generate Annotation Skeletons**
  - Run the automated skeleton generator:
    ```powershell
    python -m eval.prepare_annotation_skeleton --pdf-dir eval/raw_reports/ --output eval/real_reports_ground_truth.json
    ```
  - This extracts text page-by-page using the production PyMuPDF service and leaves `ground_truth: []` arrays for human review.

- [ ] **Step 3: Conduct Human Annotation & Peer Review**
  - Open `eval/real_reports_ground_truth.json` in an editor.
  - Read through each report's page text, identify indicators, and add objects to `ground_truth` with `type`, `value`, `page_number`, and `notes`.
  - Ensure URL host domains are added alongside full URLs.

- [ ] **Step 4: Validate Dataset Completeness**
  - Execute the dataset validator:
    ```powershell
    python -m eval.prepare_annotation_skeleton --validate eval/real_reports_ground_truth.json
    ```
  - Confirm that schema conformity passes and zero unannotated reports remain.

- [ ] **Step 5: Run Production Evaluation & Export Metrics**
  - Execute the evaluator:
    ```powershell
    python -m eval.ioc_eval --dataset eval/real_reports_ground_truth.json --output eval/production_results.json -v
    ```
  - Record the actual per-category Precision, Recall, and F1 scores in your final viva documentation.

---

## 4. Ground-Truth Annotation & Precision/Recall Evaluation Workflow

To measure true precision and recall without fabricating labels or biasing the dataset towards the current extractor, ThreatMap Lite implements a human-auditable annotation workflow.

### Overview of Workflow Components

1. **`eval.generate_review_queue`**: Combines independent, permissive candidate discovery with production extractor predictions to produce a candidate CSV review queue.
2. **`eval.review_to_dataset`**: Audits reviewed CSV annotations, ensures label validity, and exports verified `true_ioc` records into standard dataset JSON format.
3. **`eval.evaluate_annotations`**: Evaluates production extractor predictions against the human-audited review queue, computing Micro/Macro Precision, Recall, and F1 with zero-denominator safety.

---

### CSV Review Queue Schema (`eval/review_queue.csv`)

| Column | Description | Valid Values |
| :--- | :--- | :--- |
| `report_filename` | PDF report file in `eval/raw_reports/` | e.g. `cisa_aa24_016a_androxgh0st_iocs.pdf` |
| `source_page` | 1-based page number where the candidate appears | Integer $\ge 1$ |
| `ioc_type` | Supported IOC category | `ipv4`, `domain`, `url`, `md5`, `sha1`, `sha256`, `cve` |
| `raw_candidate` | Exact text matched from the PDF page | String |
| `normalized_value` | Standardized form used for matching | Lowercase hash, standardized IP/domain/CVE |
| `source_origin` | Provenance of the candidate | `both`, `permissive_discovery`, `production_extractor`, `manual_inspection` |
| `label` | Human analyst verification status | `unreviewed` (default), `true_ioc`, `not_ioc`, `uncertain` |
| `context_snippet` | Surrounding sentence or page context | Text snippet |
| `reviewer_notes` | Analyst justification for label | Analyst comment (e.g. "Adversary webshell") |

---

### Step-by-Step Evaluation Procedure

#### Step 1: Generate Candidate Review Queue
Generate a review queue for the representative 3-report evaluation subset (covering all 7 IOC categories across 30 total pages):
```powershell
# Generate review queue for representative 3-report subset:
python -m eval.generate_review_queue --subset --output eval/review_queue_subset.csv

# Or generate for all 20 accepted reports:
python -m eval.generate_review_queue --all --output eval/review_queue_all.csv
```
*Strict Rule: All emitted candidates start with `label='unreviewed'`. No positive or negative labels are auto-populated.*

#### Step 2: Human Manual Review
Open `eval/review_queue_subset.csv` in a spreadsheet or editor. For each candidate:
1. Inspect the context snippet and the original PDF page.
2. If confirmed as an adversary threat indicator, change `label` to **`true_ioc`** and add a note.
3. If confirmed as benign prose, documentation, software version, or tool reference, change `label` to **`not_ioc`**.
4. If ambiguous, set `label` to **`uncertain`** (uncertain items are tracked but excluded from ground truth).
5. If you discover an indicator in the PDF that neither automated method found, append a new row with `source_origin='manual_inspection'`.

#### Step 3: Audit Review Progress & Automated Queue Integrity
Audit review progress, verify label health, distinguish annotation rows from unique indicators, and run automated checks for malformed values, duplicate candidates, missing evidence, invalid page numbers, or unlocated text:
```powershell
# Audit manual review working file (strict human review tracking):
python -m eval.review_to_dataset --input eval/manual_review.csv --check-integrity

# Audit original review queue subset:
python -m eval.review_to_dataset --input eval/review_queue_subset.csv --check-integrity
```

> [!NOTE]
> **Definition of 119 Document-Level Unique Indicators:**  
> The queue contains **139 total annotation rows**, representing **119 document-level unique indicators** deduplicated by `(report_filename, ioc_type, normalized_value)`. Repeated occurrences or multi-page citations of the same indicator within the same document account for the difference between 139 rows and 119 unique indicators (59 true IOCs, 57 negative controls, 3 uncertain candidates).

#### Step 4: Manual Human Review & Evidence Verification Safeguards
Human analysts record decisions in `eval/manual_review.csv` while preserving `eval/review_queue_subset.csv` byte-for-byte.
Review fields:
- `human_label`: `true_ioc`, `not_ioc`, `uncertain`, or `unreviewed`.
- `human_evidence`: Exact verbatim snippet from source PDF page verifying source provenance.
- `human_notes`: Justification explaining why this indicator is malicious, benign, or ambiguous.
- `reviewed_by`: Analyst identifier/signature.

**Rigorous Safeguards:**
1. A verbatim PDF quote verifies source provenance only. Human justification (`human_notes`) is required for verified labels.
2. Never silently convert an unsupported decision to another label; validation errors are raised and reported.
3. Candidate-level evaluation is separated from full-report extraction:
   - **Candidate-Level Evaluation (Closed-World Benchmark)**: Evaluates extraction against the reviewed candidate pool. The report table presents:
     `Category`, `Support`, `Doc Extracted`, `TP`, `Conf FP`, `Uncertain`, `FN`, `Precision`, `Recall`, `F1`, and `Status`.
   - **Extraction Accounting**:
     $$\text{Doc Extracted} = \text{TP} + \text{Confirmed FP} + \text{Uncertain}$$
     Extracted predictions may not equal $TP + \text{Confirmed FP}$ because neutral uncertain predictions are also extracted by the engine. For example, in the URL category:
     $\text{Doc Extracted} = 13$, $\text{TP} = 11$, $\text{Confirmed FP} = 0$, $\text{Uncertain} = 2$, $\text{FN} = 0$.
   - **Uncertain GitHub URLs (Neutral Reserve)**:
     The two uncertain predictions are dual-use GitHub repositories from page 8 of the Androxgh0st advisory:
     - `https://github.com/alexantr/filemanager`
     - `https://github.com/prasathmani/tinyfilemanager`
     These items are held in a neutral reserve and explicitly excluded from Confirmed FP counts in both candidate-level and open-world reporting.
   - **Candidate Recall vs. Complete Document Recall**:
     Candidate-level recall ($1.0000$) applies **strictly to the currently reviewed positive candidate pool**. It proves the extractor missed 0 of the 59 reviewed true IOC candidates ($FN = 0$). It does **not** represent complete, open-world document-level recall, as unannotated sections of the PDF reports may contain additional indicators not captured in the candidate review queue.
   - **Negative-Control Metric**: Confirmed negative (`not_ioc`) suppression is calculated as:
     $$\text{Negative-Control Rejection Rate} = \frac{\text{Confirmed Negatives Rejected}}{\text{Total Confirmed Negatives Tested}}$$
     *(Strictly a negative-control metric, NOT general specificity).*
   - **Open-World Accounting**: Predictions outside the reviewed candidate scope are reported as unreviewed/unresolved; they are NOT counted as confirmed false positives without complete annotation coverage.

#### Step 5: Run Evaluation
Compare production extractor predictions against reviewed annotations:
```powershell
# 1. Evaluate human-reviewed queue (strictly reports 0 verified true IOCs if all remain unreviewed):
python -m eval.evaluate_annotations --review-queue eval/manual_review.csv

# 2. View AI-suggested baseline evaluation:
python -m eval.evaluate_annotations --review-queue eval/manual_review.csv --baseline-suggestion

# 3. Secondary Page-Aware Matching:
python -m eval.evaluate_annotations --review-queue eval/manual_review.csv --page-aware

# 4. Export detailed evaluation JSON report:
python -m eval.evaluate_annotations --review-queue eval/manual_review.csv --output eval/eval_results.json
```

#### Step 6: Convert Verified Annotations to Standard Dataset JSON
Export verified positive annotations, confirmed negatives, and uncertain candidates into `eval/dataset_schema.json` format:
```powershell
python -m eval.review_to_dataset --input eval/manual_review.csv --output eval/verified_subset_dataset.json
```

---

## 5. Known Limitations & Scope Boundaries

1. **IPv6**: Excluded from MVP scope (only IPv4 addresses are extracted and evaluated).
2. **Private Network Filtering**: The extractor intentionally rejects RFC 1918, loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast (`224.0.0.0/4`), and broadcast addresses (`240.0.0.0/4`). Ground truth should not expect private addresses to be returned.
3. **Domain False Positives**: Strings with common file extensions (e.g. `malware.exe`, `report.pdf`, `test.json`) are rejected as domains by design.
4. **Context Snippets**: Extracted IOCs provide up to 240-character evidence snippets surrounding the indicator.
5. **Deterministic**: Zero LLM or external network dependencies are permitted in this workstream.

---

## 6. Integration Contract: `GET /reports/{id}/iocs`

The PDF processing and IOC extraction deliverables (`pdf_service.py`, `ioc_service.py`, `eval/ioc_eval.py`, `eval/prepare_annotation_skeleton.py`) are fully implemented and self-contained with 100% passing tests.

### A. Extractor Service Interface Contract
```python
class PageText(TypedDict):
    page_number: int
    page_text: str  # Matches report_pages.page_text
    text: str       # Backward compatibility alias

class ExtractedIOC(TypedDict):
    type: str         # 'ipv4' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve'
    value: str        # Normalized, refanged value (e.g. 1.1.1.1, https://evil.com)
    source_page: int  # Source page number
    evidence: str     # Surrounding sentence or text context snippet

def extract_iocs(pages: list[PageText]) -> list[ExtractedIOC]: ...
```

### B. Database Mapping (`iocs` Table in architecture.md)
| `ExtractedIOC` Key | `iocs` DB Column | Type | Notes |
| :--- | :--- | :--- | :--- |
| *(system)* | `id` | `UUID` | Primary key (`gen_random_uuid()`) |
| *(pipeline)* | `report_id` | `UUID` | Foreign key referencing `reports(id) ON DELETE CASCADE` |
| `type` | `ioc_type` | `TEXT` | Category: `'ipv4' \| 'domain' \| 'url' \| 'md5' \| 'sha1' \| 'sha256' \| 'cve'` |
| `value` | `ioc_value` | `TEXT` | Normalized, refanged string |
| `source_page` | `source_page`| `INT` | 1-based page number where first seen |
| `evidence` | `evidence` | `TEXT` | Context snippet string |

### C. Proposed Endpoint Specification (`GET /reports/{id}/iocs`)
- **Path:** `GET /reports/{id}/iocs`
- **Query Parameters (Optional):**
  - `type`: filter by category (e.g. `?type=ipv4`)
  - `page`: filter by source page (e.g. `?page=1`)
- **Status Codes & Error Handling:**
  - `200 OK`: Report exists and processing completed. Returns IOC list or envelope:
    ```json
    [
      {
        "type": "ipv4",
        "value": "198.51.100.24",
        "source_page": 1,
        "evidence": "...connected from external IP 198.51.100.24 to pivot..."
      }
    ]
    ```
    *(If no IOCs were found in the report, returns `200 OK` with an empty list `[]`)*
  - `202 Accepted` / `409 Conflict`: If the report status is still `'processing'`.
  - `404 Not Found`: If `{id}` does not exist in `reports` table:
    ```json
    { "detail": "Report <id> not found" }
    ```
  - `422 Unprocessable Entity`: If `{id}` is not a valid UUID format.

### D. Decision Points for Aqsa:
1. **Response Envelope vs. Flat List**: Does Aqsa prefer a flat array (`list[ExtractedIOC]`) as in `architecture.md` line 292, or a wrapped envelope (`{ "report_id": "...", "total": int, "iocs": [...] }`)?
2. **Deduplication Persistence**: `extract_iocs()` deduplicates within a run, storing the earliest page. Should DB insertion use a composite unique constraint `(report_id, ioc_type, ioc_value)`?
3. **Endpoint Placement**: Since Aqsa owns FastAPI initialization and routers, will Aqsa register an `ioc_router` inside `backend/app/routers/` that calls an endpoint function provided by the IOC service, or will Aqsa implement the router directly using `ioc_service.py`?

## Held-out evaluation (12 reports)

`eval/heldout_review.csv` holds 1,028 candidates from 12 CISA/NCSC advisories that were **not** used to tune the extractor:
AA21-209A, AA22-011A, AA22-117A, AA22-138B, AA22-174A, AA22-257A, AA22-321A, AA23-250A, AA23-319A, AA24-241A, MAR-10430311, NCSC SVR TTPs 2021.

**Labelling method:** AI-assisted. Each row has `true_ioc` / `not_ioc` / `uncertain`, a written reason in `human_notes` (prefixed `[AI-labelled, not human-verified]`) and verbatim evidence. `reviewed_by` records the provenance. Ambiguous cases (abused third-party services, parent domains) are `uncertain` and excluded from metrics.

Reproduce:

```bash
python -m eval.evaluate_annotations --review-queue eval/heldout_review.csv --pdf-dir eval/raw_reports
```

| Type | Support | TP | Confirmed FP | Uncertain | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cve | 134 | 134 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| domain | 21 | 21 | 16 | 9 | 0 | 0.568 | 1.000 | 0.724 |
| ipv4 | 108 | 108 | 2 | 0 | 0 | 0.982 | 1.000 | 0.991 |
| md5 | 25 | 25 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| sha1 | 12 | 12 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| sha256 | 42 | 42 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| url | 5 | 5 | 3 | 4 | 0 | 0.625 | 1.000 | 0.769 |
| **Micro** | **347** | **347** | **21** | **13** | **0** | **0.943** | **1.000** | **0.971** |

Recall is measured within the candidate pool (closed world). Main error source: legitimate public services (ngrok, anonfiles, sendspace, catbox, rambler.ru), reporting-contact domains, and registry hive file names (`sam.hiv`) extracted as domains.

**Post-evaluation fix:** after the results above were recorded, filters were added for the false-positive classes they revealed. Re-running gives micro P 0.991 / F1 0.996 (domain P 0.955, URL P 0.714). That number is optimistic because the rules were chosen with these labels in view. Quote the table above as the held-out result.


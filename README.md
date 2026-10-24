# ThreatMap Lite — PDF & IOC Intelligence Module

> **Component:** PDF Ingestion, Text Extraction, and Regex Indicators of Compromise (IOC) Intelligence  
> **Team Member / Module Owner:** Ashhal  
> **System:** ThreatMap Lite (Cyber Threat Intelligence Analysis Platform)  
> **Version:** 1.2.0 | **Type:** Semester MVP  

---

## 1. Module Overview & Responsibilities

The **PDF & IOC Intelligence Module** is the foundational deterministic ingestion layer of ThreatMap Lite. It is responsible for:
1. **PDF Ingestion & Validation:** Validating uploaded threat advisories (`%PDF-` magic bytes header, 50MB file size ceiling, filename sanitization against path traversal and reserved characters).
2. **Subprocess PyMuPDF Extraction:** Executing PyMuPDF (`fitz`) in an isolated subprocess (`pdf_worker.py`) with a strict 120-second timeout to prevent denial-of-service from malformed or infinite stream PDFs.
3. **IOC Extraction, Defanging & Normalization:** Detecting, refanging, canonicalizing, and deduplicating seven indicator types (`ipv4`, `domain`, `url`, `md5`, `sha1`, `sha256`, `cve`) with surrounding evidence snippet extraction.
4. **Database Persistence & REST APIs:** Persisting structured page blocks into `report_pages` and verified indicators into `iocs` tables, exposing REST endpoints (`POST /reports/upload`, `GET /reports/{id}/status`, `GET /reports/{id}/iocs`, `GET /reports/{id}/results`).
5. **Interactive Analyst UI:** Delivering responsive dark-mode analyst interfaces (`UploadZone.jsx`, `IOCTable.jsx`) with drag-and-drop, category filtering, search, and one-click copying.
6. **Ground-Truth Evaluation:** Providing an independent, reproducible evaluation framework (`eval/ioc_eval.py`) with full traceability and explicit labeling provenance.

### Team Ownership Matrix

| Member | Primary Focus Area | Key Deliverables & Responsibilities |
|---|---|---|
| **Ashhal** | **PDF Processing + IOC Intelligence** | • PDF validation (`%PDF-`, 50MB) and PyMuPDF page-wise text extraction<br>• Regex-based IOC extraction, defanging normalization, and deduplication<br>• IOC storage, evidence snippets, and IOC endpoints (`/reports/{id}/iocs`, `/reports/upload`)<br>• IOC unit tests & evaluation (Precision, Recall, F1 per IOC type)<br>• Upload UI (`UploadZone.jsx`), IOC table (`IOCTable.jsx`), and setup documentation |
| **Zahra** | Behavior Detection + ATT&CK Mapping | • spaCy behavior sentence segmentation and linguistic filtering<br>• Sentence embeddings (`all-MiniLM-L6-v2`), cosine similarity mapping, and abstention logic<br>• Deterministic MITRE ATT&CK mitigation data preparation, loader, and retrieval<br>• Mapping UI (`MappingCard.jsx`, `AbstentionCard.jsx`, `ConfidenceBadge.jsx`) |
| **Aqsa** | Database + Pipeline + Report Management | • PostgreSQL database, pgvector integration, SQLAlchemy ORM models, and Alembic migrations<br>• Asynchronous pipeline execution, background tasks, and status polling API<br>• Direct Gemini API integration (no LangChain) for summaries/tips, caching in DB, and verification<br>• Application layout (`App.jsx`), status UI (`StatusStepper.jsx`), and E2E testing |

---

## 2. Directory Structure

```
ThreatMap/
├── backend/
│   ├── app/
│   │   ├── database.py             # SQLAlchemy engine & session factory (SQLite/PostgreSQL)
│   │   ├── main.py                 # FastAPI application entrypoint with CORS & routes
│   │   ├── models/
│   │   │   └── db_models.py        # ORM models (reports, report_pages, iocs, etc.)
│   │   ├── routers/
│   │   │   └── reports.py          # /reports/upload, /status, /iocs, /results endpoints
│   │   ├── schemas/
│   │   │   └── schemas.py          # Pydantic V2 request & response schemas
│   │   └── services/
│   │       ├── ioc_service.py      # Core IOC regex, defanging, normalization & filtering
│   │       ├── pdf_service.py      # PDF validator, sanitization & subprocess orchestration
│   │       └── pdf_worker.py       # Isolated worker process executing PyMuPDF
│   ├── requirements.txt            # Backend Python dependencies
│   └── uploads/                    # Isolated directory for sanitized uploaded PDFs
├── frontend/
│   ├── index.html                  # Frontend HTML shell
│   ├── package.json                # React 18 + Vite dependencies
│   ├── vite.config.js              # Vite server & backend API proxy configuration
│   └── src/
│       ├── App.jsx                 # Main application dashboard
│       ├── index.css               # Vanilla CSS design system (tokens from design.md)
│       ├── main.jsx                # React DOM mount entrypoint
│       └── components/
│           ├── IOCTable.jsx        # Category-filtered monospace IOC table with copy & search
│           └── UploadZone.jsx      # Drag-and-drop PDF upload component with 50MB check
├── eval/
│   ├── raw_reports/                # Source CISA/NCSC/Mandiant PDFs used for evaluation (tracked)
│   ├── review_queue_subset.csv     # 139-candidate tuning queue (auto-generated, kept byte-for-byte)
│   ├── manual_review.csv           # Human labels for those 139 rows (reviewed by Ashhal)
│   ├── heldout_review.csv          # 1,028-candidate held-out set, AI-assisted labels (not human-verified)
│   ├── evaluate_annotations.py     # Scores the extractor against a reviewed CSV (P/R/F1 per type)
│   ├── ioc_eval.py                 # P/R/F1 engine; default run uses synthetic fixtures only
│   └── test_data/                  # Synthetic fixtures for unit tests (never quote as results)
└── tests/
    ├── test_annotation_workflow.py # Annotation review queue & JSON dataset tests
    ├── test_e2e_pipeline.py        # End-to-end integration tests (Upload -> DB -> API)
    ├── test_ioc_eval.py            # Precision, recall, F1 calculation unit tests
    ├── test_ioc_service.py         # IOC extraction, defanging, and filtering unit tests
    └── test_pdf_service.py         # PDF validation, magic bytes, and PyMuPDF worker tests
```

---

## 3. Installation & Setup Instructions

### Prerequisites
- **Python:** 3.11+
- **Node.js:** v18+ (tested on v24.15.0)
- **Git**

### Step 1: Clone & Environment Setup
```bash
git clone <repository_url> ThreatMap
cd ThreatMap
```

### Step 2: Backend Setup
```bash
# Create and activate virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt
```

### Step 3: Run Unit & Integration Tests
```bash
python -m pytest -v
```
All backend unit, integration, and E2E tests should pass (97 at the time of writing).

### Step 4: Run FastAPI Backend Server
```bash
uvicorn backend.app.main:app --reload --port 8000
```
- API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

### Step 5: Frontend Setup & Development Server
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser. The Vite development server automatically proxies `/reports` and `/health` requests to `http://127.0.0.1:8000`.

Frontend configuration lives in `frontend/.env` (copy `frontend/.env.example`):

| Variable | Purpose | Default |
|---|---|---|
| `VITE_API_BASE_URL` | API URL for deployed builds; empty = use the dev proxy | *(empty)* |
| `VITE_DEV_PROXY_TARGET` | Backend the dev server proxies to | `http://127.0.0.1:8000` |
| `VITE_DEV_PORT` | Dev server port | `5173` |
| `VITE_MAX_UPLOAD_MB` | Fallback upload limit until `/health` reports the server's | `50` |
| `VITE_IOC_PAGE_SIZE` | IOC table rows per page | `25` |

The backend's upload limit and allowed CORS origins come from `backend/.env` (`MAX_UPLOAD_SIZE_MB`, `CORS_ORIGINS`). `/health` returns `max_upload_mb`, so the UI always shows and enforces the same limit as the server.

Frontend quality checks:
```bash
cd frontend
npm run lint   # ESLint
npm test       # Vitest component + helper tests
```

---

## 4. API Endpoints Specification

| Method | Endpoint | Description | Response Contract |
|---|---|---|---|
| `POST` | `/reports/upload` | Upload PDF report (validates `%PDF-`, 50MB limit, runs extraction pipeline) | `{ "report_id": UUID, "status": "processing" \| "complete" }` |
| `GET` | `/reports/{id}/status` | Check pipeline status for polling UI | `{ "status": "complete", "current_step": "complete", "error_msg": null }` |
| `GET` | `/reports/{id}/iocs` | Returns all refanged, normalized IOCs for report | `list[{ "type": str, "value": str, "source_page": int, "evidence": str }]` |
| `GET` | `/reports/{id}/results` | Complete consolidated report payload with IOC type summary counts | `{ "report_id": UUID, "file_name": str, "page_count": int, "status": str, "iocs": [...], "ioc_summary": {...} }` |
| `GET` | `/reports` | List all processed reports with page and IOC counts | `list[{ "id": UUID, "file_name": str, "page_count": int, "status": str, "ioc_count": int }]` |
| `DELETE` | `/reports/{id}` | Cascades deletion of report, extracted pages, and IOC records | `{ "deleted": true, "report_id": UUID }` |
| `GET` | `/health` | System health check endpoint | `{ "status": "ok", "service": "threatmap-lite-backend" }` |

---

## 5. IOC Extraction Rules & Normalization Standards

The `ioc_service.py` module applies deterministic regular expressions and post-extraction normalization filters:

1. **Defanging Refanging:**
   - Obfuscated dots: `[.]`, `(.)`, `{.}` → `.`
   - Obfuscated schemes: `hxxp://`, `hxxps://`, `hXXp://` → `http://`, `https://`
   - Spaced/bracketed dots: ` [.] `, `[dot]` → `.`
2. **Supported IOC Types:**
   - **IPv4:** Standard 4-octet addresses (`0.0.0.0`–`255.255.255.255`). Reserved/private ranges (RFC 1918, RFC 5737 documentation, loopback, broadcast) are strictly filtered out unless labeled.
   - **Domain:** Fully qualified domain names matching IANA TLDs. Excludes common file extension artifacts (`.php`, `.txt`, `.py`, `.json`, `.exe`) and documentation domains.
   - **URL:** HTTP and HTTPS URLs with refanging. Line reconstruction handles advisory line-wraps across breaks. Excludes standard defensive/reference authorities (`cisa.gov`, `mitre.org`, `github.com/cisa`) unless explicitly listed in threat drops.
   - **MD5:** Exactly 32 hexadecimal characters (`[a-fA-F0-9]{32}`).
   - **SHA-1:** Exactly 40 hexadecimal characters (`[a-fA-F0-9]{40}`).
   - **SHA-256:** Exactly 64 hexadecimal characters (`[a-fA-F0-9]{64}`).
   - **CVE:** Common Vulnerabilities and Exposures format (`CVE-\d{4}-\d{4,7}`).
3. **Canonical Normalization:**
   - Hashes and domain names are normalized to lowercase.
   - URLs preserve path casing but refang scheme and lowercase hostnames.
   - Deduplication is performed per report so identical indicators cited across multiple pages are tracked with their primary or distinct page citations.

---

## 6. Known Boundary Limitations & Edge Cases

1. **Advisory Editorial Typos (e.g., Maui 31-character MD5):**
   - In CISA AA22-187A Page 3 Table 1, the value `fda3a19afa85912f6dc8452675245d6` is listed under "MD5 Hash". However, it contains exactly **31 hexadecimal characters** (one digit missing).
   - *Behavior:* Strict format validation rejects this value. Relaxing the regex to 31 characters would induce false positives across random git commit hashes and hex fragments. This candidate is preserved in the review queue as `uncertain`.
2. **TLD vs. File Extension Collisions (e.g., `.sh` on Surge.sh):**
   - The indicator `http://tangible-drink.surge.sh/configx.txt` in CISA AA24-016A Page 8 is a valid adversary configuration URL.
   - *Limitation:* Extractor filters file extensions (such as `.sh` shell scripts) to eliminate reconnaissance artifacts like `install.sh`. Because the hostname ends in `.sh`, standard domain validation flags the TLD as a script extension.
3. **Dual-Use Open Source Repositories on GitHub:**
   - Indicators such as `https://github.com/alexantr/filemanager` and `https://github.com/prasathmani/tinyfilemanager` are listed in CISA AA24-016A as dropped file managers.
   - *Limitation:* Platform-hosted URLs present an ontological ambiguity between legitimate third-party open-source code and malicious infrastructure. These are preserved as `uncertain`.
4. **Scanned & Image-Only PDFs:**
   - ThreatMap Lite processes native text-based PDFs via PyMuPDF. Scanned PDFs without OCR text layers raise a structured `ValueError: Document contains no extractable text`.

5. **Abused Public Services (file sharing, tunnelling, scanning, email):**
   - Reports often name services the actors abused, e.g. `ufile[.]io`, `sendspace[.]com`, `ngrok[.]io`, `Shodan[.]io`, `rambler[.]ru`. The service apex is not adversary infrastructure.
   - *Behavior:* Known services are filtered via `PLATFORM_HOSTING_DOMAINS` / `PUBLIC_EMAIL_PROVIDERS`. Per-user subdomain services (`sslip.io`, `ngrok.io`) filter **only the bare apex**, so `149.248.35.200.sslip.io` and `<random>.ngrok.io` are still extracted.
   - Bare service roots on these platforms (`https://www.sendspace[.]com`, `https://ufile[.]io`) are not extracted as URLs, since there is no actor-controlled path; paths on them (`https://ufile[.]io/abc123`) still are.
   - *Limitation:* The lists are curated, so an unlisted service will still be extracted.
6. **Registry Hive and Other File Names That Use Real TLDs:**
   - `sam.hiv`, `system.hiv` are Windows registry dumps, but `.hiv` is a real TLD. `.hiv` is treated as a file extension. Other real-TLD collisions (e.g. `.zip`, `.mov`) depend on the extension list.
7. **WHOIS / RDAP Network Ranges:**
   - Network blocks in WHOIS output (`inetnum: 179.60.147.0/24`) are excluded via CIDR / `inetnum` / `NetRange` context; host IPs on the same line format are kept.
8. **Indicators Wrapped Across PDF Lines:**
   - A domain broken at a dot, defanged dot or hyphen (`update.evil-` / `cdn.com`, `evil[.]` / `com`) is rejoined, and the fragments are not reported separately. A plain `word.` at a line end is treated as a sentence end.
   - *Limitation:* A break with no punctuation (`split-dom` / `ain.com`) cannot be told apart from two tokens, so only the second fragment is extracted.
9. **Closed-World Recall:**
   - Recall is computed only over the reviewed candidate pool (production extractor + permissive regex + manual inspection). Indicators that no pass surfaced (e.g. a domain broken by an odd defang like `forticloud.[]online`) are not counted as false negatives.

---

## 7. Ground-Truth Evaluation Workflow

The evaluation suite (`eval/`) provides an empirical assessment of extraction performance against a subset of verified CISA advisories:

```bash
# Run evaluation benchmark
# Tuning set: 139 human-reviewed candidates from 3 reports
python -m eval.evaluate_annotations --review-queue eval/manual_review.csv --pdf-dir eval/raw_reports

# Held-out set: 1,028 AI-assisted candidates from 12 reports
python -m eval.evaluate_annotations --review-queue eval/heldout_review.csv --pdf-dir eval/raw_reports
```

`python eval/ioc_eval.py` with no arguments scores the **synthetic** fixtures in `eval/test_data/` and is a smoke test only.

### Dataset Provenance & Safeguards
- **Tuning set (`manual_review.csv`, 139 rows):** labels were reviewed by a human (Ashhal), with verbatim evidence and notes per row. The extractor was tuned on these reports, so scores here are not a generalisation estimate.
- **Held-out set (`heldout_review.csv`, 1,028 rows):** labels are **AI-assisted and not human-verified**; every note is prefixed `[AI-labelled, not human-verified]`. Datasets exported from AI-assisted rows are tagged `"verification_status": "ai_suggested_unverified"`.
- **Independence:** The evaluation review queue was generated by combining production extractor results, permissive discovery regex passes, and manual PDF inspection.
- **Traceability:** Every candidate row contains the exact PDF filename, source page number, context snippet, and surrounding advisory text.
- **Candidate Recall vs. Complete Document Recall:** Candidate-level recall ($1.0000$ or $100.0\%$) applies **strictly to the current reviewed candidate pool** ($FN = 0$ of 59 reviewed true IOCs). It does **not** represent complete, open-world document-level IOC recall across unannotated sections of the PDF reports.
- **Definition of 119 Document-Level Unique Indicators:** The queue contains **139 total annotation rows**, representing **119 document-level unique indicators** deduplicated by `(report_filename, ioc_type, normalized_value)` (59 true IOCs, 57 negative controls, 3 uncertain candidates).
- **Candidate-Level Category Accounting & Uncertain Reserves:** In the candidate-level category evaluation table, $\text{Doc Extracted} = \text{TP} + \text{Confirmed FP} + \text{Uncertain}$. Extracted predictions may not equal $\text{TP} + \text{Confirmed FP}$ because neutral uncertain predictions (specifically the 2 dual-use GitHub repositories: `https://github.com/alexantr/filemanager` and `https://github.com/prasathmani/tinyfilemanager`) are extracted by the engine from the document text but remain held in a neutral reserve and explicitly excluded from Confirmed FP counts in both candidate-level and open-world reporting.

### Final IOC Evaluation Table (held-out set, 12 reports)

A held-out set of 12 CISA/NCSC advisories (1,028 candidates, `eval/heldout_review.csv`) was labelled **with AI assistance** (provenance recorded in `reviewed_by` and `human_notes`) and was **not** used to tune the extractor before the first evaluation. Ambiguous candidates are kept in an `uncertain` reserve and excluded from the metrics.

```bash
python -m eval.evaluate_annotations --review-queue eval/heldout_review.csv --pdf-dir eval/raw_reports
```

| Type | Support | Precision (held-out, before fix) | F1 (before fix) | Precision (after fix) | F1 (after fix) |
|---|---|---|---|---|---|
| CVE | 134 | 1.000 | 1.000 | 1.000 | 1.000 |
| Domain | 21 | 0.568 | 0.724 | 0.955 | 0.977 |
| IPv4 | 108 | 0.982 | 0.991 | 1.000 | 1.000 |
| MD5 | 25 | 1.000 | 1.000 | 1.000 | 1.000 |
| SHA1 | 12 | 1.000 | 1.000 | 1.000 | 1.000 |
| SHA256 | 42 | 1.000 | 1.000 | 1.000 | 1.000 |
| URL | 5 | 0.625 | 0.769 | 0.714 | 0.833 |
| **Micro avg** | **347** | **0.943** | **0.971** | **0.991** | **0.996** |

Recall is 1.000 in every column (closed world, see Limitation 9).

- **The "before fix" column is the true held-out result** and is the number to quote for generalisation.
- The "after fix" column comes from filtering the false-positive classes found on this set (abused public services, reporting-contact domains, registry hive files, WHOIS ranges; see Limitations 5–7). Because those rules were chosen after seeing these labels, it is **optimistic** and only shows that the fix works, not how well the extractor generalises.
- A second post-hoc pass (Oct 2026: bare service-root URLs on file-sharing platforms, `slip.io` apex) removes the last 3 false positives and gives 1.000 on this set. It is even more optimistic for the same reason and must not be quoted as a result.
- Original 3-report tuning set after both fixes: micro P/R/F1 = 1.000 / 1.000 / 1.000 (no regression).


# ThreatMap Lite — Product Requirements Document
**Version:** 1.2 | **Team:** ThreatMap Lite Project Team | **Type:** Semester MVP

---

## 1. Product Overview

ThreatMap Lite is an AI-assisted cybersecurity report analysis system.

It accepts a PDF threat intelligence report, extracts indicators of compromise (IOCs) and attacker behavior sentences, maps behavior to selected MITRE ATT&CK techniques using semantic similarity, deterministically retrieves official MITRE ATT&CK mitigations for mapped techniques, generates supplementary AI threat summaries and security tips via the Gemini API, and displays the exact evidence sentence behind every prediction.

**Core differentiators:**
1. **Traceability:** Every ATT&CK prediction is strictly traceable to the original report sentence.
2. **Abstention Principle:** The system never forces a prediction — it abstains when confidence falls below an empirically determined threshold.
3. **Deterministic Official Mitigations:** Recommendations presented as official MITRE ATT&CK mitigations are deterministically retrieved from curated ATT&CK knowledge bases, never generated or rewritten by an LLM.
4. **Verifiable Supplementary AI Insights:** Direct Gemini API summaries and tips are clearly labeled as "AI-generated", cached in PostgreSQL, and verified against extracted PDF text without fabricating IOCs.

---

## 2. Problem Statement

Analysts manually read threat reports to extract IOCs, identify attacker behaviors, map them to ATT&CK, and look up relevant defenses. This takes hours per report. ThreatMap Lite automates the extraction, mapping, and mitigation lookup pipeline for a defined, evaluable subset of ATT&CK techniques, supplemented by AI-generated threat executive summaries.

---

## 3. Target Users

- Cybersecurity students studying threat intelligence
- Junior SOC/CTI analysts processing public reports
- Security researchers organizing report corpora

The system is an analysis assistant. It does not replace professional analysis.

---

## 4. MVP Workflow

```
PDF Upload (Magic Bytes + 50MB Limit)
    ↓
Text Extraction Page-by-Page (PyMuPDF) → Stored in report_pages
    ↓
    ├── IOC Extraction & Defanging (Regex) → Stored in iocs
    └── Behavior Sentence Extraction (spaCy + Keyword Filter) → Stored in behavior_sentences
            ↓
        ATT&CK Semantic Mapping (sentence-transformers all-MiniLM-L6-v2)
            ↓
        Threshold & Abstention Check (Score vs. Empirical Threshold)
            ↓
            ├── If confidence_ok = true  → technique_id + Score + Evidence
            │                                  ↓
            │                              Deterministic Mitigation Lookup (MITRE ATT&CK Data)
            └── If confidence_ok = false → technique_id = NULL + Best Score + Abstention Notice
                    ↓
        Supplementary AI Analysis (Direct Gemini API: Summary + Tips, Cached in DB)
            ↓
        Results Dashboard & History Management
```

---

## 5. MVP Scope (MUST HAVE)

1. PDF upload and validation (magic bytes `%PDF-`, 50MB limit)
2. Page-wise text extraction with page tracking (PyMuPDF) stored in `report_pages`
3. IOC extraction: IPv4, domain, URL, MD5, SHA1, SHA256, CVE
4. Defanged IOC normalization (`1[.]2[.]3[.]4` → `1.2.3.4`, `hxxp` → `http`)
5. IOC deduplication, type classification, and evidence snippet capture
6. Behavior sentence extraction (spaCy sentence tokenization + keyword filter)
7. ATT&CK knowledge base: 30–40 selected Enterprise techniques pre-embedded
8. Semantic similarity mapping (sentence-transformers `all-MiniLM-L6-v2` + cosine similarity)
9. Empirically validated confidence threshold with abstention (`technique_id = NULL`, `confidence_ok = false`, retain best score)
10. Evidence sentence and page number display per prediction
11. Recommend official MITRE ATT&CK mitigations deterministically for each mapped technique
12. Supplementary AI-generated threat summary and security tips via Gemini API (direct integration, no LangChain; combined record per report cached in PostgreSQL with SHA-256 source-text hash and prompt-version invalidation)
13. Strict visual and logical separation between deterministic mitigations and AI-generated tips
14. Results dashboard with tabbed IOC, ATT&CK mapping/mitigation, and AI summary views
15. Report history (view, re-open, delete) and optional JSON export
16. PostgreSQL storage with pgvector and Alembic migrations
17. FastAPI asynchronous backend
18. React frontend (Vite, Vanilla CSS / CSS Modules)
19. Local deployment (no Docker required)

---

## 6. Out of Scope (MVP)

- URL-based report ingestion
- OCR for scanned PDFs
- Full ATT&CK Enterprise coverage (193+ techniques)
- ATT&CK Navigator / interactive heatmaps
- STIX 2.1 / TAXII export
- Autonomous LLM agents or LangChain dependencies
- LLM replacement of deterministic regex or semantic mapping pipelines
- Fine-tuned NER models
- Cross-encoder reranking
- External IOC enrichment (VirusTotal, Shodan)
- Threat actor attribution
- Graph visualization
- Multi-user authentication and RBAC
- Docker containerization

---

## 7. Optional (if core MVP is done early)

- Basic JSON export of IOCs, mappings, mitigations, and AI summaries (`GET /reports/{id}/export`)

---

## 8. IOC Extraction Rules

| Type    | Method         | Notes                                      |
|---------|----------------|--------------------------------------------|
| IPv4    | Regex          | Handle defanging, exclude private ranges   |
| Domain  | Regex + TLD    | Handle defanging                           |
| URL     | Regex          | Handle hxxp/hxxps                          |
| MD5     | Regex (32 hex) | Validate length                            |
| SHA1    | Regex (40 hex) | Validate length                            |
| SHA256  | Regex (64 hex) | Validate length                            |
| CVE     | Regex          | Pattern: CVE-YYYY-NNNNN                    |

Each IOC record stores: type, value, source page, evidence text snippet.

---

## 9. ATT&CK Mapping & Mitigation Rules

- Pre-embed all 30–40 selected technique descriptions at system startup using `all-MiniLM-L6-v2`.
- Preload official MITRE ATT&CK mitigations and technique-mitigation relationships from `attck/mitigations.json` into the database.
- For each extracted behavior sentence: generate sentence embedding → compute cosine similarity against pre-embedded techniques → rank candidates.
- **Threshold & Abstention Rule:**
  - If max cosine similarity $\ge$ empirical threshold: map to top technique (`technique_id`, `similarity`, `confidence_ok = true`).
  - If max cosine similarity < empirical threshold: record abstention (`technique_id = NULL`, `similarity = best_score`, `confidence_ok = false`).
  - Enforce `(technique_id IS NULL AND confidence_ok = false) OR (technique_id IS NOT NULL AND confidence_ok = true)` in the database and service layer. Use restrictive deletion or an explicit transactional remapping policy for referenced techniques; do not allow deletion to silently create an inconsistent abstention.
  - Never request or display technique-specific recommendations for abstained mappings.
- **Mitigation Recommendation Rule:**
  - For mapped techniques (`confidence_ok = true`), retrieve official mitigation recommendations deterministically from `attack_mitigations`. Identical technique inputs must yield identical official recommendations.
  - Abstentions (`confidence_ok = false`) must not display technique-specific recommendations.
  - Under no circumstances shall an LLM generate or alter text presented as official MITRE ATT&CK mitigations.

---

## 10. Gemini API Integration & Caching Rules

- Direct integration using the Google GenAI SDK (`google-genai`), without LangChain or intermediate orchestration frameworks.
- Used strictly for supplementary threat report executive summaries and general security posture tips.
- **Combined Logical Storage:** Executive summaries and security tips are stored together in a single logical record per report in `report_ai_analysis` using the canonical identifier `generation_type = 'summary_and_tips'`.
- **Cache Invalidation & Versioning:**
  - Cache validity is verified via a tuple: `(report_id, generation_type, prompt_version)` matched against `source_hash`.
  - `source_hash` is the SHA-256 hex digest computed over all extracted `report_pages` text (ordered by page number).
  - `prompt_version` identifies the prompt template and generation hyper-parameters (defaulting to `'v1'`).
  - **Cache Hit:** If an entry exists for the report with matching `prompt_version` and identical `source_hash`, the cached summary and tips are reused directly (`cached = true`).
  - **Cache Miss / Invalidation:** If no cache exists, if the source report text changes (producing a different `source_hash`), or if `prompt_version` is bumped, the system triggers a new generation call and upserts the cache record (`cached = false`).
- **Grounding & Verification:** Treat extracted `report_pages` text as the only source for report-specific factual claims. Verify each report-specific claim against that text before storing or returning it. Remove/reject unsupported claims; if verification is inconclusive or fails, return a safe unavailable/error state rather than presenting output as verified. Keyword/entity overlap alone is not proof of semantic support.
- **Advice Boundary:** General security tips are supplementary advisory guidance, not report-specific verified facts or official MITRE mitigations.
- **IOC Boundary:** Gemini must not extract, add, normalize, modify, or verify IOCs. The deterministic regex IOC pipeline is the sole source of IOC findings.
- **AI-Generated Labeling:** Generated content must be prominently marked as "AI-generated" in all UI displays and API responses.
- **API Failure Handling:** Upstream Gemini API failures (e.g., HTTP 429 rate limits, timeouts) must be handled gracefully with structured error reporting and retry capabilities. The core pipeline (PDF processing, regex IOC extraction, ATT&CK mapping, and deterministic mitigations) must remain fully functional regardless of Gemini API status.
- **Credential Security:** API keys reside exclusively in backend environment variables (`GEMINI_API_KEY`). Never expose keys to the frontend.

---

## 11. Evaluation Requirements

### 11.1 IOC Extraction
- Ground truth: 15–20 manually annotated threat reports across diverse threat actors.
- Metrics: Precision, Recall, and F1 calculated per IOC type (IPv4, domain, URL, MD5, SHA1, SHA256, CVE) and macro-averaged.

### 11.2 Behavior Sentence Extraction (Owner: Zahra)
- Ground truth: 200+ manually labeled sentences (relevant behavior vs. non-relevant boilerplate/context).
- Metrics: Precision, Recall, F1 score of the keyword/linguistic filter.

### 11.3 ATT&CK Mapping & Baseline Comparison (Owner: Zahra)
- Ground truth: Labeled dataset of behavior sentences mapped to the 30–40 target techniques plus out-of-scope/abstention examples.
- **Model Comparison:** scikit-learn TF-IDF + cosine baseline vs. sentence-transformers (`all-MiniLM-L6-v2`) + cosine similarity.
- **Metrics:** Top-1 Accuracy, Top-3 Accuracy, per-technique Precision, Recall and F1, plus Macro-F1.
- **Threshold Analysis:** Precision/Recall versus cosine similarity threshold, including the selected operating threshold.
- **Abstention Analysis:** Confusion matrix including the abstention class and false-positive mapping rate on out-of-scope sentences.
- **Abstention Analysis:** Confusion matrix including the abstention class, false positive mapping rate on out-of-scope sentences, and empirical justification for the chosen cutoff threshold.

---

## 12. Security Requirements

- Accept only PDF files (validate magic bytes `%PDF-`, reject disguised files).
- Enforce strict 50MB file size limit before processing.
- Sanitize uploaded filenames using `pathlib.Path(filename).name` to prevent path traversal.
- Never execute uploaded files; store in a dedicated, isolated `uploads/` folder.
- Execute PyMuPDF within a subprocess with a hard 120-second timeout.
- Parameterize all database queries via SQLAlchemy ORM (no raw SQL injection vectors).
- HTML-escape all extracted and generated text before rendering in React (no `dangerouslySetInnerHTML`).
- Protect Gemini API keys via environment variables; implement retry limits and fallback handling for rate limits (HTTP 429) and upstream service failures.

---

## 13. Non-Functional Requirements

- Process a 30-page text-based PDF in under 120 seconds.
- Asynchronous status tracking via polling (`GET /reports/{id}/status`) to maintain an interactive, non-blocking UI.
- Graceful error reporting for corrupted, password-protected, or scanned image-only PDFs.
- Fully deterministic extraction, mapping, and mitigation lookup pipelines (identical inputs produce identical outputs).
- Fast cold-start execution through startup embedding caching of technique descriptions.

---

## 14. Success Criteria

The project is successful when the end-to-end workflow is demonstrated:
1. Upload PDF → Validate & store page-wise in PostgreSQL.
2. Extract & defang IOCs with evidence snippets.
3. Extract behavior sentences & map to ATT&CK with empirical thresholding.
4. Show abstention card for unmapped behaviors without forcing false techniques.
5. Display deterministic official MITRE ATT&CK mitigations for mapped techniques.
6. Display cached, verified, AI-generated summary and tips clearly labeled as "AI-generated".
7. Re-open report history, review past analyses, and export results.
8. Deliver documented, honest evaluation metrics (F1 per IOC type, confusion matrix, and TF-IDF vs. transformer baseline).

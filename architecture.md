# ThreatMap Lite — System Architecture
**Version:** 1.2 | **Team:** ThreatMap Lite Project Team | **Type:** Semester MVP

---

## 1. System Overview

```
                     React Frontend (Vite + Vanilla CSS)
                                    │
                                    │ HTTP / REST (api/client.js)
                                    ▼
                          FastAPI Backend (Python)
                         ┌──────────┴──────────┐
                         ▼                     ▼
              PostgreSQL (pgvector)      NLP & AI Pipeline
             ├── reports                ├── PyMuPDF (Text Extraction)
             ├── report_pages           ├── Regex Engine (IOC Extraction)
             ├── iocs                   ├── spaCy (Sentence Segmentation)
             ├── behavior_sentences     ├── sentence-transformers (Embeddings)
             ├── attack_techniques      ├── scikit-learn (TF-IDF Baseline)
             ├── attack_mitigations     ├── MITRE ATT&CK Mitigation Engine
             ├── technique_mitigations  └── Google GenAI SDK (Gemini API)
             ├── mappings                   (Supplementary Summaries & Tips)
             └── report_ai_analysis
```

All services run locally on the host machine. No Docker is required.

---

## 2. Technology Stack

| Layer               | Technology                                 | Responsibility / Notes                                    |
|---------------------|--------------------------------------------|-----------------------------------------------------------|
| Frontend            | React 18, Vite, JavaScript                 | SPA user interface, reactive state management            |
| Styling             | Vanilla CSS / CSS Modules                  | Lean, high-performance styling without CSS frameworks     |
| Backend API         | Python 3.11+, FastAPI, Uvicorn             | Asynchronous REST API and task orchestration              |
| ORM & Migrations    | SQLAlchemy 2.0, Alembic                    | Typed models, transactional integrity, schema migrations  |
| Database            | PostgreSQL 15+ with pgvector               | Relational data, cascade deletes, vector storage          |
| PDF Processing      | PyMuPDF (fitz)                             | Subprocess page-by-page text extraction (120s timeout)    |
| Behavior Extraction | spaCy (`en_core_web_sm`)                   | Linguistic tokenization and sentence boundary detection    |
| Semantic Embedding  | sentence-transformers (`all-MiniLM-L6-v2`) | 384-dimensional dense semantic vector representations     |
| Mapping Baseline    | scikit-learn (`TfidfVectorizer`)           | Deterministic lexical mapping baseline for evaluation     |
| Official Mitigations| MITRE ATT&CK Mitigation Dataset (JSON)     | Deterministic mapping from mapped techniques to defenses  |
| Supplementary AI    | Google GenAI SDK (`google-genai`)          | Direct Gemini API integration for summaries & posture tips |
| Config & Env        | python-dotenv                              | Secrets & environment variables (`GEMINI_API_KEY`)        |
| HTTP Client         | httpx                                      | Asynchronous API communication and testing client         |

---

## 3. Folder Structure

```
threatmap/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application entrypoint & middleware
│   │   ├── database.py                 # SQLAlchemy engine, session maker, pgvector init
│   │   ├── routers/
│   │   │   └── reports.py              # REST routes for upload, status, results, AI
│   │   ├── services/
│   │   │   ├── pdf_service.py          # PyMuPDF subprocess & page-wise extraction
│   │   │   ├── ioc_service.py          # Regex IOC extraction, defanging, deduplication
│   │   │   ├── behavior_service.py     # spaCy sentence splitting & behavior filtering
│   │   │   ├── mapping_service.py      # Embedding generation, similarity, abstention
│   │   │   ├── recommendation_service.py # Deterministic MITRE ATT&CK mitigation lookup
│   │   │   └── gemini_service.py       # Direct Gemini API integration & claim checking
│   │   ├── models/
│   │   │   └── db_models.py            # SQLAlchemy ORM models (reports, pages, etc.)
│   │   └── schemas/
│   │       └── schemas.py              # Pydantic v2 validation and response contracts
│   ├── alembic/
│   │   ├── env.py                      # Alembic migration configuration
│   │   └── versions/                   # Versioned migration scripts
│   ├── attck/
│   │   ├── techniques.json             # Curated 30–40 MITRE ATT&CK techniques
│   │   ├── mitigations.json            # Official MITRE ATT&CK mitigations dataset
│   │   └── loader.py                   # Preloader for techniques, embeddings, mitigations
│   ├── uploads/                        # Uploaded PDF storage (gitignored)
│   ├── requirements.txt
│   └── .env                            # Local configuration & GEMINI_API_KEY
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Upload.jsx              # PDF drag-and-drop submission view
│   │   │   ├── Status.jsx              # Processing progress stepper view
│   │   │   ├── Report.jsx              # Tabbed analysis results dashboard
│   │   │   └── History.jsx             # Report history log and management
│   │   ├── components/
│   │   │   ├── UploadZone.jsx          # File drop zone with validation checks
│   │   │   ├── StatusStepper.jsx       # Real-time polling pipeline step tracker
│   │   │   ├── IOCTable.jsx            # Filterable, sortable IOC table
│   │   │   ├── MappingCard.jsx         # Technique card with evidence & collapsible mitigations
│   │   │   ├── AbstentionCard.jsx      # Unmapped behavior display with reason
│   │   │   ├── ConfidenceBadge.jsx     # HIGH / MED / LOW / ABSTAIN score badge
│   │   │   ├── ReportSidebar.jsx       # Report metadata, statistics, export & actions
│   │   │   ├── HistoryTable.jsx        # Paginated report history table
│   │   │   ├── RecommendationList.jsx  # Deterministic official mitigations list
│   │   │   └── AIAnalysisCard.jsx      # Gemini summary & tips card (AI-generated badge)
│   │   ├── api/
│   │   │   └── client.js               # Centralized Axios/fetch HTTP wrapper
│   │   ├── App.jsx                     # Route definitions and layout wrapper
│   │   └── index.css                   # Global design tokens and base styles
│   ├── package.json
│   └── vite.config.js
└── eval/
    ├── ioc_eval.py                     # Precision, Recall, F1 evaluator per IOC type
    ├── mapping_eval.py                 # Top-1/3 accuracy, confusion matrix, threshold curve
    ├── baseline_tfidf.py               # TF-IDF baseline implementation & evaluator
    └── test_data/                      # Manually labeled threat reports & sentence sets
```

---

## 4. Database Schema (PostgreSQL + pgvector)

```sql
-- 1. Reports metadata & pipeline status
CREATE TABLE reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name   TEXT NOT NULL,
    page_count  INT,
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | processing | complete | failed
    error_msg   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Page-by-page extracted raw text
CREATE TABLE report_pages (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    page_number INT NOT NULL,
    page_text   TEXT NOT NULL,
    UNIQUE (report_id, page_number)
);

-- 3. Extracted Indicators of Compromise (IOCs)
CREATE TABLE iocs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    ioc_type    TEXT NOT NULL,   -- ipv4 | domain | url | md5 | sha1 | sha256 | cve
    ioc_value   TEXT NOT NULL,
    source_page INT NOT NULL,
    evidence    TEXT NOT NULL
);

-- 4. Extracted behavior sentences
CREATE TABLE behavior_sentences (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id   UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    sentence    TEXT NOT NULL,
    source_page INT NOT NULL
);

-- 5. Curated MITRE ATT&CK techniques (Preloaded at startup)
CREATE TABLE attack_techniques (
    technique_id   TEXT PRIMARY KEY,   -- e.g. T1059.001
    technique_name TEXT NOT NULL,
    tactic         TEXT NOT NULL,
    description    TEXT NOT NULL,
    embedding      VECTOR(384) NOT NULL
);

-- 6. Official MITRE ATT&CK mitigations (Preloaded at startup)
CREATE TABLE attack_mitigations (
    mitigation_id  TEXT PRIMARY KEY,   -- e.g. M1047
    name           TEXT NOT NULL,
    description    TEXT NOT NULL
);

-- 7. Technique-to-Mitigation mapping relationships (Preloaded at startup)
CREATE TABLE technique_mitigations (
    technique_id      TEXT NOT NULL REFERENCES attack_techniques(technique_id) ON DELETE CASCADE,
    mitigation_id     TEXT NOT NULL REFERENCES attack_mitigations(mitigation_id) ON DELETE CASCADE,
    usage_description TEXT,
    PRIMARY KEY (technique_id, mitigation_id)
);

-- 8. ATT&CK Predictions & Abstentions
-- When confidence_ok = false (abstention): technique_id = NULL, similarity = best score
CREATE TABLE mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    sentence_id     UUID NOT NULL REFERENCES behavior_sentences(id) ON DELETE CASCADE,
    technique_id    TEXT REFERENCES attack_techniques(technique_id) ON DELETE RESTRICT,
    similarity      FLOAT NOT NULL,
    confidence_ok   BOOLEAN NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_mapping_abstention_consistency CHECK (
        (technique_id IS NULL AND confidence_ok = FALSE) OR
        (technique_id IS NOT NULL AND confidence_ok = TRUE)
    )
);

-- 9. Gemini AI-Generated Combined Summaries & Tips Cache
-- Stores executive summary and supplementary security tips in one combined record per report
CREATE TABLE report_ai_analysis (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    generation_type TEXT NOT NULL DEFAULT 'summary_and_tips',  -- Combined analysis identifier
    summary         TEXT NOT NULL,
    tips            JSONB NOT NULL,                            -- Array of tip strings: list[str]
    source_hash     TEXT NOT NULL,                             -- SHA-256 hash of extracted report_pages text
    prompt_version  TEXT NOT NULL DEFAULT 'v1',                -- Version of prompt template / model configuration
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (report_id, generation_type, prompt_version)
);

-- Indexes for performance
CREATE INDEX idx_report_pages_report_id ON report_pages(report_id);
CREATE INDEX idx_iocs_report_id ON iocs(report_id);
CREATE INDEX idx_behavior_sentences_report_id ON behavior_sentences(report_id);
CREATE INDEX idx_mappings_report_id ON mappings(report_id);
CREATE INDEX idx_report_ai_analysis_lookup ON report_ai_analysis(report_id, generation_type, prompt_version);
```

---

## 5. Processing Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Ingestion Phase                                                          │
│    - Validate PDF magic bytes (%PDF-) and file size (≤ 50MB)                │
│    - Sanitize filename and save to backend/uploads/                         │
│    - Initialize report record in PostgreSQL (status = 'processing')         │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Text Extraction Phase                                                    │
│    - Execute PyMuPDF via subprocess with 120s timeout                       │
│    - Extract text page-by-page                                              │
│    - Populate report_pages table with (report_id, page_number, page_text)   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Parallel Extraction Phase                                                │
│    ├── IOC Pipeline:                                                        │
│    │     - Defang normalization (`[.]` → `.`, `hxxp` → `http`)              │
│    │     - Regex extraction (IPv4, domain, URL, MD5, SHA1, SHA256, CVE)     │
│    │     - Deduplicate & validate lengths/ranges                            │
│    │     - Insert records into iocs table with source_page and snippet      │
│    └── Behavior Pipeline:                                                   │
│          - spaCy sentence segmentation per page                             │
│          - Keyword-based behavior filter (action verbs + security terms)    │
│          - Insert filtered sentences into behavior_sentences table          │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. ATT&CK Semantic Mapping & Abstention Phase                               │
│    - Encode behavior sentences with all-MiniLM-L6-v2                        │
│    - Calculate cosine similarity against preloaded technique embeddings     │
│    - If max(similarity) >= empirical threshold:                             │
│        * Record mapping with technique_id, similarity, confidence_ok = true │
│    - Else:                                                                  │
│        * Record abstention: technique_id = NULL, best similarity score,     │
│          confidence_ok = false                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ 5. Official Mitigation Lookup (Deterministic)                               │
│    - For every mapped technique (confidence_ok = true):                     │
│        * Query attack_mitigations via technique_mitigations                 │
│        * Attach official descriptions & usage notes to response payload     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 6. Supplementary AI Generation Phase (Direct Gemini API, No LangChain)      │
│    - Compute source_hash = SHA256(concatenated report_pages text)           │
│    - Lookup report_ai_analysis by (report_id, 'summary_and_tips', prompt_v) │
│    - If cache hit and cached source_hash == current source_hash:            │
│        * Reuse cached summary and tips (cached = true)                      │
│    - Else (cache miss or stale source_hash / prompt_version):               │
│        * Prompt Gemini with extracted report_pages text                     │
│        * Generate combined executive summary and security tips              │
│        * Verify report-specific claims against report_pages text           │
│        * Reject unsupported claims; fail safely if verification fails     │
│        * Gemini never creates, alters, or verifies IOC findings             │
│        * Upsert only verified output in report_ai_analysis (cached = false) │
│    - Generic security tips remain advisory, not verified facts or official  │
│      MITRE mitigations                                                      │
│    - On API/verification failure: return structured unavailable/error state │
│      without blocking core extraction, mapping, or official mitigations     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 7. Finalization Phase                                                       │
│    - Update report status = 'complete' (or 'failed' with error_msg)         │
│    - Frontend polling completes and displays dashboard                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. API Endpoints Specification

| Method | Endpoint                       | Access    | Description & Response Contract                                     |
|--------|--------------------------------|-----------|---------------------------------------------------------------------|
| `POST` | `/reports/upload`              | Public    | Accepts `multipart/form-data`. Returns `{ "report_id": UUID, "status": "processing" }` |
| `GET`  | `/reports/{id}/status`         | Public    | Returns `{ "status": "processing"|"complete"|"failed", "current_step": str, "error_msg": str|null }` |
| `GET`  | `/reports/{id}/results`        | Public    | Complete report payload: metadata, IOCs, mappings, mitigations, and AI cache |
| `GET`  | `/reports/{id}/iocs`           | Public    | Returns `list[{ "type": str, "value": str, "source_page": int, "evidence": str }]` |
| `GET`  | `/reports/{id}/behaviors`      | Internal  | Returns `list[{ "id": UUID, "sentence": str, "source_page": int }]` |
| `GET`  | `/reports/{id}/mappings`       | Public    | Returns mappings with joined techniques, scores, abstentions, and official mitigations |
| `GET`  | `/reports/{id}/recommendations`| Public    | Returns official MITRE ATT&CK mitigations mapped for the report's identified techniques |
| `GET`  | `/reports/{id}/ai-analysis`    | Public    | Returns combined Gemini summary & tips: `{ "report_id": UUID, "generation_type": "summary_and_tips", "summary": str, "tips": list[str], "source_hash": str, "prompt_version": str, "cached": bool }` |
| `POST` | `/reports/{id}/ai-analysis`    | Public    | Triggers or forces regeneration of combined analysis (`?force_refresh=true`); upserts cache |
| `GET`  | `/reports/{id}/export`         | Public    | Downloads consolidated report analysis in JSON format                |
| `GET`  | `/reports`                     | Public    | Returns paginated list of analyzed reports                          |
| `DELETE`| `/reports/{id}`               | Public    | Cascades deletion of all report records, pages, IOCs, and cached AI  |

---

## 7. Strict Separation of Concerns

1. **Deterministic vs. Generative Separation:**
   - **Official MITRE ATT&CK Mitigations:** Retrieved deterministically from relational tables (`attack_mitigations`, `technique_mitigations`) populated strictly from official MITRE JSON files.
   - **Gemini AI Analysis:** Produced by the Gemini API, strictly labeled "AI-generated", and isolated in `report_ai_analysis`. Gemini never alters or generates content presented as official MITRE mitigations.
2. **Deterministic Pipeline Integrity:**
   - The regex IOC extractor and sentence-transformers mapping pipeline execute independently of the Gemini API. If the Gemini API is unreachable, rate-limited, or fails, the core analysis (IOCs, ATT&CK mapping, official mitigations) remains 100% operational.
3. **No LangChain Rule:**
   - All Gemini interactions use the official Google GenAI Python SDK (`google-genai`). No LangChain abstractions, chains, or agent runtimes are permitted.

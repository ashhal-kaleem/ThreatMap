# ThreatMap Lite — Project Rules & Engineering Guidelines
**Version:** 1.2 | **Team:** Ashhal, Zahra, Aqsa | **Type:** Semester MVP

---

## 1. Team Governance & Review Rules

- **Branching Policy:** Work strictly on feature branches branched from `main`. Direct commits to `main` are blocked.
  - Branch naming: `feature/<name>`, `fix/<name>`, `eval/<name>`, `docs/<name>`.
  - Commit messages: imperative and concise (e.g., `Add defang normalization for IPv4 regex`).
- **Enforced Peer Review Chain:** Every pull request requires review and approval from the designated reviewer before merging:
  - **Ashhal's PRs** $\rightarrow$ Reviewed and approved by **Zahra**
  - **Zahra's PRs** $\rightarrow$ Reviewed and approved by **Aqsa**
  - **Aqsa's PRs** $\rightarrow$ Reviewed and approved by **Ashhal**
- **Viva Readiness:** Every team member must be capable of demonstrating and explaining the entire system architecture, pipeline stages, evaluation methodologies, and code components during the final viva defense.
- **Scope Discipline:** No feature outside the agreed MVP scope may be added without unanimous team consensus. If a task encounters blockers, adjust depth rather than skipping evaluation or testing.

---

## 2. Backend & Python Rules

- **Python Environment:** Python 3.11+. Use a dedicated virtual environment (`venv`). All project dependencies must be pinned in `requirements.txt`.
- **Environment & Configuration:** Use `python-dotenv` exclusively for configuration (`.env`). Secrets (including `GEMINI_API_KEY`, database credentials, and file paths) must never be hardcoded or checked into version control.
- **Asynchronous Architecture:** Use asynchronous FastAPI route handlers and background tasks for file ingestion, PDF processing, and pipeline execution.
- **ORM & Data Access:** Use SQLAlchemy 2.0 ORM exclusively for database interactions. Raw SQL strings are strictly prohibited in application route handlers.
- **Data Validation:** All input payloads and API responses must be validated against typed Pydantic v2 schemas.
- **Execution Safeguards:**
  - Filenames must be sanitized with `pathlib.Path(filename).name`.
  - External subprocess calls (e.g., PyMuPDF worker) must enforce a hard `timeout=120` parameter.
  - Business logic belongs in `app/services/` — routers must only handle request dispatching, status codes, and response serialization.
- **Gemini SDK Rule (No LangChain):** Direct integration via the official Google GenAI SDK (`google-genai`). LangChain, LlamaIndex, or other third-party LLM orchestration frameworks are strictly prohibited.

---

## 3. Frontend & React Rules

- **Component Design:** Functional components with React hooks only. No class components.
- **File Structure:**
  - Component files: `PascalCase.jsx` in `src/components/`
  - Page views: `PascalCase.jsx` in `src/pages/`
  - Utility/API modules: `camelCase.js` in `src/api/` or `src/utils/`
- **Centralized Networking:** All HTTP requests must route through `src/api/client.js`. No raw `fetch` or scattered Axios calls inside components.
- **Styling Architecture:** Use **Vanilla CSS / CSS Modules** exclusively with predefined design tokens. Do not introduce Tailwind CSS or utility frameworks.
- **Security & Rendering:**
  - Strictly forbidden: `dangerouslySetInnerHTML`.
  - All report text, evidence snippets, and AI outputs must be sanitized and HTML-escaped before display.
- **Clarity of Provenance:** UI components must visually separate deterministic IOC facts, semantic ATT&CK predictions, official MITRE mitigations, and Gemini AI-generated insights.

---

## 4. Security Rules (Non-Negotiable)

- **File Ingestion:** Validate PDF files by magic bytes (`%PDF-`), not file extensions. Reject files failing byte verification immediately.
- **File Size Cap:** Enforce an immutable 50MB file size limit on the upload route.
- **Isolated Storage:** Uploaded files must be written strictly to `backend/uploads/` (gitignored) and never placed in public or web-accessible directories.
- **Subprocess Isolation:** PDF text extraction must run in a separate subprocess with a 120-second timeout to mitigate PDF decompression bombs or parser freezes.
- **Injection Prevention:** All database operations must execute via parameterized ORM queries to prevent SQL injection.
- **Gemini Key Isolation & Resilience:**
  - `GEMINI_API_KEY` must remain strictly in backend environment variables (`.env`). Never expose API keys to the React frontend or client-side bundles.
  - Upstream Gemini API errors (HTTP 429 rate limits, network timeouts, service outages) must be caught and handled gracefully without crashing the application. Core deterministic extraction (IOCs, behavior sentences, ATT&CK mappings, and official mitigations) must remain 100% operational regardless of Gemini availability.
- **AI Claim Grounding & Verification:**
  - Verify report-specific factual claims against extracted `report_pages` text before storing or returning them. Remove/reject unsupported claims; if verification fails or is inconclusive, return a safe unavailable/error state rather than presenting output as verified.
  - Keyword/entity overlap alone is not proof of semantic support.
  - Gemini must never create, extract, normalize, alter, or verify IOC findings. Only the deterministic regex IOC pipeline supplies IOC results.
  - General security tips are advisory and must not be presented as verified report facts or official MITRE ATT&CK mitigations.

---

## 5. Database & Migration Rules

- **Alembic Migrations:** All schema alterations must be applied via versioned Alembic migration scripts committed to the repository. Manual schema editing on shared databases is prohibited.
- **Identifier Convention:** UUID primary keys (`gen_random_uuid()`) for all transactional tables (`reports`, `report_pages`, `iocs`, `behavior_sentences`, `mappings`, `report_ai_analysis`).
- **Cascade Deletion:** Foreign keys linking to `reports(id)` must specify `ON DELETE CASCADE` so deleting a report purges all associated pages, IOCs, sentences, mappings, and AI cache.
- **Storage Boundaries:** Raw PDF binaries must never be stored in PostgreSQL. Raw extracted text is stored page by page in `report_pages`.
- **Nullable Technique & Abstention:** `mappings.technique_id` must be nullable. When similarity falls below the empirical threshold, set `technique_id = NULL`, `confidence_ok = false`, and preserve the best cosine `similarity` score. Enforce `(technique_id IS NULL AND confidence_ok = false) OR (technique_id IS NOT NULL AND confidence_ok = true)` with a database check constraint and service validation. Use restrictive deletion or an explicit transactional remapping policy for referenced techniques; do not use `ON DELETE SET NULL` without preserving the invariant. Recommendation lookup must return an empty list for `None`, and abstentions must never show recommendations.
- **AI Cache Invalidation & Combined Storage:** Store executive summary and security tips in a single combined record per report (`generation_type = 'summary_and_tips'`). Cache validation must verify `(report_id, generation_type, prompt_version)` against a SHA-256 hash (`source_hash`) of the extracted report text in `report_pages`. Invalidate and regenerate cached outputs when `source_hash` or `prompt_version` changes. Enforce `UNIQUE (report_id, generation_type, prompt_version)`.

---

## 6. ML, NLP & Mitigation Rules

- **Model Lifecycle:** The semantic embedding model (`all-MiniLM-L6-v2`) must be loaded into memory once during backend startup, never re-instantiated per request.
- **Static Knowledge Preloading:** MITRE ATT&CK technique descriptions and embeddings, as well as official MITRE mitigations, must be preloaded into PostgreSQL at startup via `attck/loader.py`.
- **Deterministic Recommendations:** Recommendations presented as official MITRE ATT&CK mitigations must be retrieved deterministically from `attack_mitigations`. LLMs must never generate or rewrite official MITRE mitigations.
- **Abstention Integrity:** Model abstention is an expected, high-value result. The system must never force a technique prediction when the similarity score is below the empirical threshold.
- **Baseline Requirement:** Evaluate scikit-learn TF-IDF alongside `all-MiniLM-L6-v2`. Report the confusion matrix, per-technique precision/recall/F1, macro-F1, threshold-versus-precision/recall results, and abstention behavior.
- **Code Separation:** All evaluation scripts and test corpora must reside in `eval/` and must remain separate from production application code.

---

## 7. What Not To Build

To guarantee semester MVP completion, the following features are strictly out of scope:

1. **No LangChain or Autonomous Agents:** Do not introduce LangChain, CrewAI, AutoGPT, or complex multi-turn agent frameworks.
2. **No LLM Overwrite of Core Pipelines:** Gemini must not replace deterministic regex IOC extraction or semantic ATT&CK mapping.
3. **No STIX / TAXII Integration:** Do not implement STIX 2.1 serialization or TAXII server connections.
4. **No ATT&CK Navigator / Heatmaps:** Standard mapping cards and tables satisfy the MVP.
5. **No Fine-Tuned Models:** Do not attempt fine-tuning custom LLMs or NER models.
6. **No External IOC Enrichment:** No live calls to external threat intelligence APIs (e.g., VirusTotal, AbuseIPDB, Shodan).
7. **No Graph Visualizations:** Do not build Neo4j or D3 graph visualizations.
8. **No Multi-User Authentication:** No user login, roles, or session management.
9. **No Docker Packaging:** The application is developed and demonstrated directly on local environments.

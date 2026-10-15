# ThreatMap Lite — Development Phases & Interface Contracts
**Version:** 1.2 | **Team:** Ashhal, Zahra, Aqsa | **Type:** Semester MVP

---

## 1. Project Team Ownership Matrix

| Member | Primary Focus Area | Key Deliverables & Responsibilities |
|---|---|---|
| **Ashhal** | PDF Processing + IOC Intelligence | • PDF validation (magic bytes, 50MB) and PyMuPDF page-wise text extraction<br>• Regex-based IOC extraction, defanging normalization, and deduplication<br>• IOC storage, evidence snippets, and IOC endpoints<br>• IOC unit tests & evaluation (Precision, Recall, F1 per IOC type)<br>• Upload UI (`UploadZone.jsx`), IOC table (`IOCTable.jsx`), and setup README |
| **Zahra** | Behavior Detection + ATT&CK Mapping | • spaCy behavior sentence segmentation and linguistic filtering<br>• Sentence embeddings (`all-MiniLM-L6-v2`), cosine similarity mapping, and abstention logic<br>• Deterministic MITRE ATT&CK mitigation data preparation, loader, and retrieval<br>• Mapping UI (`MappingCard.jsx`, `AbstentionCard.jsx`, `ConfidenceBadge.jsx`, `RecommendationList.jsx`)<br>• Baseline TF-IDF evaluation, confusion matrix, threshold tuning, and 10-report demo corpus |
| **Aqsa** | Database + Pipeline + Report Management | • PostgreSQL database, pgvector integration, SQLAlchemy ORM models, and Alembic migrations<br>• Asynchronous pipeline execution, background tasks, and status polling API<br>• Direct Gemini API integration (no LangChain) for summaries/tips, caching in DB, and verification<br>• Report history, reopening, deletion, and JSON export APIs<br>• Application layout (`App.jsx`), status UI (`StatusStepper.jsx`), history UI (`HistoryTable.jsx`), and E2E testing |

---

## 2. Parallel Development Phases (Weeks 1–14)

### Phase 1 — Environment & Knowledge Base Setup (Weeks 1–2)
*Goal: Working local development skeleton, database with pgvector, and curated ATT&CK dataset.*

- **Ashhal (PDF & IOC):**
  - Set up Python venv, backend dependencies, and configure PyMuPDF.
  - Implement PDF magic bytes (`%PDF-`) and size check utility functions.
  - Write unit tests for PDF validator.
- **Zahra (ATT&CK & Mitigations):**
  - Curate 30–40 MITRE ATT&CK Enterprise techniques into `attck/techniques.json`.
  - Curate corresponding official mitigations into `attck/mitigations.json`.
  - Build `attck/loader.py` to preload techniques and mitigations into PostgreSQL.
  - Begin gathering raw threat reports for the ground-truth annotation set.
- **Aqsa (Database & Skeleton):**
  - Initialize FastAPI repository with health check endpoint and CORS settings.
  - Configure PostgreSQL database with `pgvector` extension locally.
  - Initialize Alembic and create baseline migrations for `reports`, `report_pages`, `attack_techniques`, `attack_mitigations`, and `technique_mitigations`.
  - Initialize React + Vite project with Vanilla CSS structure and verify backend proxy connectivity.

*Integration Checkpoint 1:* Backend connects to PostgreSQL; `attck/loader.py` successfully populates techniques and mitigations tables; React communicates with FastAPI `/health`.

---

### Phase 2 — Core Extraction & Persistence Pipelines (Weeks 3–4)
*Goal: Process PDFs into structured pages, extract defanged IOCs, and filter behavior sentences.*

- **Ashhal (PDF & IOC Extraction):**
  - Implement `pdf_service.extract_pages` using PyMuPDF in a subprocess with 120s timeout.
  - Implement `ioc_service.extract_iocs` with defang normalization (`[.]` → `.`, `hxxp` → `http`) and regex patterns for IPv4, domain, URL, MD5, SHA1, SHA256, CVE.
  - Add deduplication and evidence snippet extraction.
  - Write unit tests for all IOC regex rules and defanging edge cases.
- **Zahra (Behavior Extraction & Mitigations):**
  - Implement `behavior_service.extract_sentences` with spaCy (`en_core_web_sm`) sentence tokenization and security action keywords.
  - Implement `recommendation_service.get_recommendations` to deterministically query `attack_mitigations`.
  - Label 200+ behavior sentences for filter evaluation (relevant vs. irrelevant).
- **Aqsa (Database Models & Async Pipeline):**
  - Create SQLAlchemy models and Alembic migrations for `iocs`, `behavior_sentences`, `mappings`, and `report_ai_analysis`.
  - Build asynchronous pipeline runner using FastAPI `BackgroundTasks`.
  - Implement `POST /reports/upload` and `GET /reports/{id}/status` endpoints.
  - Implement `GET /reports/{id}/behaviors` internal inspection endpoint.

*Integration Checkpoint 2:* Uploading a PDF saves pages to `report_pages`, extracts IOCs to `iocs`, and stores candidate sentences in `behavior_sentences`.

---

### Phase 3 — Semantic Mapping, Baselines & Gemini Integration (Weeks 5–7)
*Goal: ATT&CK similarity matching, abstention logic, baseline comparison, and Gemini API integration.*

- **Ashhal (IOC Evaluation & Refinement):**
  - Annotate ground-truth IOCs across 15–20 sample reports.
  - Implement `eval/ioc_eval.py` to calculate Precision, Recall, and F1 per IOC type.
  - Refine regex patterns based on false positives/negatives in evaluation.
  - Implement `GET /reports/{id}/iocs` endpoint.
- **Zahra (Semantic Mapping & Baseline):**
  - Implement `mapping_service.map_sentences` using sentence-transformers (`all-MiniLM-L6-v2`) and cosine similarity against startup technique embeddings.
  - Implement abstention logic (`technique_id = NULL`, `confidence_ok = false`, record best similarity).
  - Implement TF-IDF baseline using `scikit-learn` in `eval/baseline_tfidf.py`.
  - Run evaluation comparing TF-IDF vs. `all-MiniLM-L6-v2` on labeled pairs.
  - Generate Precision-Recall vs. threshold curve and select the final empirical cutoff.
- **Aqsa (Gemini API & Cache Layer):**
  - Implement `gemini_service.py` using Google GenAI SDK (`google-genai`) direct (no LangChain).
  - Design prompt for combined executive threat summary and supplementary security tips.
  - Implement combined database caching in `report_ai_analysis` (`generation_type = 'summary_and_tips'`).
  - Implement SHA-256 source-text hashing and prompt-version cache invalidation.
  - Verify report-specific claims against `report_pages`; remove/reject unsupported claims and fail safely if verification is inconclusive.
  - Keep general security tips labeled as advisory, separate from verified report facts and official MITRE mitigations.
  - Gemini must never create, alter, normalize, or verify IOC findings; regex remains the only IOC source.
  - Expose `GET /reports/{id}/ai-analysis` and `POST /reports/{id}/ai-analysis` with force-refresh support.

*Integration Checkpoint 3:* Backend successfully maps sentences to ATT&CK or abstains, queries deterministic mitigations, and caches verified Gemini summaries.

---

### Phase 4 — API Unification & UI Implementation (Weeks 8–10)
*Goal: Complete frontend interfaces connected to the unified REST API.*

- **Ashhal (Upload & IOC Frontend):**
  - Build `UploadZone.jsx` with drag-and-drop, file size validation (50MB), and feedback states.
  - Build `IOCTable.jsx` with category filter buttons (All, IPv4, Domain, Hash, CVE), pagination, and copy actions.
  - Ensure monospace styling for IOC values and sanitized rendering.
- **Zahra (Mapping & Mitigations Frontend):**
  - Build `MappingCard.jsx` showing technique details, confidence pill, and exact evidence sentence blockquote.
  - Build `AbstentionCard.jsx` displaying unmapped sentences with abstention explanation (no mitigations).
  - Build `ConfidenceBadge.jsx` for HIGH, MED, LOW, ABSTAIN visual pills.
  - Build `RecommendationList.jsx` as a collapsible drawer on `MappingCard` labeled **"From MITRE ATT&CK Mitigations"**.
- **Aqsa (Layout, Status, History & End-to-End API):**
  - Build `App.jsx` application shell, header, and client router (`/`, `/reports/:id/status`, `/reports/:id`, `/history`).
  - Build `StatusStepper.jsx` with real-time polling to `GET /reports/{id}/status`.
  - Build `ReportSidebar.jsx` and `HistoryTable.jsx` with report deletion and re-opening.
  - Build `AIAnalysisCard.jsx` with prominent **"AI-generated"** badge, loading skeletons, and error retry state.
  - Finalize `GET /reports/{id}/results`, `GET /reports/{id}/recommendations`, and `GET /reports/{id}/export`.

*Integration Checkpoint 4:* Full interactive user flow: upload PDF → see animated stepper → view results across IOC, ATT&CK, and AI summary tabs → re-open from history.

---

### Phase 5 — Testing, Robustness & Verification (Weeks 11–12)
*Goal: Robust error handling, cache verification, and unit/integration test coverage.*

- **Ashhal (PDF/IOC Robustness & Testing):**
  - Test malicious and malformed PDFs (corrupted magic bytes, password protected, infinite streams).
  - Verify defanging normalization across complex patterns (`hxxp[://]bad[.]com`, `10[.]0[.]0[.]1`).
  - Write automated tests in `tests/test_pdf_service.py` and `tests/test_ioc_service.py`.
- **Zahra (Mapping & Mitigation Verification):**
  - Unit tests for `mapping_service.py` and database constraints: ensure abstention assigns `technique_id = NULL`, `confidence_ok = false`, and preserves the best score; reject inconsistent pairs.
  - Verify deleting a referenced technique cannot silently break the abstention invariant.
  - Verify official mitigations are deterministic and sourced from `attack_mitigations`; abstentions never receive recommendations.
  - Validate that abstained records never render mitigation recommendations.
  - Assemble and verify the 10-report demonstration corpus (`demo_reports/`).
- **Aqsa (Pipeline & Gemini Integration Testing):**
  - Unit and integration tests for `gemini_service.py`: verify combined output caching, cache hits, cache misses on source-text hash / prompt-version changes, forced refresh, error handling (429 rate limit, upstream timeout), and prevention of hallucinated IOCs.
  - Write database cascade deletion tests: verify deleting a report purges `report_pages`, `iocs`, `mappings`, and `report_ai_analysis`.
  - End-to-end API testing using `httpx`.

*Integration Checkpoint 5:* All unit and integration test suites pass; pipeline handles failures gracefully without crashing.

---

### Phase 6 — Evaluation, Documentation & Final Viva Prep (Weeks 13–14)
*Goal: Final evaluation artifacts, documentation, and live demo rehearsal.*

- **Ashhal:**
  - Produce final IOC evaluation table (Precision, Recall, F1 for IPv4, domain, URL, hashes, CVE).
  - Write installation, setup instructions, and primary `README.md`.
  - Document IOC extraction rules and known boundary limitations.
- **Zahra:**
  - Finalize ATT&CK mapping evaluation report: confusion matrix, Top-1/Top-3 accuracy, per-technique precision/recall/F1, macro-F1, threshold vs. precision/recall curves, and abstention behavior.
  - Document TF-IDF vs. transformer comparison and justify the chosen confidence threshold.
  - Package the 10 sample threat-report PDFs for live evaluation and defense.
- **Aqsa:**
  - Finalize end-to-end integration test documentation and database migration guide.
  - Audit system performance: ensure 30-page PDF processes in < 120s.
  - Verify all code conforms to project rules and ensure the team is prepared for viva walkthrough.

*Integration Checkpoint 6:* Complete, production-grade submission with reproducible evaluation tables, demo corpus, and comprehensive documentation.

---

## 3. Strict Interface Contracts

To guarantee seamless parallel development, the backend services must adhere strictly to these Python type-annotated contracts:

```python
from pathlib import Path
from typing import TypedDict, Optional

# --- 1. PDF Service (Owner: Ashhal) ---
class PageText(TypedDict):
    page_number: int
    page_text: str    # Matches report_pages.page_text
    text: str         # Alias for backward compatibility

def extract_pages(pdf_path: Path) -> list[PageText]:
    """
    Executes PyMuPDF via a sandboxed subprocess with a 120s timeout.
    Returns page-indexed raw text blocks.
    Raises ValueError if PDF is malformed, encrypted, or contains no extractable text.
    """
    ...

# --- 2. IOC Service (Owner: Ashhal) ---
class ExtractedIOC(TypedDict):
    type: str       # 'ipv4' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve'
    value: str      # Normalized, refanged value (e.g. 1.1.1.1, https://evil.com)
    source_page: int  # Matches iocs.source_page and API payloads
    evidence: str     # Surrounding sentence or text context snippet

def extract_iocs(pages: list[PageText]) -> list[ExtractedIOC]:
    """
    Applies regex patterns to extract, defang, normalize, and deduplicate IOCs
    across all extracted document pages.
    """
    ...

# --- 3. Behavior Extraction Service (Owner: Zahra) ---
class BehaviorSentence(TypedDict):
    sentence: str
    source_page: int  # Matches behavior_sentences.source_page and API payloads

def extract_sentences(pages: list[PageText]) -> list[BehaviorSentence]:
    """
    Splits text using spaCy and filters sentences containing security action verbs
    or threat behaviors.
    """
    ...

# --- 4. ATT&CK Mapping Service (Owner: Zahra) ---
class MappingResult(TypedDict):
    sentence: str
    technique_id: Optional[str]  # None if abstained (similarity < threshold)
    similarity: float            # Cosine similarity score of top candidate
    confidence_ok: bool          # False indicates abstention

def map_sentences(sentences: list[BehaviorSentence]) -> list[MappingResult]:
    """
    Encodes sentences with sentence-transformers and calculates cosine similarity
    against pre-embedded MITRE ATT&CK techniques. Applies empirical thresholding.
    """
    ...

# --- 5. Recommendation Service (Owner: Zahra) ---
class MitigationRecommendation(TypedDict):
    mitigation_id: str           # e.g. M1047
    name: str                    # e.g. Audit
    description: str             # Official MITRE mitigation definition
    usage_description: str       # Technique-specific application context

def get_recommendations(technique_id: Optional[str]) -> list[MitigationRecommendation]:
    """
    Deterministically retrieves official MITRE ATT&CK mitigations for the given technique.
    Returns an empty list if technique_id is None (abstention).
    """
    ...

# --- 6. Gemini AI Service (Owner: Aqsa) ---
class AIAnalysisResult(TypedDict):
    report_id: str
    generation_type: str        # 'summary_and_tips'
    summary: str                # Executive summary text
    tips: list[str]             # List of supplementary security tips
    source_hash: str            # SHA-256 of extracted report_pages text
    prompt_version: str         # Prompt template and model settings version (e.g., 'v1')
    cached: bool                # True if returned from DB cache, False if freshly generated

def compute_source_hash(pages: list[PageText]) -> str:
    """
    Computes a deterministic SHA-256 hex digest across all extracted document
    page texts sorted by page_number.
    """
    ...

def generate_summary_and_tips(
    report_id: str,
    pages: list[PageText],
    iocs: list[ExtractedIOC],
    mappings: list[MappingResult],
    prompt_version: str = "v1",
    force_refresh: bool = False
) -> AIAnalysisResult:
    """
    Directly invokes Gemini API (no LangChain) to generate a combined executive threat
    summary and posture tips. Validates and writes to report_ai_analysis cache with
    computed source_hash and prompt_version. Handles API failures gracefully.
    """
    ...

def get_cached_analysis(
    report_id: str,
    current_source_hash: str,
    prompt_version: str = "v1"
) -> Optional[AIAnalysisResult]:
    """
    Retrieves combined analysis from report_ai_analysis cache only if
    stored source_hash matches current_source_hash and prompt_version matches.
    Returns None on cache miss or stale cache.
    """
    ...

class ClaimVerificationResult(TypedDict):
    verified: bool
    unsupported_claims: list[str]

def verify_claims(generated_text: str, pages: list[PageText]) -> ClaimVerificationResult:
    """
    Validates that entities and facts referenced in AI text appear within report_pages.
    Ensures zero fabricated IOCs.
    """
    ...
```

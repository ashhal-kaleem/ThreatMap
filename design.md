# ThreatMap Lite — UI/UX Design Specification
**Version:** 1.2 | **Team:** ThreatMap Lite Project Team | **Type:** Semester MVP

---

## 1. Design Principles

- **Clarity over decoration** — Cybersecurity analysts need actionable findings fast without distracting animations.
- **Strict Provenance Separation** — Visually and conceptually distinguish:
  1. *Deterministic Extractions* (Regex IOCs — verified ground facts).
  2. *Semantic Predictions* (sentence-transformers ATT&CK mappings with confidence scores).
  3. *Official Mitigations* (Deterministic recommendations labeled **"From MITRE ATT&CK Mitigations"**).
  4. *Generative AI Insights* (Gemini summaries & tips prominently labeled **"AI-generated"**).
- **Honest Confidence & Abstention** — Low-confidence mapping predictions are never masked or forced into false positives. Below-threshold sentences display clear abstention states.
- **Minimal Clicks** — Seamless upload → status → results workflow without disruptive modals.

---

## 2. Design Tokens & Color Palette

| Token            | Hex       | Usage                                                        |
|------------------|-----------|--------------------------------------------------------------|
| Background       | `#0f1117` | Root application background (dark mode only)                 |
| Surface          | `#1a1d27` | Cards, panels, modal dialogs                                 |
| Surface Hover    | `#222634` | Interactive card and row hover states                        |
| Border           | `#2a2d3e` | Card boundaries, dividers, table row borders                 |
| Text Primary     | `#e8eaf0` | Main headings, body text, primary table cells                |
| Text Secondary   | `#8b8fa8` | Labels, metadata, timestamps, secondary notes                |
| Accent Blue      | `#4a9eff` | Interactive links, technique IDs, primary focus states       |
| Green            | `#3ecf8e` | High confidence ($\ge 0.70$), success states, verified tags  |
| Yellow           | `#f59e0b` | Medium confidence ($0.50–0.69$), warning indicators          |
| Red              | `#f87171` | Low confidence ($< 0.50$), failure alerts, delete actions    |
| Gray             | `#4b5063` | Abstention badges, disabled buttons, subtle borders          |
| AI Purple        | `#a855f7` | "AI-generated" badge, Gemini summary/tips borders & accents  |

- **Typography:** `Inter`, `ui-sans-serif, system-ui` for UI copy.
- **Code & IOC Typography:** `JetBrains Mono`, `ui-monospace` for IOCs, hashes, technique IDs, and similarity scores.
- **Styling Architecture:** Vanilla CSS / CSS Modules (no Tailwind or third-party CSS frameworks).

---

## 3. Screen Designs & User Flows

### 3.1 Upload Page (`/`)

```
┌─────────────────────────────────────────────────────────┐
│  ThreatMap Lite                          [History →]    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   ┌─────────────────────────────────────────────────┐   │
│   │                                                 │   │
│   │   📄  Drop PDF report here or click to browse   │   │
│   │                                                 │   │
│   │   Max 50MB · Native text-based PDFs only        │   │
│   └─────────────────────────────────────────────────┘   │
│                                                         │
│                  [ Analyze Report ]                     │
│                                                         │
│   ── Recent Analysis History ───────────────────────    │
│   apt29_cozybear.pdf       48 pages  2026-09-24   [→]   │
│   lazarus_crypto.pdf       32 pages  2026-09-22   [→]   │
└─────────────────────────────────────────────────────────┘
```

**Interaction Details:**
- Implemented via `UploadZone.jsx`.
- Performs client-side validation on file size ($\le 50$MB) and MIME type.
- Navigates to `/reports/{id}/status` upon successful upload.

---

### 3.2 Processing Status Page (`/reports/{id}/status`)

```
┌─────────────────────────────────────────────────────────┐
│  Analyzing Report: apt29_cozybear.pdf                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ✅ 1. PDF Upload & Integrity Check                     │
│  ✅ 2. Text Extraction (Page-by-page via PyMuPDF)       │
│  ✅ 3. Regex IOC Extraction & Defanging                 │
│  ⟳ 4. ATT&CK Semantic Mapping & Mitigations ← Current   │
│  ○ 5. Supplementary AI Summary & Tips (Gemini)          │
│  ○ 6. Finalization & Complete                           │
│                                                         │
│  [Estimated time: 15–45 seconds]                        │
└─────────────────────────────────────────────────────────┘
```

**Interaction Details:**
- Implemented via `StatusStepper.jsx`.
- Polls `GET /reports/{id}/status` every 2.5 seconds.
- Automatically redirects to `/reports/{id}` once `status: "complete"`.
- Displays structured error details and retry options if `status: "failed"`.

---

### 3.3 Results Dashboard (`/reports/{id}`)

The results view features a persistent report sidebar (`ReportSidebar.jsx`) and a multi-tab analytical workspace.

```
┌──────────────┬──────────────────────────────────────────────────────────┐
│ apt29.pdf    │ [Overview & AI]   [IOCs (40)]   [ATT&CK & Mitigations]   │
│ 48 pages     ├──────────────────────────────────────────────────────────┤
│ 2026-09-24   │                                                          │
│              │ (Tab contents rendered below)                            │
│ Summary      │                                                          │
│  IPs: 12     │                                                          │
│  Domains: 8  │                                                          │
│  Hashes: 17  │                                                          │
│  CVEs: 3     │                                                          │
│  Mapped: 14  │                                                          │
│  Abstained: 3│                                                          │
│              │                                                          │
│ [Export JSON]│                                                          │
│ [Delete]     │                                                          │
└──────────────┴──────────────────────────────────────────────────────────┘
```

#### Tab 1: Overview & AI Analysis (`AIAnalysisCard.jsx`)

Presents the combined AI analysis record with cache status (`Cached` vs. `Fresh`), manual refresh, loading skeletons, and a retryable error/unavailable state if generation or verification fails. Show report-specific claims only after verification against extracted report text; do not render unsupported claims as findings. Label general tips as advisory, not verified report facts or official MITRE mitigations. Gemini output is never an IOC source.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Executive Threat Summary            [ Cached ]   [ ✨ AI-generated ]    │
├─────────────────────────────────────────────────────────────────────────┤
│  This report analyzes an advanced cyber espionage campaign attributed   │
│  to APT29 targeting European diplomatic entities. The adversary heavily  │
│  relied on compromised credentials and obfuscated PowerShell scripts...  │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Supplementary Security Tips                      [ ✨ AI-generated ]    │
├─────────────────────────────────────────────────────────────────────────┤
│  • Enforce strict PowerShell Constrained Language Mode across endpoints │
│  • Audit privileged VPN service accounts for anomalous geographic logins│
│  • Verify all claims against primary report text before taking action.  │
│                                                                         │
│  ⚠️ Note: AI-generated tips are supplementary advisory guidance and     │
│  do not replace official MITRE ATT&CK mitigation requirements.          │
│                                              [ ⟳ Refresh AI Analysis ] │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Tab 2: IOC Extraction Table (`IOCTable.jsx`)

Shows deterministically extracted IOCs with defanging status, source pages, and evidence snippets.

```
Filter: [All (40)]  [IPv4 (12)]  [Domain (8)]  [Hashes (17)]  [CVE (3)]

┌──────────┬────────────────────────────────┬──────┬──────────────────────┐
│ Type     │ Normalized Value               │ Page │ Evidence Snippet     │
├──────────┼────────────────────────────────┼──────┼──────────────────────┤
│ IPv4     │ 192.0.2.14                     │  4   │ "...beaconed to C2..."│
│ Domain   │ updates-microsoft.evil[.]com   │  6   │ "...staged payload..."│
│ SHA-256  │ e3b0c44298fc1c149afbf4c8996fb92│  7   │ "...installer drop..."│
│ CVE      │ CVE-2023-38831                 │ 11   │ "...WinRAR exploit..."│
└──────────┴────────────────────────────────┴──────┴──────────────────────┘
[ Copy Filtered IOCs ]   [ Download CSV ]
```

#### Tab 3: ATT&CK Mapping & Mitigations (`MappingCard.jsx`, `AbstentionCard.jsx`, `RecommendationList.jsx`)

Displays semantic technique mappings with exact report evidence sentences, confidence scores, and official mitigations.

```
14 techniques mapped  ·  3 abstentions recorded

┌─────────────────────────────────────────────────────────────────────────┐
│ T1059.001 · Command and Scripting Interpreter: PowerShell   Score: 0.84 │
│ Tactic: Execution                           [ ●●●● HIGH ] (AI Semantic) │
├─────────────────────────────────────────────────────────────────────────┤
│ Evidence Sentence (Page 6):                                             │
│ "The threat actor leveraged obfuscated PowerShell commands to bypass    │
│ execution policies and download the secondary payload."                 │
├─────────────────────────────────────────────────────────────────────────┤
│ ▾ Recommended Mitigations (From MITRE ATT&CK Mitigations)   [Official]  │
│   ├── M1047 · Audit: Monitor execution of PowerShell scripts using      │
│   │   Script Block Logging (Event ID 4104).                             │
│   ├── M1042 · Disable or Remove Feature or Program: Disable PowerShell  │
│   │   v2 to prevent downgrade attacks.                                  │
│   └── M1038 · Execution Prevention: Restrict execution using AppLocker  │
│       or Windows Defender Application Control in Constrained Mode.      │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ⊘ No reliable ATT&CK mapping found                        Page 18       │
│ Evidence Sentence:                                                      │
│ "The surrounding telecommunication infrastructure was acquired in 2021."│
│ Reason: Similarity score (0.31) below empirical threshold (0.55).       │
│ (Abstention: No technique or official mitigations assigned)             │
└─────────────────────────────────────────────────────────────────────────┘
```

**Confidence Badge Criteria (`ConfidenceBadge.jsx`):**
- **HIGH** ($\ge 0.70$): Green pill (`#3ecf8e`), confident semantic match.
- **MED** ($0.50–0.69$): Yellow pill (`#f59e0b`), probable semantic match.
- **LOW** ($< 0.50$): Red pill (`#f87171`), weak similarity flag.
- **ABSTAIN**: Gray pill (`#4b5063`), model explicitly abstained.

---

### 3.4 History Page (`/history`)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Report History                                    [ Search reports... ] │
├────────────────────┬──────────────┬──────┬───────────┬──────────────────┤
│ Report Name        │ Date         │ IOCs │ Mappings  │ Actions          │
├────────────────────┼──────────────┼──────┼───────────┼──────────────────┤
│ apt29_cozybear.pdf │ 2026-09-24   │  40  │ 14 (3 ⊘)  │ [ View ] [ 🗑️ ]   │
│ lazarus_crypto.pdf │ 2026-09-22   │  22  │  9 (1 ⊘)  │ [ View ] [ 🗑️ ]   │
│ unit42_cobalt.pdf  │ 2026-09-18   │  31  │ 11 (2 ⊘)  │ [ View ] [ 🗑️ ]   │
└────────────────────┴──────────────┴──────┴───────────┴──────────────────┘
```

---

## 4. Component Architecture & Responsibilities

The frontend components listed below match `architecture.md` 1:1:

| Component            | File                       | Responsibility & Behavior                                      |
|----------------------|----------------------------|----------------------------------------------------------------|
| `UploadZone`         | `UploadZone.jsx`           | Drag-and-drop file ingestion, size & extension validation      |
| `StatusStepper`      | `StatusStepper.jsx`        | Displays pipeline stages and manages polling interval          |
| `IOCTable`           | `IOCTable.jsx`             | Renders normalized IOCs, category filter buttons, copy actions |
| `MappingCard`        | `MappingCard.jsx`          | ATT&CK technique details, evidence blockquote, score badge     |
| `AbstentionCard`     | `AbstentionCard.jsx`       | Renders abstained behavior sentences without mitigations       |
| `ConfidenceBadge`    | `ConfidenceBadge.jsx`      | Color-coded confidence score pill (HIGH, MED, LOW, ABSTAIN)    |
| `ReportSidebar`      | `ReportSidebar.jsx`        | Report metadata, high-level counts, JSON export, report delete |
| `HistoryTable`       | `HistoryTable.jsx`         | Paginated list of past analyzed reports with deletion modal    |
| `RecommendationList` | `RecommendationList.jsx`   | Collapsible list of official MITRE ATT&CK mitigations          |
| `AIAnalysisCard`     | `AIAnalysisCard.jsx`       | Gemini summary and tips card with "AI-generated" badge & states|

---

## 5. UI Rules & Safeguards

1. **Dark Mode Only:** The interface exclusively supports a modern dark color palette for high contrast and reduced eye strain.
2. **Typography Rules:**
   - All IOC values, technique IDs, CVEs, and confidence numbers must render in monospace font.
   - Evidence sentences must always render in a distinct blockquote surface with quotation styling.
3. **Collapsible Mitigations:**
   - Official MITRE mitigations are collapsed by default on `MappingCard.jsx` to prevent visual clutter, expanding on click with the label: **"From MITRE ATT&CK Mitigations"**.
   - Mitigations must NEVER appear on `AbstentionCard.jsx`.
4. **AI Generation Tagging:**
   - Every block produced by the Gemini API must carry a prominent **"✨ AI-generated"** badge in purple (`#a855f7`).
   - Skeletons and shimmer states must be displayed during Gemini API calls.
5. **No Dangerous HTML:** Never use `dangerouslySetInnerHTML`. All extracted report sentences and AI texts are strictly escaped before rendering.
6. **Responsive Resilience:** Error states must always display clear diagnostic feedback with a "Retry" or "Back to Upload" button, never an empty screen.

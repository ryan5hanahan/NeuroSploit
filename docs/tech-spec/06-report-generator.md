# Report Generator

## Overview

Generates self-contained HTML security assessment reports with dark/light theme support, severity-based color coding, interactive finding expand/collapse, screenshot zoom modals, and a CSS-only CTF flag timeline chart. Reports are auto-generated on scan completion and partial reports are saved when scans are stopped.

File: `backend/core/report_generator.py`

## Class: HTMLReportGenerator

### Constructor

```python
HTMLReportGenerator(config: Optional[ReportConfig] = None)
```

Defaults to `ReportConfig()` if no config provided.

### ReportConfig Dataclass

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `company_name` | str | `"sploit.ai Security"` | Company name in header/footer |
| `logo_base64` | Optional[str] | None | Base64-encoded logo image |
| `include_executive_summary` | bool | True | Include executive summary section |
| `include_methodology` | bool | True | Include methodology section |
| `include_recommendations` | bool | True | Include recommendations section |
| `theme` | str | `"dark"` | `"dark"` or `"light"` |

### Severity Colors

```python
SEVERITY_COLORS = {
    "critical": {"bg": "#dc2626", "text": "#ffffff", "border": "#991b1b"},
    "high":     {"bg": "#ea580c", "text": "#ffffff", "border": "#c2410c"},
    "medium":   {"bg": "#ca8a04", "text": "#ffffff", "border": "#a16207"},
    "low":      {"bg": "#2563eb", "text": "#ffffff", "border": "#1d4ed8"},
    "info":     {"bg": "#6b7280", "text": "#ffffff", "border": "#4b5563"},
}
```

### Severity Sort Order

```python
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
```

Findings are sorted critical-first before rendering.

## generate_report()

```python
def generate_report(
    self,
    session_data: Dict,
    findings: List[Dict],
    scan_results: Optional[List[Dict]] = None
) -> str
```

**Input:**
- `session_data` -- Dict with keys: `name`, `target`, `created_at`, `recon_data` (technologies, endpoints), `ctf_data` (optional).
- `findings` -- List of finding dicts. Each finding has: `title`, `severity`, `vulnerability_type`, `cvss_score`, `cvss_vector`, `cwe_id`, `owasp`, `description`, `affected_endpoint`, `evidence`, `impact`, `remediation`, `references` (list), `screenshots` (list of base64 data URIs), `id`.
- `scan_results` -- Optional list of tool result dicts with `tool`, `status`, `output`.

**Output:** Complete self-contained HTML string with inline CSS, inline JavaScript, and embedded images.

**Processing steps:**
1. Sort findings by severity (critical first) using `SEVERITY_ORDER`.
2. Calculate statistics via `_calculate_stats()`.
3. Render all sections into a single HTML document.

## Report Sections (rendered in order)

### 1. Header (`_generate_header`)
- Report title ("Security Assessment Report")
- Scan name as subtitle
- Metadata row: target URL, date (formatted as "Month DD, YYYY"), scanner identifier

### 2. Executive Summary (`_generate_executive_summary`)
- Narrative text dynamically generated based on severity distribution:
  - Critical findings present: emphasizes immediate risk
  - High findings present: emphasizes prompt remediation
  - Medium findings: moderate risk language
  - Low/info only: reasonable security posture
- Risk score (0-100) calculated as: `critical*25 + high*15 + medium*8 + low*3 + info*1`, capped at 100
- Risk level classification:
  - `score >= 70` or `critical > 0` = HIGH (red gradient meter)
  - `score >= 40` or `high > 1` = MEDIUM (orange gradient meter)
  - Otherwise = LOW (green gradient meter)
- Total findings count in accent box

### 3. Scope (`_generate_scope_section`)
- Target URL (clickable link)
- Endpoints tested count (from `recon_data.endpoints`)
- Assessment type label
- Detected technologies displayed as pill badges (up to 15)

### 4. Findings Summary (`_generate_findings_summary`)
- Six stat cards in a responsive grid: Critical, High, Medium, Low, Info, Total
- Each card has a gradient background matching its severity color

### 5. Findings Detail (`_generate_findings_detail`)
- Expand All / Collapse All buttons
- Per finding (accordion, click to expand):
  - **Header**: severity badge, title, affected endpoint (truncated), expand arrow
  - **Technical info panel** (when CVSS/CWE/OWASP present):
    - CVSS score with color coding (9.0+ red, 7.0+ orange, 4.0+ yellow, >0 blue, 0 gray) and rating text
    - CVSS vector string (monospace)
    - CWE reference as link to `cwe.mitre.org`
    - OWASP Top 10 reference
  - Vulnerability type
  - Description
  - Affected endpoint (monospace box)
  - Evidence / Proof of Concept (monospace box)
  - Screenshots (grid layout, clickable for fullscreen modal)
  - Impact
  - Remediation (green-tinted box)
  - References (up to 5, clickable links)

**Default CVSS scores** (when finding lacks explicit score):
| Severity | Default CVSS |
|----------|-------------|
| critical | 9.5 |
| high | 7.5 |
| medium | 5.0 |
| low | 3.0 |
| info | 0.0 |

### 6. Tool Scan Results (`_generate_scan_results`)
Only rendered when `scan_results` is provided. Per tool:
- Tool name with status indicator (green=completed, red=other)
- Output in scrollable monospace box (truncated to 2000 chars)

### 7. CTF Section (`_generate_ctf_section`)
Only rendered when `session_data['ctf_data']` is present. Contains:
- **Stats row**: Flags Captured, Platforms count, Time to First Flag, Total Elapsed
- **Flags table**: Flag value (monospace, truncated 80 chars), Platform, Source URL, Exploit (method + payload), Time, Submission status (Accepted badge or message)
- **Timeline bar chart**: CSS-based horizontal bars proportional to elapsed time, with flag label and seconds
- **Submission summary**: Submission rate percentage and accepted/total count

### 8. Recommendations (`_generate_recommendations`)
Grouped by priority tier:
- **Immediate** (red): Remediation for each critical finding
- **Short-term (1-2 weeks)** (orange): Address each high finding
- **Medium-term (1 month)** (yellow): Plan fixes for medium findings (up to 5)
- **Ongoing** (blue): Always included -- regular scanning, dependency updates, auth review, logging, periodic pentesting

### 9. Methodology (`_generate_methodology`)
Static four-phase grid:
1. Reconnaissance -- technology fingerprinting, endpoint discovery
2. Vulnerability Scanning -- automated scanning for known vulns
3. AI Analysis -- LLM-powered context and remediation
4. Verification -- manual verification of critical findings

### 10. Footer (`_generate_footer`)
- sploit.ai branding
- Generation timestamp (UTC)
- Confidentiality notice

## Screenshots

`_generate_screenshots_html(finding)` supports two screenshot sources:
1. `finding['screenshots']` list -- base64 data URIs from agent capture
2. Filesystem fallback -- reads PNG files from `reports/screenshots/{finding_id}/` directory, base64-encodes them

Capped at 5 screenshots per finding. First screenshot labeled "Evidence Capture", second "Exploitation Proof", rest "Screenshot N".

## Interactive JavaScript

- **Accordion**: Click finding header to expand/collapse content. Clicking one closes all others.
- **Expand/Collapse All**: Buttons to toggle all findings simultaneously.
- **Print**: `printReport()` function triggers `window.print()`.
- **Screenshot modal**: Click any screenshot image to view fullscreen overlay. Click overlay or press Escape to close.

## CSS Features

- Google Fonts (Inter)
- Responsive grid layouts (`auto-fit`, `minmax`)
- Print styles (`@media print`) with page-break avoidance
- Mobile responsive (`@media max-width: 768px`)
- Fade-in animations on cards
- Hover effects on findings and stat cards

## Report Persistence

Report model in database (`reports` table):

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `scan_id` | FK | References `scans.id` (cascade delete) |
| `title` | String(255) | Report title |
| `format` | String(20) | `"html"`, `"pdf"`, or `"json"` |
| `file_path` | Text | Path to generated file on disk |
| `executive_summary` | Text | Executive summary text |
| `auto_generated` | Boolean | True when generated on scan completion |
| `is_partial` | Boolean | True when generated from stopped/incomplete scan |
| `generated_at` | DateTime | Generation timestamp |

Auto-generation behavior:
- On scan completion: report auto-generated with `auto_generated=True`, `is_partial=False`
- On scan stop: partial report generated with `auto_generated=True`, `is_partial=True`

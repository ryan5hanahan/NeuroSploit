# Reporting

## Overview

NeuroSploit generates professional HTML security assessment reports automatically at scan completion. When a scan finishes (either by completing all phases or being stopped early), the `HTMLReportGenerator` produces a self-contained HTML document with styled sections covering the full assessment. Partial reports are generated when scans are stopped mid-execution, preserving findings discovered up to that point.

## Report Sections

### Header
Company branding (name and optional base64-encoded logo), scan metadata (target name, date range, scan type), and report title. The company name defaults to "NeuroSploit Security" and is configurable via `ReportConfig`.

### Executive Summary
High-level overview of key findings and risk assessment. Summarizes the total number of vulnerabilities by severity (critical, high, medium, low, info), highlights the most significant findings, and provides an overall risk level assessment. Can be excluded via `include_executive_summary` config option.

### Scope
Lists all targets tested during the scan. Includes target URLs and any authentication methods used.

### Findings Summary
Visual summary of findings counts. Includes a severity distribution chart (bar chart with severity-based colors) and a count table of vulnerabilities per severity level.

### Findings Detail
Each vulnerability finding is rendered as a detailed card containing:

| Field | Description |
|-------|-------------|
| Title | Vulnerability name |
| Type | Vulnerability type classification |
| Severity | Critical, High, Medium, Low, or Info with color-coded badge |
| CVSS Score | Numeric CVSS score (when available) |
| CWE ID | Common Weakness Enumeration identifier |
| Description | Detailed vulnerability description |
| Affected Endpoint | URL and HTTP method where the vulnerability was found |
| PoC Payload | Proof-of-concept payload that triggers the vulnerability |
| Evidence | Response data demonstrating the vulnerability exists |
| Request/Response | HTTP request sent and response received (when captured) |
| Impact | Description of what an attacker could achieve |
| Remediation | Specific steps to fix the vulnerability |
| References | External links to relevant security documentation |
| Screenshots | Base64-embedded PNG screenshots (when browser validation captures them) |

Findings are sorted by severity (critical first, info last) using a predefined severity order.

### Scan Results
Optional section included when tool-based scan results are available. Shows output from security tools executed during the scan (nuclei findings, nmap results, etc.).

### CTF Section
Included only when CTF data is present in the session data. Displays:
- Flags captured with their platform, source, and discovery timestamp
- Timing metrics (time to first flag, total flags over time)
- Flag submission results (if auto-submission was configured)

### Recommendations
Aggregated remediation guidance based on all findings. Groups recommendations by vulnerability category and severity. Can be excluded via `include_recommendations` config option.

### Methodology
Description of the testing approach used during the assessment. Covers the phases (recon, analysis, testing), tools used, and testing standards referenced (OWASP WSTG, OWASP Top 10, etc.). Can be excluded via `include_methodology` config option.

### Footer
Report generation timestamp and NeuroSploit branding.

## Report Generation

### Automatic Generation
Reports are automatically generated at two points:
1. **Scan completion**: When all phases complete successfully, a full report is generated with `auto_generated=True`
2. **Scan stop**: When a user stops a running scan, a partial report is generated with `is_partial=True` and `auto_generated=True`

### Manual Generation
Reports can also be generated on demand via the API:
```
POST /api/v1/reports
```
Request body:
```json
{
  "scan_id": "uuid-of-scan",
  "include_executive_summary": true,
  "include_methodology": true,
  "include_recommendations": true
}
```

### Report Storage
Generated reports are stored in the database as `Report` model records linked to the parent scan via `scan_id`. The HTML content is stored directly in the DB record. Reports can be retrieved as raw HTML via the API for download or inline viewing.

### Tool Execution Data
The report generator attempts to include tool execution data from the agent's in-memory results. It checks `agent_results` for the scan's associated agent and includes any `tool_executions` records in the scan results section.

## Styling

### Theme
Reports use a dark theme by default with a dark background and light text. A light theme option is available via the `theme` config parameter (set to `"dark"` or `"light"`).

### Severity Color Coding

| Severity | Background | Border |
|----------|------------|--------|
| Critical | `#dc2626` (red) | `#991b1b` |
| High | `#ea580c` (orange) | `#c2410c` |
| Medium | `#ca8a04` (yellow) | `#a16207` |
| Low | `#2563eb` (blue) | `#1d4ed8` |
| Info | `#6b7280` (gray) | `#4b5563` |

All severity badges use white text for readability.

### Layout
The report uses a responsive layout with a centered container. Findings are rendered as cards with severity-colored left borders. The layout is self-contained -- all CSS is inline in the HTML document, with no external stylesheet dependencies.

## Configuration

The `ReportConfig` dataclass controls report generation behavior:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `company_name` | `str` | `"NeuroSploit Security"` | Company name in header and branding |
| `logo_base64` | `str` | `None` | Base64-encoded logo image for header |
| `include_executive_summary` | `bool` | `True` | Include executive summary section |
| `include_methodology` | `bool` | `True` | Include methodology section |
| `include_recommendations` | `bool` | `True` | Include recommendations section |
| `theme` | `str` | `"dark"` | Color theme: `"dark"` or `"light"` |

## API Endpoints

### List Reports
```
GET /api/v1/reports
```
Query parameters:
- `scan_id` (optional): Filter by scan ID
- `auto_generated` (optional): Filter by auto-generated flag
- `is_partial` (optional): Filter by partial report flag

### Generate Report
```
POST /api/v1/reports
```
Creates a new report for a specified scan.

### Get Report HTML
```
GET /api/v1/reports/{report_id}/html
```
Returns the raw HTML content for inline viewing or download.

### Get Report Details
```
GET /api/v1/reports/{report_id}
```
Returns report metadata (ID, scan_id, generated_at, auto_generated, is_partial, finding counts).

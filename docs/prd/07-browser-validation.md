# Browser Validation

## Overview

Playwright-based browser validation provides real browser interaction for security finding verification and client-side vulnerability detection. Agents use a headless Chromium instance to execute payloads, detect dialogs, capture screenshots, and analyze page content.

## User Stories

- An agent validates XSS findings by executing payloads in a real browser and detecting alert dialogs.
- The CTF pipeline runs browser probes to discover DOM XSS vulnerabilities and hidden pages.
- The MCP server exposes a `screenshot_capture` tool for external LLM agents (Claude Desktop, Cursor) to take page screenshots.

## Capabilities

### Navigation and Injection
- Navigate to URLs with payloads injected into query parameters or form fields.
- Custom interaction steps: click elements, fill form fields, submit forms.

### Security Trigger Detection
The browser validator detects multiple vulnerability indicators in page content:

| Trigger Type | Detection Method |
|-------------|-----------------|
| XSS | Script tags, event handlers in rendered DOM |
| SQLi | Database error patterns in response |
| LFI | System file content (e.g., `/etc/passwd` entries) |
| RCE | uid/gid output patterns |
| Error Disclosure | Stack traces, debug output |

### Dialog Detection
Intercepts JavaScript `alert()`, `confirm()`, and `prompt()` dialogs. Used as the primary XSS validation signal -- a triggered dialog confirms script execution.

### Page Content Analysis
Analyzes rendered page content for trigger patterns after payload injection.

### Screenshot Capture
Screenshots are saved as PNG files in `reports/screenshots/{finding_id}/`. Each validation step can produce a screenshot. Screenshots can be embedded as base64 data URIs in reports and findings.

## CTF Browser Probes

Used in the CTF pipeline (Phase 2), after quick-wins and credential harvesting:

### DOM XSS Probes
- Tests 5 URLs with 2 payloads each (reduced from 15 URLs x 3 payloads to keep probe time under 3 minutes).
- Validation is by `dialog_detected` only -- `triggers_found` matches framework JavaScript and is not reliable for actual XSS confirmation.
- A sentinel `found` flag breaks both the inner payload loop and the outer injection loop on first successful detection.

### Hidden Page Discovery
- Crawls for pages not linked from the homepage.
- Uses baseline text comparison with a similarity ratio threshold: pages with >0.85 similarity to the homepage are classified as SPA fallback routes and skipped.
- Findings are labeled as "BrowserProbe" (not the default "QuickWin").

## Configuration

- **Feature toggle**: `ENABLE_BROWSER_VALIDATION` environment variable.
- **Docker support**: Both `docker/Dockerfile.backend` and `docker/Dockerfile.backend.lite` include Playwright and Chromium installation.
- **Lifecycle**: `BrowserValidator` manages its own browser lifecycle (start/stop). No external browser process management needed.
- **Headless mode**: Enabled by default. Configurable for debugging.

## Integration Points

| Component | Usage |
|-----------|-------|
| `AutonomousAgent` (web UI scan path) | Validates findings when `ENABLE_BROWSER_VALIDATION` is enabled |
| `BaseAgent` (CLI path) | Reads toggle from `ENABLE_BROWSER_VALIDATION` env var |
| `CTFCoordinator` | Runs DOM XSS and hidden page browser probes in Phase 2 |
| MCP Server | `screenshot_capture` tool calls `BrowserValidator.capture_screenshot()` |

## Limitations

- Requires Playwright and Chromium installed in the runtime environment.
- Dialog-only XSS validation can miss non-dialog XSS variants (e.g., DOM manipulation, fetch-based exfiltration).
- Headless Chromium may behave differently from real user browsers (e.g., missing extensions, different user-agent).
- No support for authenticated browser sessions beyond cookie injection.

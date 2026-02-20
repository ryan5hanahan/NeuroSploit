# Scan Engine

## Overview

The scan engine is the primary workflow in sploit.ai. Users create scans targeting URLs, which progress through sequential phases: reconnaissance, AI analysis, vulnerability testing, and report generation. The engine orchestrates real security tools (nmap, nuclei, httpx, subfinder, etc.) combined with LLM-driven analysis to discover, test, and verify vulnerabilities. Scans run as background asyncio tasks and provide real-time progress updates via WebSocket.

## User Stories

### Create and Run a Scan
A penetration tester creates a scan against a target URL and receives a professional HTML report. The scan progresses autonomously through recon, analysis, and testing phases. The user monitors progress in real time and receives findings as they are discovered.

### Authenticated Testing
A user configures authentication (cookie, bearer token, basic auth, or custom header) for a scan. The scan engine includes these credentials in all requests, enabling testing of authenticated attack surfaces that would be inaccessible to unauthenticated scans.

### Real-time Monitoring
A user monitors scan progress via WebSocket. The frontend receives phase changes, progress percentage updates, log messages, and individual findings as they are discovered -- without polling.

### Scan Control
A user pauses a running scan to investigate a finding manually, then resumes it. Alternatively, a user stops a scan early, which saves partial results and auto-generates a partial report. A user can also skip ahead to a later phase (e.g., skip recon and jump to testing).

### Repeat Scan
A user repeats a completed scan. The system clones the original scan's configuration (targets, type, auth, custom headers, tradecraft, prompt) into a new scan and starts it automatically. The new scan links back to the original via `repeated_from_id`.

### Compare Scans
A user compares two completed scans to understand what changed. The comparison produces a structured diff: new vulnerabilities, resolved vulnerabilities, persistent vulnerabilities, changed vulnerabilities (severity or CVSS changes), new endpoints, removed endpoints, changed endpoints (status code, technologies, parameters), and stable endpoints.

## Scan Lifecycle

A scan progresses through the following states:

```
pending → running → completed
                  → stopped (user-initiated)
                  → failed (error)
```

While in `running` state, the scan progresses through phases:

```
initializing → recon → analyzing → testing → reporting → completed
```

Each phase transition is broadcast via WebSocket. The `current_phase` field on the Scan model tracks the active phase.

### Phase Details

1. **Initializing**: Scan record created in DB, targets validated, configuration loaded, agent instantiated.
2. **Recon**: Real tool-based reconnaissance using ReconIntegration (subfinder, httpx, katana, nmap, etc.). Discovers endpoints, technologies, forms, parameters, API endpoints. Falls back to autonomous scanning if tools find minimal data.
3. **Analyzing**: LLM analyzes the recon data and generates a testing plan (TestingPlan). The plan includes prioritized vulnerability types, specific endpoints to target, bypass techniques, custom payloads, and testing depth. If the user skips this phase, a default testing plan covering 16 common vulnerability types is used.
4. **Testing**: The AutonomousAgent executes the testing plan. For each vulnerability type and endpoint combination, the agent generates payloads, sends requests, analyzes responses, verifies findings via negative control testing, scores confidence, and produces proof-of-execution records.
5. **Reporting**: HTMLReportGenerator produces a professional report from the scan's findings. The report is stored in the DB (Report model) and linked to the scan.

## Scan Types

| Type | Description |
|------|-------------|
| `quick` | Minimal reconnaissance, reduced payload count, faster completion |
| `full` | Complete reconnaissance and comprehensive vulnerability testing |
| `custom` | User-defined configuration via custom prompt and manual settings |

The default scan type is controlled by the `DEFAULT_SCAN_TYPE` setting (defaults to `full`).

## Scan Configuration

Scans are created via `POST /api/v1/scans` with the following configuration:

| Field | Type | Description |
|-------|------|-------------|
| `targets` | `List[str]` | Target URLs to scan (required, at least one) |
| `name` | `str` | Scan name (optional, max 255 chars) |
| `scan_type` | `str` | `quick`, `full`, or `custom` (optional, uses `DEFAULT_SCAN_TYPE` setting if not specified) |
| `recon_enabled` | `bool` | Enable recon phase (optional, uses `RECON_ENABLED_BY_DEFAULT` setting if not specified) |
| `custom_prompt` | `str` | Custom instructions for the AI agent (optional, max 32k chars) |
| `prompt_id` | `str` | ID of a preset prompt to use instead of custom_prompt |
| `auth` | `AuthConfig` | Authentication configuration (see below) |
| `custom_headers` | `dict` | Custom HTTP headers to include in all requests |
| `tradecraft_ids` | `List[str]` | TTP IDs from the tradecraft library to use |
| `config` | `dict` | Additional configuration key-value pairs |

### Authentication Configuration (AuthConfig)

| Field | Description |
|-------|-------------|
| `auth_type` | `none`, `cookie`, `header`, `basic`, `bearer` |
| `cookie` | Session cookie value (for `cookie` type) |
| `bearer_token` | Bearer/JWT token (for `bearer` type) |
| `username` | Username (for `basic` type) |
| `password` | Password (for `basic` type) |
| `header_name` | Custom header name (for `header` type) |
| `header_value` | Custom header value (for `header` type) |

## Real-time Updates

WebSocket endpoint: `ws://host/ws/scan/{scan_id}`

The WebSocket broadcasts the following event types during scan execution:

- **Progress updates**: `{ progress: int, phase: str }` -- percentage complete and current phase name
- **Log messages**: `{ level: "info"|"warning"|"error", message: str }` -- agent activity logs
- **Finding notifications**: Individual vulnerability findings as they are discovered and verified
- **Phase transitions**: Notification when the scan moves from one phase to the next
- **Completion**: Final status (completed, stopped, failed) with summary statistics

## Scan Control Operations

### Start
`POST /api/v1/scans` -- Creates and starts a scan. The scan is registered in the scan registry and launched as a background asyncio task. Enforces `MAX_CONCURRENT_SCANS` limit; returns HTTP 429 if exceeded.

### Stop
`POST /api/v1/scans/{scan_id}/stop` -- Stops a running scan. Cancels the background task via the scan registry. The agent saves partial results, and a partial report is auto-generated. The scan status is set to `stopped` with `completed_at` timestamp and duration calculated.

### Pause / Resume
`POST /api/v1/scans/{scan_id}/pause` and `POST /api/v1/scans/{scan_id}/resume` -- Pauses and resumes a running scan. The agent suspends/resumes its testing loop.

### Skip to Phase
`POST /api/v1/scans/{scan_id}/skip-to/{phase}` -- Advances a running scan to a later phase. Only forward skips are allowed (based on the phase order: initializing, recon, analyzing, testing, completed). Skipping the analysis phase uses a default testing plan covering 16 common vulnerability types. The skip signal is communicated via an in-memory dict (`_scan_phase_control`) that the running task checks between phases.

### Repeat
`POST /api/v1/scans/{scan_id}/repeat` -- Clones the configuration of a completed scan (targets, scan_type, recon_enabled, custom_prompt, prompt_id, auth, custom_headers, tradecraft_ids) into a new scan record. The new scan's `repeated_from_id` field references the original. The cloned scan is auto-started. Enforces `MAX_CONCURRENT_SCANS` limit; returns HTTP 429 if exceeded.

### Delete
`DELETE /api/v1/scans/{scan_id}` -- Deletes a scan and all associated records (targets, endpoints, vulnerabilities, vulnerability tests, agent tasks, tradecraft links, reports). Running scans must be stopped before deletion.

## Scan Comparison

`GET /api/v1/scans/compare/{scan_id_a}/{scan_id_b}` -- Computes a structured diff between two scans.

### Vulnerability Diff
Vulnerabilities are matched by a composite key of `(vulnerability_type, affected_endpoint, parameter)`. The diff produces four categories:

- **New**: Vulnerabilities present in scan B but not scan A
- **Resolved**: Vulnerabilities present in scan A but not scan B
- **Persistent**: Vulnerabilities present in both scans with the same severity and CVSS
- **Changed**: Vulnerabilities present in both scans but with different severity or CVSS scores (includes `severity_changed` and `cvss_changed` detail)

### Endpoint Diff
Endpoints are matched by `(url, method)`. The diff produces four categories:

- **New**: Endpoints discovered in scan B but not scan A
- **Removed**: Endpoints present in scan A but not scan B
- **Changed**: Endpoints in both scans with different response status, technologies, or parameters
- **Stable**: Endpoints unchanged between scans

## Aggressive Mode

Controlled by the `AGGRESSIVE_MODE` toggle in settings.

When enabled:
- Scan depth context is set to `"thorough"` (vs `"standard"` when disabled)
- Payload limit per vulnerability type is increased to 15 (vs 5 in standard mode)

This affects the AutonomousAgent's testing behavior -- more payloads are generated and tested per endpoint/vulnerability combination, increasing coverage at the cost of scan duration and request volume.

## Concurrent Scan Limiting

The `MAX_CONCURRENT_SCANS` setting (default: 3) limits how many scans can run simultaneously. This limit is enforced at two points:

1. **start_scan** (`POST /api/v1/scans`): Before launching a new scan, the system counts running scans in the database. If the count meets or exceeds the limit, the request is rejected with HTTP 429.
2. **repeat_scan** (`POST /api/v1/scans/{scan_id}/repeat`): Same enforcement as start_scan, since repeating a scan launches a new background task.

## Default Configuration Settings

Two settings provide defaults when the client does not specify values:

- **`DEFAULT_SCAN_TYPE`** (default: `"full"`): Used when `scan_type` is not provided in the ScanCreate request. The `ScanCreate` schema defines `scan_type` as `Optional[str]`, and the `create_scan()` endpoint reads this setting as the fallback.
- **`RECON_ENABLED_BY_DEFAULT`** (default: `true`): Used when `recon_enabled` is not provided in the ScanCreate request. Same pattern -- the `ScanCreate` schema defines `recon_enabled` as `Optional[bool]`, with the setting as fallback.

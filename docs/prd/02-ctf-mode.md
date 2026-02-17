# CTF Mode

## Overview

The multi-agent CTF pipeline is an orchestrated system for automated CTF challenge solving. The `CTFCoordinator` class manages a phased approach that deploys specialized agents through reconnaissance, quick exploitation, credential harvesting, browser probes, LLM-driven prioritization, and parallel testing to maximize flag capture rate against web application CTF targets.

The CTF pipeline is a separate code path from the standard scan engine. It is invoked via `POST /api/v1/vuln-lab/run` with `ctf_mode: true`, not through the scans API.

## User Stories

### Launch CTF Pipeline
A CTF competitor launches the multi-agent pipeline against a CTF target (e.g., OWASP Juice Shop). The system autonomously deploys 2-6 agents through phased testing, capturing flags as challenges are solved.

### Auto-detect Flags
The system automatically detects flags from multiple CTF platforms in HTTP responses, page content, and log messages. Supported formats include `flag{...}`, `HTB{...}`, `THM{...}`, `picoCTF{...}`, `MetaCTF{...}`, `CTF{...}`, PortSwigger "Congratulations" messages, and bare MD5/SHA256 hex hashes.

### Auto-submit Flags
When a flag submission URL and platform token are configured, captured flags are automatically submitted to the CTF platform API at the end of the pipeline. The submitter tries multiple common body formats to maximize compatibility with different CTF platforms.

## Pipeline Phases

The CTF pipeline progresses through the following phases in order. Each phase checks for cancellation before proceeding. If cancelled at any point, the pipeline builds and returns a partial report with findings collected so far.

### Phase 1: Recon (5% progress)

A single AutonomousAgent is instantiated in `FULL_AUTO` mode with a `GovernanceAgent` scoped to the CTF target. The agent runs two parallel tasks:
- **Reconnaissance** (`_run_recon_only()`): Endpoint discovery, technology detection, form enumeration, parameter extraction, API endpoint identification using the standard recon pipeline (subfinder, httpx, katana, etc.)
- **Sandbox scan** (`_run_sandbox_scan()`): Docker-based security tool execution (nuclei, nmap, etc.)

The recon data (endpoints, parameters, technologies, forms, API endpoints) is deep-copied and shared with all subsequent phases.

After completion, the recon agent is removed and its resources released.

### Phase 1.5: Quick Wins (20% progress)

Ten parallel generic exploit probes run simultaneously against common vulnerability patterns. These are lightweight HTTP-based probes that do not require the full agent framework. Each probe targets a single common vulnerability:

1. **SQLi Login Bypass**: Attempts `' OR 1=1--` and similar payloads against discovered login forms and common auth endpoints (`/rest/user/login`, `/api/login`, `/login`, `/auth/login`)
2. **Default Credentials**: Tries common username/password combinations (`admin/admin`, `admin/password`, `admin/admin123`, etc.) against login endpoints
3. **Admin Panel Discovery**: Probes common admin paths (`/admin`, `/administrator`, `/admin-panel`, `/management`, `/admin.php`, etc.)
4. **Exposed Files**: Checks for sensitive file exposure (`.env`, `.git/config`, `robots.txt`, `sitemap.xml`, `package.json`, `composer.json`, `/api-docs`, `/.well-known/security.txt`, etc.)
5. **XSS Probes**: Injects XSS payloads into discovered form parameters and URL query parameters
6. **IDOR Probes**: Tests sequential ID manipulation on API endpoints (e.g., changing `/api/users/1` to `/api/users/2`)
7. **Open Redirect**: Tests redirect parameters (`?url=`, `?redirect=`, `?next=`, `?return=`) with external URLs
8. **Path Traversal**: Attempts `../../../etc/passwd` and similar payloads against file-related endpoints
9. **API Disclosure**: Probes for API documentation endpoints (`/api/swagger.json`, `/api/openapi.json`, `/api-docs`, `/graphql`, etc.)
10. **Registration Abuse**: Attempts user registration at common signup endpoints, which can solve challenges related to account creation

All quick-win findings are checked against the flag detector. Findings are labeled with agent `"QuickWin"`.

### Phase 1.55: Credential Harvesting

Runs after quick wins. This phase attempts to log in with discovered or default credentials, extract JWT tokens from successful login responses, and use those tokens to probe authenticated endpoints.

**Login attempts**: The system tries credential combinations against REST API auth paths (`/rest/user/login`, `/api/login`, `/login`) and any additional paths discovered during recon. These REST API paths are always prepended (not appended) to ensure they are tried first.

**Token extraction** (`_extract_auth_token()`): Parses JWT tokens from login response bodies. Checks multiple JSON paths in order: `token`, `access_token`, `authentication.token`, `data.token`.

**Authenticated probes**: With harvested tokens, the system probes:
- IDOR with sequential user IDs
- Admin endpoints (`/api/admin`, `/rest/admin`, `/admin`)
- API manipulation (PUT/DELETE on user-related endpoints)
- Parameter boundary values

Harvested tokens are stored in `self._harvested_auth_headers` and merged with base auth headers for all testing agents in subsequent phases.

### Phase 1.6: Browser Probes (22% progress)

Requires Playwright and Chromium. If not available, this phase is skipped.

**DOM XSS Detection**: Tests up to 5 URLs with 2 XSS payloads each. Validation is based exclusively on `dialog_detected` events (JavaScript `alert()` / `confirm()` / `prompt()` dialogs) rather than pattern matching in page source (which produces false positives from framework JavaScript). A sentinel `found` flag breaks both the payload loop and the injection loop when a dialog is detected.

**Hidden Page Discovery**: Probes common hidden paths (`/score-board`, `/admin`, `/accounting`, etc.). Each discovered page's content is compared against the homepage text baseline using similarity ratio. Pages with similarity > 0.85 are treated as SPA fallback routes and skipped. Only pages with genuinely distinct content are reported.

Browser probe findings are labeled `"BrowserProbe"`.

### Phase 2: LLM Analysis (25% progress)

A single LLM call prioritizes vulnerability types based on the recon data. The LLM receives a summary of discovered technologies, endpoints, forms, parameters, and API endpoints, along with the full list of available vulnerability types.

The LLM returns a JSON array of vulnerability type strings ordered by likelihood of success for the specific target. If the LLM call fails (no API key, network error, invalid JSON), the system falls back to the default attack plan.

**Filtering**: Vulnerability types that are irrelevant for web application CTFs are removed before distribution. The filter excludes 9 types: `s3_bucket_misconfiguration`, `cloud_metadata_exposure`, `container_escape`, `serverless_misconfiguration`, `subdomain_takeover`, `soap_injection`, `zip_slip`, `insecure_cdn`, `rest_api_versioning`.

**Distribution**: Prioritized vulnerability types are round-robin distributed across N-1 testing agents (one agent was used for recon). Each agent receives a roughly equal share of vulnerability types.

### Phase 3: Parallel Testing (35% progress)

N-1 AutonomousAgents are launched in parallel via `asyncio.gather`. Each agent:
- Receives the shared recon data (deep-copied)
- Tests its assigned vulnerability types
- Has access to harvested auth headers from Phase 1.55
- Reports findings via the shared finding callback
- Is governed by a `GovernanceAgent` scoped to the CTF target

Agents use labels from the `AGENT_LABELS` list: Alpha, Bravo, Charlie, Delta, Echo.

Periodic challenge polling runs concurrently with testing (for CTF platforms that expose a challenge API). The system takes a baseline snapshot and periodically diffs to detect newly solved challenges.

### Phase 3.5: Flag Submission (93% progress)

If a flag submission URL was configured and the flag detector has captured flags, the `CTFFlagSubmitter` submits all captured flags to the CTF platform.

### Phase 4: Aggregation (95% progress)

All findings from all phases are merged and deduplicated into a final report. The report includes:
- Combined finding list
- Flag timeline (when each flag was captured)
- Agent performance metrics
- Pipeline duration

## Flag Detection

The `CTFFlagDetector` class maintains a registry of regex patterns for 7 CTF platforms:

| Platform | Pattern | Example |
|----------|---------|---------|
| NetWars | `flag{...}` or `FLAG{...}` | `flag{s3cret_token}` |
| HackTheBox | `HTB{...}`, bare 32-char MD5 hex, bare 64-char SHA256 hex | `HTB{h4ck3d}` |
| TryHackMe | `THM{...}` (case-insensitive) | `THM{got_root}` |
| PortSwigger | `"Congratulations, you solved the lab"` or `congratulations-message` CSS class | Page content match |
| PicoCTF | `picoCTF{...}` | `picoCTF{sql_1nj3ct10n}` |
| MetaCTF | `MetaCTF{...}` | `MetaCTF{binary_fun}` |
| Generic | `CTF{...}` (case-insensitive) | `CTF{found_it}` |

Additionally, custom regex patterns can be provided at pipeline launch via the `ctf_flag_patterns` parameter.

The flag detector:
- Scans HTTP response bodies, headers, and log messages
- Deduplicates flags (tracks seen flags in a set)
- Records capture metadata: `CapturedFlag` dataclass with flag value, platform, source (body/header/log), URL, field, request method, payload, timestamp, finding ID
- Tracks a flag timeline for performance metrics (time from pipeline start to each flag capture)

## Flag Submission

The `CTFFlagSubmitter` auto-submits captured flags to a CTF platform's submission endpoint. It tries multiple common request body formats in sequence:

1. `{"flag": flag_value}` (CTFd standard)
2. `{"answer": flag_value}`
3. `{"submission": flag_value}`
4. `{"key": flag_value}`
5. Form-encoded `flag=flag_value` (fallback)

For each format, a successful submission is identified by HTTP 200/201 status with response body containing "correct", "success", "accepted", "solved", or "already". A 400 response containing "already" is also treated as success (flag was previously submitted).

Bearer token authentication is supported via `ctf_platform_token`.

## API

### Launch CTF Pipeline

```
POST /api/v1/vuln-lab/run
```

Request body:
```json
{
  "target_url": "http://target:3000",
  "ctf_mode": true,
  "ctf_agent_count": 4,
  "ctf_flag_patterns": ["custom_flag_\\{[^}]+\\}"],
  "ctf_submit_url": "https://ctf-platform.com/api/submit",
  "ctf_platform_token": "bearer-token-here",
  "challenge_name": "Juice Shop",
  "auth_type": "bearer",
  "auth_value": "existing-token",
  "custom_headers": {"X-Custom": "value"},
  "notes": "Focus on injection challenges"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_url` | `str` | Yes | Target URL |
| `ctf_mode` | `bool` | Yes (must be `true`) | Enable CTF pipeline |
| `ctf_agent_count` | `int` | No | Number of agents, 2-6 (default: 3) |
| `ctf_flag_patterns` | `List[str]` | No | Custom regex patterns for flag detection |
| `ctf_submit_url` | `str` | No | Flag submission endpoint URL |
| `ctf_platform_token` | `str` | No | Auth token for flag submission |
| `challenge_name` | `str` | No | Name for this CTF run |
| `auth_type` | `str` | No | Auth type: cookie, bearer, basic, header |
| `auth_value` | `str` | No | Auth credential value |
| `custom_headers` | `dict` | No | Custom HTTP headers |
| `notes` | `str` | No | Notes / additional context |

### Stop Running Pipeline

```
POST /api/v1/vuln-lab/challenges/{challenge_id}/stop
```

Cancels the running CTF pipeline. All agents are signaled to stop. A partial report is generated from findings collected so far.

## Current Performance

Testing against OWASP Juice Shop (standard benchmark):

- **Baseline**: 10-13 challenges solved per 10-minute run, including SQLi login bypass, default credentials, information disclosure, registration abuse, IDOR
- **With credential harvesting**: Additional challenges solved including Login Jim (difficulty 3), Login Bjoern (difficulty 4), Forged Feedback (difficulty 3)

## Limitations

- Many easy CTF challenges require client-side interaction (DOM XSS with specific browser events, Score Board discovery, Zero Stars review submission, Privacy Policy acceptance) that is not yet fully automated
- DOM XSS detection is limited by dialog-only validation -- XSS payloads that do not trigger `alert()`/`confirm()`/`prompt()` are not detected
- The pipeline is optimized for web-based CTFs. Binary exploitation, cryptography, reverse engineering, and forensics challenges are not supported
- Agent count is capped at 2-6 (the coordinator enforces `max(2, min(6, agent_count))`)
- The `lab_results` log buffer holds 200 entries -- early pipeline logs rotate out during long runs

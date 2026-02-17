# CTF Coordinator

## Overview
Multi-agent pipeline orchestrator for CTF challenge solving. Coordinates specialized agents through a phased approach to maximize flag capture. Designed for competitive CTF scenarios where breadth and speed matter.

## Class: CTFCoordinator
File: `backend/core/ctf_coordinator.py`

### Constructor
```python
CTFCoordinator(
    target: str,
    agent_count: int,           # clamped to range [2, 6]
    flag_detector: CTFFlagDetector,
    log_callback: Callable,     # async (level, message)
    progress_callback: Callable, # async (progress_int, phase_str)
    finding_callback: Callable,  # async (finding_dict)
    auth_headers: Optional[Dict] = None,
    custom_prompt: Optional[str] = None,
    challenge_name: Optional[str] = None,
    notes: Optional[str] = None,
    lab_context: Optional[Dict] = None,
    scan_id: Optional[str] = None,
    ctf_submit_url: str = "",
    ctf_platform_token: str = "",
)
```

- `agent_count` is clamped: `max(2, min(6, agent_count))`. Testing agents = `agent_count - 1` (1 agent reserved for recon).
- `AGENT_LABELS`: `["Alpha", "Bravo", "Charlie", "Delta", "Echo"]` -- human-readable labels for testing agents.

### Internal State
- `_agents: List[AutonomousAgent]` -- currently running agent instances (for cancellation)
- `_cancelled: bool` -- pipeline cancellation flag
- `_recon_data` -- deep-copied recon data from Phase 1
- `_all_findings: List[Dict]` -- accumulated findings from all phases
- `_harvested_auth_headers: Dict[str, str]` -- JWT tokens extracted from successful logins

### Pipeline Phases

#### Phase 1: Recon (progress 5-15%)
- Single `AutonomousAgent` in `FULL_AUTO` mode (despite the name, only `_run_recon_only()` and `_run_sandbox_scan()` are called via `asyncio.gather`)
- `GovernanceAgent` with `create_ctf_scope(target)` for scope enforcement
- Discovers endpoints, forms, parameters, technology stack
- Results deep-copied into `_recon_data`
- Progress mapped: agent 0-100% -> pipeline 5-25%

#### Phase 1.5: Quick Wins (progress 15-30%)
10 parallel probe coroutines via `asyncio.gather`, all using a shared `aiohttp.ClientSession` with `TCPConnector(ssl=False, limit=20)` and 10-second timeout:

1. **SQLi login bypass** (`_probe_sqli_login`): Tries 5 SQLi payloads (`' OR 1=1--`, `admin'--`, etc.) on login endpoints. REST API auth paths (`/rest/user/login`, `/api/login`, etc.) are always prepended to the login path list -- recon-discovered SPA paths appended as supplements. Tries both JSON and form-encoded. Extracts auth tokens from successful responses.

2. **Default credentials** (`_probe_default_creds`): Tries 9 credential pairs (admin/admin, admin/password, root/root, etc.) on up to 2 login URLs. Both `email`+`password` and `username`+`password` JSON formats. Extracts auth tokens.

3. **Admin panel discovery** (`_probe_admin_access`): Checks recon-discovered admin paths + `/admin`, `/administration`, `/api/admin`. Looks for admin indicators in 200 responses while filtering out login/unauthorized pages.

4. **Sensitive file exposure** (`_probe_sensitive_files`): Probes 30+ paths in batches of 10 (`/robots.txt`, `/.env`, `/.git/HEAD`, `/backup/`, `/package.json`, `/metrics`, etc.). Non-redirect 200 responses > 50 bytes without "not found"/"404" indicators count as findings.

5. **Search/parameter injection** (`_probe_search_injection`): Tests search endpoints for XSS (3 payloads, reflected check), SQLi (3 payloads, SQL error keyword check), and SSTI (`{{13*37}}` checking for `481` in response -- not `{{7*7}}`/49 which false-positives on natural page content).

6. **IDOR** (`_probe_idor`): Tests API endpoints by appending `/1` and `/2` -- different non-empty responses indicate potential IDOR.

7. **Open redirect** (`_probe_open_redirect`): Tests redirect parameters (`to`, `url`, `next`, `redirect`, etc.) with `https://evil.com` targets. Checks for "evil.com" in `Location` header on 3xx responses.

8. **Path traversal** (`_probe_path_traversal`): Tests file-related endpoints with 4 traversal payloads as both query params (`file`, `path`, `name`, etc.) and path suffixes. Checks for `root:` or `[extensions]` in response.

9. **API disclosure** (`_probe_api_disclosure`): GraphQL introspection query on `/graphql`, `/api/graphql`, `/gql`. Checks for `__schema` in response.

10. **Registration abuse** (`_probe_registration_abuse`): Mass assignment (register with `role: admin` or `isAdmin: true`), empty registration. Checks response for role/admin indicators.

Findings labeled with `agent_label: "QuickWin"`.

#### Phase 1.55: Credential Harvesting (progress 30-40%)
`_harvest_and_reuse_credentials()` -- runs only if `_harvested_auth_headers` is non-empty (populated by successful logins during Quick Wins).

**Token extraction** (`_extract_auth_token`):
- Parses JSON response body
- Checks keys in order: `token`, `access_token`, `authentication.token`, `data.token`
- Stores as `{"Authorization": "Bearer <token>"}`
- Only extracts once (first successful login wins)

**Authenticated probes** (4 parallel coroutines via `asyncio.gather`):
1. `_probe_authed_idor` -- access resources `/1`, `/2`, `/3` on API endpoints, check for user data fields (email, username, password, address)
2. `_probe_authed_admin` -- access `/api/admin`, `/api/users`, `/api/config` with auth token
3. `_probe_authed_api_manipulation` -- access other users' baskets/carts, DELETE feedback/reviews
4. `_probe_parameter_manipulation` -- boundary values on feedback (rating=0, -1, 999), negative quantity on product endpoints

Findings labeled with `agent_label: "AuthProbe"`.

#### Phase 2: Browser Probes (progress 40-55%)
Requires `HAS_PLAYWRIGHT` (imported with fallback). Uses `BrowserValidator` with `screenshots_dir="reports/screenshots"`.

**DOM XSS** (`_probe_dom_xss`):
- 2 payloads: `<img src=x onerror=alert(document.domain)>`, `"><svg onload=alert(1)>`
- Up to 6 URLs (search endpoints prioritized, then other recon endpoints)
- Injected via URL fragment (`#payload`) and query param (`?q=payload`)
- Validation: only `dialog_detected` is trusted (not `triggers_found`, which matches framework JS patterns)
- Dialog verification: checks for "1" or "document.domain" in dialog messages to distinguish from app-triggered dialogs
- Sentinel `found` flag breaks both payload and injection loops
- Screenshots captured as base64 data URIs

**Hidden pages** (`_probe_hidden_pages`):
- Tests 12 paths: `/#/profile`, `/#/settings`, `/#/help`, `/#/faq`, `/#/terms`, `/#/privacy`, `/#/docs`, `/#/leaderboard`, `/admin`, `/dashboard`, `/debug`, `/console`
- Homepage baseline: captures `document.body.innerText` (first 500 chars)
- Jaccard similarity: word-set overlap. Pages with similarity > 0.75 to homepage are skipped (SPA fallback detection)
- Filters: 404/error indicators, content length < 20 chars
- Full-page screenshot as evidence

**Client-side exploits** (`_probe_client_side_exploits`):
- Inspects `localStorage`, `sessionStorage`, and `document.cookie` for sensitive keys (token, jwt, auth, session, password, secret, api_key)
- Triggers 404 page to check for verbose error pages (stack traces, tracebacks)

Findings labeled with `agent_label: "BrowserProbe"`.

#### Phase 3: LLM Analysis (progress 55-65%)
`_run_analysis_phase()`:
- Builds recon summary: technologies, endpoint samples (first 15), forms count, parameters count, API endpoint count
- Gets default attack plan (91 vuln types in priority order from `_static_default_attack_plan()`)
- Sends prompt to LLM asking for JSON array of prioritized vuln types
- Parses response, handles markdown code blocks
- Falls back to default plan on LLM failure
- Filters out `_IRRELEVANT_WEB_CTF_VULNS` (9 types: s3_bucket_misconfiguration, cloud_metadata_exposure, container_escape, serverless_misconfiguration, subdomain_takeover, soap_injection, zip_slip, insecure_cdn, rest_api_versioning)
- Round-robin distributes vuln types across testing agents

#### Phase 4: Parallel Testing (progress 65-90%)
`_run_testing_phase(assignments)`:
- N-1 `AutonomousAgent` instances launched via `asyncio.gather(*tasks, return_exceptions=True)`
- Each agent (`_run_single_tester`):
  - Gets labeled log/finding callbacks (prefixed with `[Alpha]`, `[Bravo]`, etc.)
  - `GovernanceAgent` with `create_ctf_scope(target)`
  - `AutonomousAgent` in `FULL_AUTO` mode with `preset_recon` (deep-copied recon data), `focus_vuln_types`, and `agent_label`
  - Auth headers merged: `{**self.auth_headers, **self._harvested_auth_headers}`
  - Findings appended to `_all_findings` via labeled finding callback
- Progress mapped: each agent contributes proportionally within 35-95% range
- Exceptions logged but don't crash the pipeline

#### Phase 3.5: Flag Submission (progress 93%)
`_submit_captured_flags()`:
- Only runs when `flag_detector` has captured flags AND `ctf_submit_url` is configured
- Creates `CTFFlagSubmitter(submit_url, platform_token)`
- Shared `aiohttp.ClientSession` with `ssl=False`
- Updates each `CapturedFlag.submitted` and `CapturedFlag.submit_message`
- Logs accepted/rejected counts

#### Phase 5: Aggregation (progress 95-100%)
`_build_final_report(start_time)`:
- Sorts all findings by severity (critical first)
- Deduplicates by `(vuln_type, normalized_endpoint, parameter)` key
  - Endpoint normalized: strip query params + trailing slash
  - Highest-severity finding wins per dedup key
- Returns report dict with:
  - `findings` -- deduplicated list
  - `recon` -- endpoints, technologies, parameters
  - `executive_summary` -- agent count, duration, finding count
  - `pipeline_info` -- raw vs unique finding counts, duration
  - `ctf_flags` -- serialized `CapturedFlag` list (if flag detector present)
  - `ctf_metrics` -- flag count, time-to-first-flag, timeline
  - `ctf_data` -- combined flags + metrics + submit URL

### Cancellation
- `cancel()` sets `_cancelled = True` and calls `cancel()` on every agent in `_agents` list
- Each pipeline phase checks `if self._cancelled: return self._build_final_report(start_time)` before proceeding
- Agent-level cancellation: `AutonomousAgent.cancel()` sets internal flag, checked between vuln type iterations

### Finding Format
`_make_finding()` produces standardized dict:
```python
{
    "title": str,
    "vulnerability_type": str,
    "severity": str,
    "affected_endpoint": str,
    "parameter": str,
    "payload": str,
    "evidence": str,
    "request_method": str,
    "agent_label": str,  # "QuickWin", "AuthProbe", "BrowserProbe", or agent label
    "cvss_score": float, # mapped from severity: critical=9.8, high=7.5, medium=5.0, low=3.0, info=0.0
    "cwe_id": str,
    "description": str,
    "impact": str,
    "remediation": str,
    "references": list,
}
```

### Progress Mapping
- Recon agent: agent 0-100% mapped to pipeline 5-25%
- Testing agents: each agent's 0-100% mapped to proportional slice within pipeline 35-95%
- Formula: `base + (progress * per_agent_range / 100)` where `per_agent_range = 60 / testing_agent_count`

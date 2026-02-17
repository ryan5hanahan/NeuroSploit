# Scan Service

## Overview
The scan service orchestrates the end-to-end scan lifecycle from the web UI path. It manages the `ScanService` class (traditional scan pipeline) and `AutonomousAgent` instances (AI-driven testing loop). The entry point is `run_scan_task(scan_id)`, spawned as an asyncio task by the scans API router.

## Entry Point
`backend/services/scan_service.py` exports `run_scan_task(scan_id)` -- an async function that creates its own DB session via `async_session_factory()`, instantiates `ScanService`, and calls `execute_scan(scan_id)`. On `CancelledError`, it updates the scan to "stopped" status. On completion (or cancellation), it calls `scan_registry.unregister(scan_id)` and cleans up `_scan_phase_control`.

## Scan Registry
`backend/core/scan_registry.py` manages active scans via a module-level `_registry` dict mapping `scan_id` to `ScanHandle` dataclass instances.

### ScanHandle
```python
@dataclass
class ScanHandle:
    scan_id: str
    cancel_event: asyncio.Event  # cooperative cancellation flag
    child_pids: Set[int]         # tracked subprocess PIDs
    task: Optional[asyncio.Task] # the asyncio task running the scan
```

### Registry Functions
- `register(scan_id)` -> returns `ScanHandle` (called BEFORE `asyncio.create_task` to avoid race conditions)
- `get(scan_id)` -> returns handle or `None`
- `cancel(scan_id)` -> sets `cancel_event`, sends SIGTERM to all tracked child PIDs, schedules SIGKILL after 3 seconds, cancels the asyncio `Task`
- `unregister(scan_id)` -> removes from registry
- `track_pid(scan_id, pid)` / `untrack_pid(scan_id, pid)` -> manage subprocess PIDs for forceful termination

### Stop Check
`ScanService._stop_requested` is a property that checks `scan_registry.get(scan_id).is_cancelled()`. Setting it to `True` triggers `scan_registry.cancel(scan_id)`.

## ScanService Class
File: `backend/services/scan_service.py`

### Constructor
```python
ScanService(db: AsyncSession, scan_id: str = None)
```
- `db`: Async SQLAlchemy session
- `scan_id`: Scan ID for registry-based cancellation checks
- `ai_processor`: `AIPromptProcessor()` -- converts prompts + recon data into `TestingPlan`
- `ai_analyzer`: `AIVulnerabilityAnalyzer()` -- AI-confirms findings
- `payload_generator`: `PayloadGenerator()` -- generates test payloads per vuln type
- `aggressive_mode`: Read from `os.getenv("AGGRESSIVE_MODE")` on init. Controls testing depth ("thorough" vs "standard") and payload limit (15 vs 5 per vuln type per endpoint).

### Execution Flow (`execute_scan`)

**Phase 0: Initializing** (progress 2%)
1. Load scan and targets from DB
2. Check installed security tools via `check_tools_installed()`
3. Load prompt content (custom_prompt > prompt_id lookup > default comprehensive prompt)

**Phase 1: Reconnaissance** (progress 5-20%)
- Skippable via phase-skip signal from API
- `ReconIntegration(scan_id).run_full_recon(target_url, depth)` per target
- Depth: "medium" for full scans, "quick" otherwise
- Discovered endpoints persisted to `Endpoint` table
- Recon data merged across targets via `_merge_recon_data()`

**Phase 1.5: Autonomous Discovery** (progress 20-40%)
- Triggered when total endpoints + URLs < 10
- `AutonomousScanner(scan_id, log_callback, timeout=15, max_depth=3).run_autonomous_scan(target_url, recon_data)`
- Saves both discovered endpoints and any vulnerabilities found during discovery
- Merges URLs, directories, and parameters into recon data

**Phase 2: AI Analysis** (progress 40-45%)
- Skippable via phase-skip signal (falls back to `_default_skip_plan()` with 16 common vuln types)
- Loads tradecraft TTP guidance from scan-associated or globally-enabled `Tradecraft` records
- Builds enhanced prompt: `GLOBAL_AUTHORIZATION` + tradecraft block + user request
- `AIPromptProcessor.process_prompt()` returns `TestingPlan` (vulnerability_types, testing_focus, custom_payloads, testing_depth, specific_endpoints, bypass_techniques, priority_order, ai_reasoning)

**Phase 3: AI Offensive Agent** (progress 45-90%)
- Skippable via phase-skip signal
- Per target: `AIPentestAgent(target, log_callback, auth_headers, max_depth=5).run()` -- AI-powered pen test agent that discovers and exploits vulnerabilities
- Then: `DynamicVulnerabilityEngine` tests every endpoint against every vuln type in the testing plan
- `_execute_payload_test()`: injects payloads into query parameters, checks response for vuln indicators (reflected payload for XSS, SQL error patterns for SQLi, file contents for LFI, etc.)
- `AIVulnerabilityAnalyzer.analyze_finding()` confirms findings with confidence >= 0.5
- Findings persisted to `Vulnerability` table with broadcast via WebSocket
- Uses shared `aiohttp.ClientSession` per endpoint (avoids creating 500+ connections per scan)

**Phase 4: Completed** (progress 100%)
- Final vuln count update from DB
- Duration calculated from `started_at` to `completed_at`
- `auto_generate_report(db, scan_id)` -- creates HTML report with executive summary
- Broadcasts scan completion via WebSocket

### Authentication Support
`_build_auth_headers(scan)` constructs headers from scan config:
- Cookie auth: `Cookie: <value>`
- Bearer token: `Authorization: Bearer <token>`
- Basic auth: `Authorization: Basic <base64(user:pass)>`
- Custom header: `<header_name>: <header_value>`
- Plus any `custom_headers` dict from scan config

### Tradecraft Integration
`_get_tradecraft_guidance(scan_id)` builds a text block from `Tradecraft` records:
1. First: scan-specific TTP associations (via `ScanTradecraft` join table)
2. Fallback: all globally-enabled TTPs
3. Formatted as `[CATEGORY] Name\nContent` blocks, injected into the AI prompt pipeline

## AutonomousAgent
File: `backend/core/autonomous_agent.py`

The AutonomousAgent is the AI-driven testing loop used by both the vuln-lab and CTF pipeline paths. It implements `__aenter__`/`__aexit__` for resource cleanup.

### Constructor
- `target`: Target URL
- `mode`: `OperationMode` enum (RECON_ONLY, FULL_AUTO, PROMPT_ONLY, ANALYZE_ONLY, AUTO_PENTEST)
- `log_callback`, `progress_callback`, `finding_callback`: async callbacks
- `auth_headers`: Authentication headers dict
- `custom_prompt`: Optional user prompt
- `lab_context`: Optional dict with vuln_type, challenge context
- `scan_id`: DB scan record ID
- `governance`: `GovernanceAgent` instance for scope enforcement
- `preset_recon`: Pre-populated recon data (used by CTF testing agents to skip recon phase)
- `focus_vuln_types`: Restrict testing to specific vuln types (used by CTF agent assignment)
- `agent_label`: Human-readable label (Alpha, Bravo, etc.)

### Component Stack (conditionally imported)
- `VulnerabilityRegistry` -- 100+ vuln type definitions with metadata, payloads, detection rules
- `PayloadGenerator` -- Generates test payloads per vuln type
- `ResponseVerifier` -- Analyzes HTTP responses for vulnerability indicators
- `NegativeControlEngine` -- Sends baseline requests to reduce false positives
- `ProofOfExecution` -- Evidence collection and screenshot capture for findings
- `ConfidenceScorer` -- Scores finding confidence based on multiple signals
- `ValidationJudge` -- Final pass/fail decision on findings
- `AccessControlLearner` -- Learns auth patterns during testing
- `RequestEngine` -- HTTP request execution with error classification
- `WAFDetector` -- Detects and adapts to Web Application Firewalls
- `StrategyAdapter` -- Adjusts testing strategy based on WAF detection and error patterns
- `ChainEngine` -- Multi-step exploit chain execution
- `AuthManager` -- Authentication token management and renewal
- `AgentMemory` -- Cross-scan learning (when `ENABLE_PERSISTENT_MEMORY`)
- `BrowserValidator` -- Playwright browser validation (when `ENABLE_BROWSER_VALIDATION`)
- `ReconIntegration` -- Endpoint and technology discovery
- `SandboxManager` / `MCPToolClient` -- Docker sandbox and MCP tool integration

### Execution Flow
1. Initialize all component engines
2. If `recon_enabled` (and no `preset_recon`): Run reconnaissance (endpoint discovery, technology detection, form/parameter mapping)
3. LLM analysis of attack surface (with optional knowledge augmentation via `KnowledgeAugmentor` when `ENABLE_KNOWLEDGE_AUGMENTATION`)
4. For each vulnerability type in the attack plan: generate payloads -> deliver via `RequestEngine` -> verify with `ResponseVerifier` -> negative control check -> confidence scoring via `ConfidenceScorer` -> `ValidationJudge` decision
5. If `ENABLE_BROWSER_VALIDATION`: validate high-confidence findings in Playwright browser
6. Persist findings to database via `finding_callback`
7. Return structured report dict with findings, recon data, and executive summary

### Resource Cleanup
`__aexit__` closes: BrowserValidator, SandboxManager containers, MCPToolClient session.

## Governance
`backend/core/governance.py` -- `GovernanceAgent` enforces scope boundaries via data-level validation.

### Scope Types
- `create_vuln_lab_scope(target, vuln_type)` -- scoped to single target URL + single vuln type
- `create_ctf_scope(target)` -- broader scope for CTF testing (all vuln types allowed for the target)

### Enforcement
- Validates all outbound HTTP requests against allowed target URLs (hostname + port matching)
- Restricts vuln types to those in scope
- Logs scope violations but does not crash the agent (warning-level governance)
- Vuln-type to Nuclei template tag mapping for tool-level scope enforcement

## Phase Tracking
Scan phases: `initializing` -> `recon` -> `analyzing` -> `testing` -> `completed`
- Phase stored in `scan.current_phase` column
- Progress (0-100 integer) stored in `scan.progress` column
- Updated via `progress_callback` -> persisted to DB + broadcast via WebSocket `broadcast_progress`
- Phase changes broadcast via `broadcast_phase_change`

### Phase Skip
- API sets `_scan_phase_control[scan_id] = target_phase`
- `ScanService._should_skip_phase(scan_id, current_phase)` pops the signal and validates forward-only skip
- When analysis is skipped: uses `_default_skip_plan()` with 16 common vuln types
- When testing is skipped (target = "completed"): sets `_stop_requested = True`

## Error Handling
- **Individual finding errors**: Logged at debug level, scan continues to next vuln type
- **Fatal errors**: Scan status set to "failed", `error_message` saved, `completed_at` set
- **Stop**: Partial results saved, auto-generates partial report via `auto_generate_report(db, scan_id, is_partial=True)`
- **CancelledError**: Caught in `run_scan_task`, updates scan to "stopped", calculates duration

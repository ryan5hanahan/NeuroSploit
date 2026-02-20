# System Architecture

## Overview
sploit.ai follows a layered architecture with clear separation between frontend, API, services, core modules, and external integrations.

## System Layers

```
+---------------------------------------------------+
|                   Frontend                         |
|        React/TypeScript SPA (Vite + Tailwind)      |
|        17 pages, WebSocket client, Axios API       |
+---------------------------------------------------+
|                   API Layer                         |
|         FastAPI (backend/main.py)                   |
|  16 routers: scans, vuln-lab, settings, reports,   |
|  agent, agent-tasks, scheduler, terminal,           |
|  sandbox, tradecraft, memory, traces,               |
|  targets, prompts, dashboard, vulnerabilities       |
|  WebSocket: /ws/scan/{scan_id}                      |
|  Health: /api/health                                |
+---------------------------------------------------+
|                Service Layer                        |
|  ScanService (run_scan_task)                        |
|  AutonomousAgent (AI-driven testing loop)           |
|  CTFCoordinator (multi-agent CTF pipeline)          |
|  GovernanceAgent (scope enforcement)                |
|  ReportService (auto_generate_report)               |
+---------------------------------------------------+
|                 Core Modules                        |
|  LLMManager (multi-provider LLM interface)          |
|  ModelRouter (task-type-based routing)               |
|  BrowserValidator (Playwright probes)               |
|  KnowledgeAugmentor (bug bounty RAG)               |
|  MCP Server (28 tools via MCP protocol)             |
|  SandboxManager (Docker container pool)             |
|  VulnerabilityRegistry (100+ vuln types)            |
|  RequestEngine, ResponseVerifier, WAFDetector       |
|  ChainEngine, StrategyAdapter, AuthManager          |
+---------------------------------------------------+
|               Data Layer                            |
|  SQLite via async SQLAlchemy (aiosqlite)            |
|  Models: Scan, Target, Endpoint, Vulnerability,     |
|  Report, AgentTask, VulnLabChallenge, Prompt,       |
|  Tradecraft, Memory, Trace, LlmTestResult           |
+---------------------------------------------------+
|            External Integrations                    |
|  LLM APIs: Anthropic, OpenAI, Google, Bedrock       |
|  Docker Engine (sandbox containers)                 |
|  Playwright/Chromium (browser validation)           |
|  Security Tools (nuclei, nmap, sqlmap, etc.)        |
|  mitmproxy (traffic interception)                   |
|  InteractSH (OOB detection)                         |
+---------------------------------------------------+
```

## Data Flow -- Scan Execution
1. Client creates scan via `POST /api/v1/scans` with target URLs, auth config, and optional prompt. Scan record persisted to DB in "pending" status.
2. Client starts scan via `POST /api/v1/scans/{id}/start`. The scans router registers the scan in `scan_registry` (returns a `ScanHandle` with cancellation event), then spawns `asyncio.create_task(run_scan_task(scan_id))` and stores the task reference on the handle.
3. `run_scan_task` creates its own `async_session_factory()` DB session and instantiates `ScanService`, which orchestrates phases: initializing (tool check) -> recon (endpoint discovery via `ReconIntegration`, plus `AutonomousScanner` if recon finds < 10 endpoints) -> analyzing (AI prompt processing to produce a `TestingPlan`) -> testing (`AutonomousAgent` in AUTO_PENTEST mode + `DynamicVulnerabilityEngine` payload delivery per endpoint per vuln type) -> completed (auto-generate HTML report via `ReportService`).
4. Real-time updates pushed via WebSocket manager (`broadcast_log`, `broadcast_progress`, `broadcast_phase_change`, `broadcast_vulnerability_found`, `broadcast_scan_completed`, `broadcast_scan_stopped`).
5. Findings persisted to `Vulnerability` table with CVSS, CWE, PoC payload/request/response, AI analysis, and remediation.
6. Report record created with executive summary. Partial report auto-generated on stop.

## Data Flow -- CTF Pipeline
1. Client calls `POST /api/v1/vuln-lab/run` with `ctf_mode: true`, `ctf_agent_count`, `ctf_flag_patterns`, and optional `ctf_submit_url`/`ctf_platform_token`. Creates `VulnLabChallenge` + `Scan` records.
2. If `ctf_agent_count > 1`: `CTFCoordinator` orchestrates a multi-phase pipeline:
   - Phase 1 (5-15%): Recon via single `AutonomousAgent` in `RECON_ONLY` mode
   - Phase 1.5 (15-30%): Quick wins -- 10 parallel generic exploit probes (SQLi login, default creds, admin panels, sensitive files, XSS, IDOR, open redirect, path traversal, API disclosure, registration abuse)
   - Phase 1.55 (30-40%): Credential harvesting -- extract JWT tokens from successful logins, then authenticated probes (IDOR, admin endpoints, API manipulation, parameter boundary values)
   - Phase 1.6 (40-55%): Browser probes -- DOM XSS (dialog-detected validation), hidden pages (Jaccard similarity vs homepage baseline), client-side storage inspection
   - Phase 2 (55-65%): LLM analysis -- prioritize vuln types, round-robin distribute across testing agents
   - Phase 3 (65-90%): Parallel testing -- N-1 `AutonomousAgent` instances via `asyncio.gather`, each assigned specific vuln types
   - Phase 3.5 (93%): Flag submission -- `CTFFlagSubmitter` auto-submits captured flags
   - Phase 4 (95-100%): Aggregation -- merge + deduplicate findings by (vuln_type, normalized_endpoint, parameter)
3. If `ctf_agent_count <= 1`: single `AutonomousAgent` runs in `FULL_AUTO` mode.
4. Findings flow through `finding_callback` into in-memory `_all_findings` list + DB persistence via the callback chain.
5. `CTFFlagDetector.scan_response()` called on every HTTP response body and headers; `CTFFlagDetector.scan_text()` called on every log message.
6. Captured flags optionally auto-submitted to CTF platform API via `CTFFlagSubmitter`.

## Key Design Decisions
- **Async everywhere**: FastAPI with async SQLAlchemy (aiosqlite), aiohttp for HTTP requests, asyncio for task orchestration. All agent/scan operations are async coroutines.
- **In-memory + DB hybrid**: Real-time state tracked in module-level dicts (`agent_results`, `lab_results`, `_scan_phase_control`, `scan_registry._registry`). Persistent state in SQLite via `async_session_factory()`.
- **Two agent paths**: `BaseAgent` (CLI, synchronous, config-driven, in `agents/base_agent.py`) vs `AutonomousAgent` (web UI, async, AI-driven, in `backend/core/autonomous_agent.py`). Both support optional feature toggles but have independent implementations.
- **Feature toggles via env vars**: All optional features gated by `ENABLE_X` environment variables (e.g., `ENABLE_MODEL_ROUTING`, `ENABLE_BROWSER_VALIDATION`, `ENABLE_KNOWLEDGE_AUGMENTATION`, `ENABLE_PERSISTENT_MEMORY`, `ENABLE_EXTENDED_THINKING`). Settings API persists to in-memory dict + `os.environ` + `.env` file.
- **Config.json for static config**: LLM profiles, agent roles, sandbox settings, model routing configuration, opsec profiles. Settings API provides runtime overrides.
- **Cooperative cancellation**: `scan_registry` provides a `ScanHandle` with `cancel_event` (asyncio.Event). Both `ScanService` and `AutonomousAgent` check `is_cancelled()` between phases. Child processes tracked by PID for SIGTERM/SIGKILL.
- **Governance enforcement**: `GovernanceAgent` validates all requests against scope (target URL, allowed vuln types, allowed HTTP methods) before execution. Scoped differently for vuln-lab (single target + single vuln type) vs CTF (broad scope for single target).

## Directory Structure
```
/
+-- backend/
|   +-- main.py              # FastAPI app, lifespan, routers, WebSocket, health
|   +-- config.py            # Pydantic Settings class (BaseSettings)
|   +-- api/v1/              # 16 API routers
|   +-- api/websocket.py     # WebSocket connection manager
|   +-- core/                # AutonomousAgent, CTFCoordinator, GovernanceAgent, etc.
|   +-- models/              # SQLAlchemy models (Scan, Target, Endpoint, Vulnerability, etc.)
|   +-- schemas/             # Pydantic request/response schemas
|   +-- services/            # ScanService, ReportService
|   +-- db/                  # Database init (init_db, close_db, async_session_factory)
+-- core/                    # Shared core: LLMManager, ModelRouter, BrowserValidator, MCP server
+-- agents/                  # CLI agents (BaseAgent) -- not in Docker containers
+-- frontend/src/            # React app (17 pages, Vite + Tailwind)
+-- config/                  # config.json, opsec_profiles.json
+-- docker/                  # Dockerfiles (backend full, backend lite, frontend)
+-- models/bug-bounty/       # Bug bounty finetuning dataset (1826 entries, 2.9MB)
+-- prompts/                 # Prompt library (library.json + md_library/ markdown files)
+-- docs/                    # Documentation (PRD, tech specs, requirements)
```

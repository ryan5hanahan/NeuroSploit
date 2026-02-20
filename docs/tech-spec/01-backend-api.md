# Backend API

## Overview
FastAPI application serving REST API and WebSocket endpoints. 16 routers mounted under `/api/v1/`. Docs at `/api/docs` (Swagger), `/api/redoc`, and `/api/openapi.json`.

## Application Setup
- **Entry point**: `backend/main.py`
- **Configuration**: `backend/config.py` -- Pydantic `BaseSettings` class, reads from env vars and `.env` file
- **Database**: SQLite via aiosqlite, URL default `sqlite+aiosqlite:///./data/sploitai.db`
- **Lifespan handler** (`@asynccontextmanager`):
  1. `init_db()` -- create tables via async SQLAlchemy
  2. `seed_builtin_tradecraft(db)` -- populate built-in TTP library
  3. `ScanScheduler(config).start()` -- initialize scheduled scan support
  4. `get_pool().cleanup_orphans()` -- destroy leftover Docker sandbox containers from previous crashes
  5. On shutdown: `cleanup_all()` sandbox containers, stop scheduler, `close_db()`
- **CORS**: Origins `http://localhost:3000`, `http://127.0.0.1:3000` (hardcoded in Settings class)
- **Static files**: Serves `frontend/dist/` in production via `StaticFiles` mount + catch-all route returning `index.html` for SPA routing

## API Routers

### Scans (`/api/v1/scans`)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List scans (paginated: `page`, `per_page`, `status` filter) |
| POST | `/` | Create scan (`ScanCreate` schema). Applies `default_scan_type` and `recon_enabled_by_default` settings when client omits values. |
| GET | `/compare/{scan_id_a}/{scan_id_b}` | Compare two scans. Returns structured diff: vuln diff (new/resolved/persistent/changed) + endpoint diff (new/removed/changed/stable). |
| GET | `/{scan_id}` | Get scan details with targets |
| POST | `/{scan_id}/start` | Start scan. Enforces `MAX_CONCURRENT_SCANS` (HTTP 429 if exceeded). Registers in `scan_registry`, spawns `asyncio.create_task(run_scan_task(scan_id))`. |
| POST | `/{scan_id}/stop` | Stop scan. Cancels via registry + signals agent directly. Computes final vuln counts from DB. Broadcasts stop via WebSocket. Auto-generates partial report. |
| POST | `/{scan_id}/pause` | Pause running scan. Signals agent to pause, sets status to "paused". |
| POST | `/{scan_id}/resume` | Resume paused scan. Signals agent to resume, sets status to "running". |
| POST | `/{scan_id}/skip-to/{target_phase}` | Skip to phase (forward only). Valid phases: `recon`, `analyzing`, `testing`, `completed`. Auto-resumes if paused. Validates forward-only skip. Signals via `_scan_phase_control` dict. |
| POST | `/{scan_id}/repeat` | Clone scan config + targets + tradecraft associations. Auto-starts the new scan. Enforces `MAX_CONCURRENT_SCANS`. Only works on completed/stopped/failed scans. |
| DELETE | `/{scan_id}` | Delete scan. Blocked while status is "running". |
| GET | `/{scan_id}/status` | Get scan progress (`ScanProgress` schema: scan_id, status, progress, current_phase, total_endpoints, total_vulnerabilities) |
| GET | `/{scan_id}/endpoints` | Get discovered endpoints (paginated: `page`, `per_page`) |
| GET | `/{scan_id}/vulnerabilities` | Get findings (paginated: `page`, `per_page`, `severity` filter) |
| PATCH | `/vulnerabilities/{vuln_id}/validate` | Validate or reject a finding. Valid statuses: `validated`, `false_positive`, `ai_confirmed`, `ai_rejected`, `pending_review`. Adjusts scan severity counts when changing between confirmed and rejected states. |

### Vulnerability Lab (`/api/v1/vuln-lab`)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/types` | List vulnerability types by category (from `VulnerabilityRegistry`) |
| POST | `/run` | Launch isolated vuln test or CTF pipeline. Routes to `CTFCoordinator` when `ctf_mode=true` and `ctf_agent_count > 1`, otherwise single `AutonomousAgent` in `FULL_AUTO`. |
| GET | `/challenges` | List challenges (filter by `type`, `category`, `status`, `result`) |
| GET | `/challenges/{id}` | Get challenge details. Checks in-memory `lab_results` first, falls back to DB. |
| POST | `/challenges/{id}/stop` | Stop running challenge. Cancels agent/coordinator, updates status. |
| DELETE | `/challenges/{id}` | Delete challenge record |
| GET | `/logs/{id}` | Get challenge logs (from in-memory `lab_results` buffer, max 200 entries) |
| GET | `/stats` | Aggregated lab statistics (total, by status, by result, by category) |

### Settings (`/api/v1/settings`)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Get current settings. API keys masked to `has_X_key` booleans. Never exposes raw secrets. |
| PUT | `/` | Update settings. Persists to in-memory `_settings` dict + `os.environ` + `.env` file. Handles all feature toggles and API keys. |
| POST | `/test-llm` | Test LLM connection by sending a test prompt |
| POST | `/clear-database` | Clear all data from all tables |
| GET | `/stats` | Database record counts per table |
| GET | `/tools` | Check installed security tools (nuclei, nmap, sqlmap, etc.) |

### Other Routers
| Router | Prefix | Description |
|--------|--------|-------------|
| targets | `/api/v1/targets` | Target management (CRUD, import) |
| prompts | `/api/v1/prompts` | Prompt library CRUD + built-in preset prompts |
| reports | `/api/v1/reports` | Report listing, download (HTML), auto-generation |
| dashboard | `/api/v1/dashboard` | Dashboard aggregations (scan stats, vuln breakdown, recent activity) |
| vulnerabilities | `/api/v1/vulnerabilities` | Vulnerability management across all scans |
| agent | `/api/v1/agent` | Agent status and control (start, stop, results tracking via `agent_instances`, `agent_results`, `scan_to_agent` dicts) |
| agent-tasks | `/api/v1/agent-tasks` | Agent task tracking (per-scan task list with timing) |
| scheduler | `/api/v1/scheduler` | Scan scheduling (cron-based via `ScanScheduler`) |
| terminal | `/api/v1/terminal` | Terminal agent interface (interactive prompt-response) |
| sandbox | `/api/v1/sandbox` | Sandbox container management (Docker pool lifecycle) |
| tradecraft | `/api/v1/tradecraft` | Tradecraft TTP library (built-in + custom, per-scan association) |
| memory | `/api/v1/memory` | Persistent agent memory (cross-scan learning when `ENABLE_PERSISTENT_MEMORY`) |
| traces | `/api/v1/traces` | Execution traces (when `ENABLE_TRACING`) |

## WebSocket
- **Endpoint**: `/ws/scan/{scan_id}`
- **Protocol**: Text frames (JSON messages)
- **Client commands**: `"ping"` -> `"pong"` response
- **Server broadcasts** (via `ws_manager`):
  - `broadcast_scan_started` -- scan initialized
  - `broadcast_progress` -- progress percentage + message
  - `broadcast_phase_change` -- phase transitions (recon, analyzing, testing, completed, stopped)
  - `broadcast_log` -- structured logs with level (info, warning, error, debug)
  - `broadcast_vulnerability_found` -- new finding with id, title, severity, type, endpoint
  - `broadcast_stats_update` -- real-time severity count updates
  - `broadcast_scan_completed` -- final summary
  - `broadcast_scan_stopped` -- partial results summary
  - `broadcast_agent_task_started` / `broadcast_agent_task_completed` -- task lifecycle events
  - `broadcast_error` -- error messages
- **Connection lifecycle**: `ws_manager.connect(websocket, scan_id)` on open, `ws_manager.disconnect(websocket, scan_id)` on `WebSocketDisconnect`

## Key Schemas
- **ScanCreate**: `targets` (list[str], required), `scan_type` (Optional[str] -- defaults to settings `default_scan_type`), `recon_enabled` (Optional[bool] -- defaults to settings `recon_enabled_by_default`), `custom_prompt`, `auth` (nested: auth_type, cookie, bearer_token, username, password, header_name, header_value), `custom_headers` (dict), `tradecraft_ids` (list[str]), `prompt_id`, `name`, `config`
- **ScanResponse**: Full scan state including targets, progress, severity counts (critical_count, high_count, medium_count, low_count, info_count), total_endpoints, total_vulnerabilities, duration, current_phase
- **ScanProgress**: scan_id, status, progress (0-100), current_phase, total_endpoints, total_vulnerabilities
- **VulnLabRunRequest**: `target_url`, `vuln_type`, `challenge_name`, auth config, `ctf_mode`, `ctf_flag_patterns` (list[str]), `ctf_agent_count`, `ctf_submit_url`, `ctf_platform_token`
- **SettingsUpdate**: All settings fields (optional). API keys accepted as raw strings. Feature toggles as booleans.
- **SettingsResponse**: Current state with `has_anthropic_key`, `has_openai_key`, etc. booleans -- never exposes raw API key values.

## Health Check
- **Endpoint**: `GET /api/health`
- Checks LLM availability by probing `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and AWS Bedrock (via `boto3.client('sts').get_caller_identity()`)
- Returns: `{"status": "healthy", "app": "...", "version": "...", "llm": {"status": "configured"|"not_configured", "provider": "..."|null, "message": "..."}}`

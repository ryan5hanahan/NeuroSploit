# Integration Requirements

## LLM Provider APIs

| Provider | Protocol | Auth Env Var(s) | Default Model | Notes |
|----------|----------|-----------------|---------------|-------|
| Anthropic (Claude) | HTTPS (Anthropic SDK) | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5-20250929` | Default provider; supported in both BaseAgent (via LLMManager) and AutonomousAgent (direct SDK) |
| OpenAI (GPT) | HTTPS (OpenAI SDK) | `OPENAI_API_KEY` | `gpt-4-turbo-preview` | OpenAI-compatible API format |
| Google (Gemini) | HTTPS (Google GenAI HTTP API) | `GEMINI_API_KEY` | `gemini-pro` | Default profile in config.json; uses `generativelanguage.googleapis.com/v1beta` |
| AWS Bedrock | HTTPS (boto3 `bedrock-runtime`) | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` or `AWS_PROFILE` | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | Region via `AWS_BEDROCK_REGION` (default `us-east-1`); supports extended thinking with `thinking_budget_tokens` |
| Ollama | HTTP (localhost:11434) | None | `llama3.2` | Local deployment only; URL configurable via `OLLAMA_URL` env var |
| OpenRouter | HTTPS (OpenAI-compatible) | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4-5-20250929` | Multi-model gateway using OpenAI SDK format |

### Provider Selection

AutonomousAgent's `LLMClient._initialize_provider()` tries providers in order:
1. `DEFAULT_LLM_PROVIDER` (user preference from settings) first
2. Fallback order: `claude -> openai -> gemini -> bedrock -> ollama -> lmstudio`

Each provider requires a valid API key (non-empty, non-placeholder). First successful initialization wins.

### Global Model Override

`DEFAULT_LLM_MODEL` env var overrides per-provider model defaults. Applies to all providers when set.

`MAX_OUTPUT_TOKENS` env var controls max tokens per request (default: 4096).

### Error Handling

| HTTP Status / Error | User-Facing Message |
|---------------------|-------------------|
| 401 | "Authentication failed" |
| 403 | "Access denied" |
| Timeout | "Connection timed out" |
| Connection refused | "Is the provider endpoint reachable?" |

Retry policy: 3 attempts with exponential backoff (1s, 2s, 4s).

### Model Routing (Optional)

When `ENABLE_MODEL_ROUTING` is enabled, `core/model_router.py` routes LLM calls by task type:
- `reasoning` -> bedrock_claude profile
- `analysis`, `generation`, `validation` -> gemini profile

BaseAgent's LLMManager uses `task_type` parameter in `generate()` calls. Child LLMManagers use `_routing_disabled=True` to prevent recursion.

## Docker Engine

- **Required for**: sandbox containers, mitmproxy, interactsh
- **Docker socket mount**: `/var/run/docker.sock:/var/run/docker.sock` in docker-compose.yml
- **Python SDK**: `docker` package (guarded import -- sandbox features disabled when unavailable)
- **Container images**:
  - `neurosploit-kali:latest` -- Sandbox container with security tools
  - `mitmproxy/mitmproxy:latest` -- OPSEC proxy
  - `projectdiscovery/interactsh-server:latest` -- OOB interaction detection
- **Container pool**: max 5 concurrent sandbox containers, auto-cleanup orphans on startup
- **Resource limits**: 2G memory, 2.0 CPU per sandbox container
- **Container TTL**: 60 minutes (auto-cleanup)

## Playwright / Chromium

- **Required for**: browser validation, screenshot capture, DOM XSS testing (both CTF browser probes and scan-time validation)
- **Package**: `playwright >= 1.40.0`
- **Browser**: Chromium (headless)
- **Installation**:
  ```bash
  pip install playwright
  python -m playwright install chromium        # lite Dockerfile
  python -m playwright install --with-deps chromium  # full Dockerfile (includes system deps)
  ```
- **Both Dockerfiles** include Playwright + Chromium
- **Guard**: `HAS_PLAYWRIGHT` import flag -- browser validation silently disabled when unavailable
- **Usage**:
  - `core/browser_validator.py` -- `BrowserValidator` class and `validate_finding_sync()` helper
  - `backend/core/autonomous_agent.py` -- screenshot capture during scan
  - `backend/core/ctf_coordinator.py` -- DOM XSS probes and hidden page discovery
  - `core/mcp_server.py` -- `screenshot_capture` MCP tool

## MCP Protocol

- **Package**: `mcp >= 1.0.0`
- **Transport**: stdio (default) or SSE (via `MCP_TRANSPORT=sse` env var)
- **Server**: `core/mcp_server.py`
- **Client**: `core/mcp_client.py`
- **No authentication** on MCP connections

### Registered Tools (28 total)

**Core (8 tools)**:
| Tool | Purpose |
|------|---------|
| `screenshot_capture` | Playwright screenshot of URL |
| `payload_delivery` | Deliver test payload to target |
| `dns_lookup` | DNS record resolution |
| `port_scan` | Port scanning |
| `technology_detect` | Technology fingerprinting |
| `subdomain_enumerate` | Subdomain discovery |
| `save_finding` | Persist a vulnerability finding |
| `get_vuln_prompt` | Get AI prompt for a vulnerability type |

**Sandbox (4 tools)**:
| Tool | Purpose |
|------|---------|
| `execute_nuclei` | Run Nuclei vulnerability scanner |
| `execute_naabu` | Run Naabu port scanner |
| `sandbox_health` | Check sandbox container health |
| `sandbox_exec` | Execute arbitrary command in sandbox |

**ProjectDiscovery Extended (9 tools)**:
| Tool | Purpose |
|------|---------|
| `execute_cvemap` | CVE database mapping |
| `execute_tlsx` | TLS certificate analysis |
| `execute_asnmap` | ASN mapping |
| `execute_mapcidr` | CIDR range manipulation |
| `execute_alterx` | Subdomain permutation |
| `execute_shuffledns` | Mass DNS resolution |
| `execute_cloudlist` | Cloud asset discovery |
| `execute_interactsh` | OOB interaction detection |
| `execute_notify` | Notification delivery |

**Proxy (7 tools)**:
| Tool | Purpose |
|------|---------|
| `proxy_status` | mitmproxy health/status |
| `proxy_flows` | List captured HTTP flows |
| `proxy_capture` | Start/stop traffic capture |
| `proxy_replay` | Replay captured requests |
| `proxy_intercept` | Set intercept rules |
| `proxy_clear` | Clear captured flows |
| `proxy_export` | Export flows to file |

## SQLite / SQLAlchemy

- **Driver**: `aiosqlite` (async SQLite adapter)
- **ORM**: SQLAlchemy 2.0 with `async_sessionmaker` and `AsyncSession`
- **Database file**: `data/neurosploit.db` (mounted via Docker volume `neurosploit-data:/app/data`)
- **Connection string**: `sqlite+aiosqlite:///./data/neurosploit.db`
- **Session config**: `expire_on_commit=False`
- **Schema management**: 13 model files defining tables, runtime `ALTER TABLE ADD COLUMN` migrations
- **No migration framework** (no Alembic) -- purely additive column additions via `PRAGMA table_info` checks

## OSINT APIs (Optional)

| Service | Env Var(s) | Purpose |
|---------|-----------|---------|
| Shodan | `SHODAN_API_KEY` | Internet device search, port/service enumeration |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Certificate and host search |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Malware analysis, URL reputation |
| BuiltWith | `BUILTWITH_API_KEY` | Technology profiling |
| HackerOne | `HACKERONE_API_TOKEN` + `HACKERONE_USERNAME` | Bug bounty program integration |

All OSINT keys are optional. Configured via Settings UI and persisted to `.env`.

## Security Tools

### Go Tools (Built in Dockerfile Stage 1)

| Tool | Source | Purpose |
|------|--------|---------|
| subfinder | ProjectDiscovery | Subdomain enumeration |
| httpx | ProjectDiscovery | HTTP probing and technology detection |
| nuclei | ProjectDiscovery | Template-based vulnerability scanning |
| katana | ProjectDiscovery | Web crawling |
| dnsx | ProjectDiscovery | DNS resolution and brute-force |
| naabu | ProjectDiscovery | Port scanning |
| waybackurls | tomnomnom | Wayback Machine URL extraction |
| ffuf | ffuf | Fuzzing (directory, parameter) |
| gau | lc | GetAllURLs from multiple sources |
| gf | tomnomnom | Grep patterns for URLs |
| qsreplace | tomnomnom | Query string parameter replacement |
| dalfox | hahwul | XSS scanner |
| gobuster | OJ | Directory/DNS brute-force |
| gospider | jaeles | Web spider |
| anew | tomnomnom | Append unique lines to files |
| hakrawler | hakluke | Web crawler (optional, build may fail) |

### System Tools (Installed in Dockerfile Stage 3)

| Tool | Purpose |
|------|---------|
| nmap | Port scanning, service detection |
| sqlmap | SQL injection detection and exploitation |
| curl | HTTP requests |
| wget | HTTP downloads |
| dig (dnsutils) | DNS lookups |
| whois | Domain registration lookup |
| git | Repository operations |
| jq | JSON processing |

### Python Tools (pip installed)

| Tool | Purpose |
|------|---------|
| arjun | Hidden HTTP parameter discovery |
| wafw00f | WAF detection and fingerprinting |
| playwright | Browser automation (Chromium) |

### Lite Dockerfile

`Dockerfile.backend.lite` excludes all Go tools and system security tools. Only includes Python dependencies and Playwright/Chromium. Suitable for development when recon tools are not needed.

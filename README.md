# sploit.ai v3

![sploit.ai](https://img.shields.io/badge/sploit.ai-AI--Powered%20Pentesting-blueviolet)
![Version](https://img.shields.io/badge/Version-3.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![React](https://img.shields.io/badge/React-18-61dafb)
![Vuln Types](https://img.shields.io/badge/Vuln%20Types-100+%20(119%20w%2F%20PATT)-red)
![LLM Agent](https://img.shields.io/badge/LLM%20Agent-18%20Tools-purple)
![Payloads](https://img.shields.io/badge/Payloads-34K+-orange)
![Docker](https://img.shields.io/badge/Docker-Kali%20Sandbox-informational)

**AI-Powered Autonomous Penetration Testing Platform**

sploit.ai v3 is a security assessment platform built around a single LLM-driven autonomous agent with 18 tools and a KNOW/THINK/TEST/VALIDATE cognitive framework. The agent operates inside per-scan isolated Kali Linux containers, governed by 2-layer scope and phase-action enforcement (6 profiles, 3 modes). It supports 3-tier LLM model routing across 6 providers, 100+ vulnerability types with 34,000+ payloads, 14 OSINT API clients, swarm sub-agents for parallel recon, runtime dynamic tool creation, anti-hallucination validation, exploit chaining, and a 21-page React dashboard with WebSocket real-time updates.

---

## Highlights

- **100 vulnerability types** (+ 19 PATT-conditional, totaling 119) across **12 tester categories**
- **34,000+ payloads** — 665 curated + 33,500 from PayloadsAllTheThings, merged at all scan depths
- **18-tool LLM-driven agent** with KNOW/THINK/TEST/VALIDATE cognitive cycle
- **Swarm sub-agents** (`spawn_subagent`) for parallel FAST-tier recon (max 3 concurrent, 120s timeout)
- **Runtime dynamic tool creation** (`create_tool`) with AST validation and blocked module enforcement
- **3-tier LLM routing** (fast/balanced/deep) across **6 providers** with per-tier cost tracking
- **2-layer governance** — scope enforcement + phase-action gating, **6 profiles**, **3 modes** (strict/warn/off)
- **14 OSINT API clients** — Shodan, Censys, VirusTotal, SecurityTrails, BuiltWith, NVD, ExploitDB, ZoomEye, FOFA, PublicWWW, GitHub Dork, GrayhatWarfare, HIBP, DeHashed
- **Per-scan isolated Kali containers** — 38 pre-installed + 28 on-demand tools, 60-min TTL, auto-cleanup
- **Opsec profiles** — stealth/balanced/aggressive controlling rate limits, jitter, proxy routing, DNS-over-HTTPS
- **TF-IDF vector memory** — per-target cross-engagement persistence, 6 categories, no external dependencies
- **Exploit chain engine** — 10 rules, max depth 3 (SSRF→internal, SQLi→DB-specific, LFI→config, etc.)
- **Anti-hallucination pipeline** — negative controls, proof-of-execution, confidence scoring, validation judge
- **Bug bounty program support** — BUG_BOUNTY scope profile, submission tracking, agent prompt injection
- **21-page React dashboard** with WebSocket real-time updates
- **34+ MCP tools** — scanning, reconnaissance, proxy control, ProjectDiscovery suite
- **mitmproxy + interactsh OOB** — opt-in traffic interception and out-of-band testing

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [LLM-Driven Agent](#llm-driven-agent)
- [Governance](#governance)
- [Opsec Profiles](#opsec-profiles)
- [OSINT Integration](#osint-integration)
- [MCP Server & Tools](#mcp-server--tools)
- [Prompt & Task Library](#prompt--task-library)
- [Vulnerability Engine](#vulnerability-engine)
- [PayloadsAllTheThings Integration](#payloadsallthethings-integration)
- [Kali Sandbox System](#kali-sandbox-system)
- [Anti-Hallucination & Validation](#anti-hallucination--validation)
- [Unified LLM Layer](#unified-llm-layer)
- [mitmproxy Integration](#mitmproxy-integration)
- [interactsh OOB Server](#interactsh-oob-server)
- [Vulnerability Enrichment](#vulnerability-enrichment)
- [Tradecraft Library](#tradecraft-library)
- [Bug Bounty Support](#bug-bounty-support)
- [Web GUI](#web-gui)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Development](#development)
- [Security Notice](#security-notice)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository with submodules
git clone --recurse-submodules https://github.com/your-org/sploit.ai.git
cd sploit.ai

# If already cloned without submodules, initialize PATT payload library
git submodule update --init

# Copy environment file and add your API keys
cp .env.example .env
nano .env  # Add an LLM API key or configure AWS Bedrock credentials

# Start all services
docker compose up -d
```

Access the web interface at **http://localhost:8080** (Docker) or **http://localhost:5173** (dev mode).

### Option 2: Manual Setup

```bash
# Initialize PATT submodule (optional but recommended for 33K+ extra payloads)
git submodule update --init

# Backend
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev   # Dev server at http://localhost:5173
```

### Build Kali Sandbox Image

```bash
# Normal build (uses Docker cache)
./scripts/build-kali.sh

# Full rebuild (no cache)
./scripts/build-kali.sh --fresh

# Build + run health check
./scripts/build-kali.sh --test

# Or via docker-compose
docker compose -f docker/docker-compose.kali.yml build
```

### Optional Services

```bash
# Start mitmproxy for HTTP/HTTPS traffic interception
docker compose --profile proxy up -d

# Start self-hosted interactsh server for OOB testing
docker compose --profile oob up -d

# Start both
docker compose --profile proxy --profile oob up -d
```

---

## Architecture

```
sploit.ai/
├── backend/                             # FastAPI Backend
│   ├── api/v1/                          # REST API (21 routers)
│   │   ├── agent_v2.py                  # LLM-Driven Agent (start/stop/status/findings/ws)
│   │   ├── agent_tasks.py               # Scan task tracking
│   │   ├── bugbounty.py                 # Bug bounty submission tracking
│   │   ├── dashboard.py                 # Stats + activity feed
│   │   ├── enrichment.py                # NVD/ExploitDB vulnerability enrichment
│   │   ├── governance.py                # Governance scope violations + stats
│   │   ├── memory.py                    # Agent memory management
│   │   ├── prompts.py                   # Preset prompts
│   │   ├── realtime.py                  # Realtime interactive sessions
│   │   ├── reports.py                   # Report generation (HTML/PDF/JSON)
│   │   ├── sandbox.py                   # Sandbox container monitoring
│   │   ├── scans.py                     # Scan CRUD + pause/resume/stop
│   │   ├── scheduler.py                 # Cron/interval scheduling
│   │   ├── settings.py                  # Runtime settings + per-tier model config
│   │   ├── targets.py                   # Target validation
│   │   ├── task_library.py              # Task library CRUD
│   │   ├── terminal.py                  # Terminal agent (10 endpoints)
│   │   ├── traces.py                    # LLM call tracing
│   │   ├── tradecraft.py                # TTP tradecraft library (35 entries)
│   │   ├── vulnerabilities.py           # Vulnerability management
│   │   └── vuln_lab.py                  # Per-type vulnerability lab
│   ├── core/
│   │   ├── llm_agent.py                 # LLMDrivenAgent — the sole autonomous agent
│   │   ├── llm_agent_tools.py           # 18 tool schemas (MCP format)
│   │   ├── governance.py                # Layer 1: Scope enforcement (6 profiles)
│   │   ├── governance_gate.py           # Layer 2: Phase-action gating (7 categories × 9 phases)
│   │   ├── governance_facade.py         # Unified governance interface
│   │   ├── llm/                         # Unified LLM layer
│   │   │   ├── client.py                # UnifiedLLMClient (generate, generate_json, generate_with_tools)
│   │   │   ├── router.py                # 3-tier ModelRouter (fast/balanced/deep)
│   │   │   ├── providers/               # 6 providers (anthropic, openai, gemini, bedrock, ollama, lmstudio)
│   │   │   ├── tool_executor.py         # Tool dispatch with governance + payload/vuln-info handlers
│   │   │   ├── cost_tracker.py          # Per-tier token/cost tracking with budget enforcement
│   │   │   ├── prompt_composer.py       # Tier-aware system prompt composition
│   │   │   ├── tool_adapter.py          # MCP-to-provider tool format conversion
│   │   │   ├── conversation.py          # Multi-turn message history
│   │   │   └── meta_tools.py            # 7 structured decision schemas
│   │   ├── tools/                       # 6 LLM agent tool implementations
│   │   │   ├── shell_tool.py            # Docker sandbox shell execution
│   │   │   ├── browser_tool.py          # Playwright browser automation
│   │   │   ├── http_tool.py             # HTTP request handler
│   │   │   ├── parallel_executor.py     # Parallel tool execution (asyncio.gather)
│   │   │   ├── dynamic_tool.py          # Runtime tool creation with AST validation
│   │   │   └── swarm_tool.py            # Sub-agent spawning (FAST-tier swarm)
│   │   ├── osint/                       # 14 OSINT API clients
│   │   │   ├── shodan_client.py         # Shodan host/port/vuln search
│   │   │   ├── censys_client.py         # Censys hosts, certificates, search
│   │   │   ├── virustotal_client.py     # VirusTotal URL/domain scan
│   │   │   ├── securitytrails.py        # SecurityTrails subdomains, DNS history
│   │   │   ├── builtwith_client.py      # BuiltWith technology profiling
│   │   │   ├── nvd_client.py            # NVD CVE data
│   │   │   ├── exploitdb_client.py      # ExploitDB known exploits
│   │   │   ├── zoomeye.py               # ZoomEye port/banner search
│   │   │   ├── fofa.py                  # FOFA open port/service search
│   │   │   ├── publicwww.py             # PublicWWW code search
│   │   │   ├── github_dork.py           # GitHub code leak detection
│   │   │   ├── grayhat_warfare.py       # GrayhatWarfare exposed buckets
│   │   │   ├── hibp.py                  # Have I Been Pwned breach data
│   │   │   ├── dehashed.py              # DeHashed credential breach search
│   │   │   ├── base.py                  # Base client class
│   │   │   └── aggregator.py            # Parallel multi-source queries
│   │   ├── memory/                      # Persistent memory system
│   │   │   ├── vector_memory.py         # TF-IDF semantic search, per-target persistence
│   │   │   └── plan_manager.py          # Plan lifecycle with checkpoints
│   │   ├── prompts/                     # Cognitive prompt framework
│   │   │   ├── agent_system_prompt.md   # KNOW/THINK/TEST/VALIDATE cognitive framework
│   │   │   ├── execution_prompt_general.md  # Web pentest execution guidance
│   │   │   ├── execution_prompt_recon.md    # Recon-specific execution guidance
│   │   │   └── prompt_composer.py       # Dynamic prompt assembly with plan/memory injection
│   │   ├── observability/               # Operation metrics
│   │   │   ├── operation_tracker.py     # Token/cost/tool metrics tracking
│   │   │   └── quality_evaluator.py     # Post-op quality scoring (5 dimensions)
│   │   ├── vuln_engine/                 # Vulnerability engine
│   │   │   ├── registry.py              # 100 VULNERABILITY_INFO entries (+ 19 PATT)
│   │   │   ├── payload_generator.py     # 34K+ payloads (665 curated + PATT merge)
│   │   │   ├── injection_context.py     # DB type detection from error signatures
│   │   │   ├── ai_prompts.py            # Per-vuln AI decision prompts
│   │   │   ├── system_prompts.py        # 17 composable prompts, 8 task contexts
│   │   │   ├── patt/                    # PayloadsAllTheThings integration
│   │   │   │   ├── category_map.py      # 61 PATT category mappings
│   │   │   │   ├── parser.py            # Intruder wordlist + markdown parsers
│   │   │   │   ├── loader.py            # PATTLoader with lazy loading + caching
│   │   │   │   └── cli.py              # PATT CLI (status/parse/dump/update)
│   │   │   └── testers/                 # 12 category tester modules
│   │   │       ├── injection.py         # SQLi, NoSQLi, LDAP, XPath, command injection
│   │   │       ├── advanced_injection.py # SSTI, CRLF, header, log, GraphQL injection
│   │   │       ├── auth.py              # Auth bypass, session fixation, credential stuffing
│   │   │       ├── authorization.py     # BOLA, BFLA, IDOR, privilege escalation
│   │   │       ├── client_side.py       # XSS, CORS, clickjacking, open redirect, DOM clobbering
│   │   │       ├── cloud_supply.py      # Cloud metadata, S3 misconfig, dependency confusion
│   │   │       ├── data_exposure.py     # Info disclosure, debug endpoints, source code exposure
│   │   │       ├── deserialization.py   # Insecure deserialization, Java RMI, GWT
│   │   │       ├── file_access.py       # LFI, RFI, path traversal, file upload, XXE
│   │   │       ├── infrastructure.py    # SSL/TLS, HTTP methods, subdomain takeover
│   │   │       ├── logic.py             # Business logic, race conditions, JWT, OAuth
│   │   │       └── request_forgery.py   # SSRF, CSRF, DNS rebinding
│   │   ├── validation/                  # False-positive hardening
│   │   │   ├── negative_control.py      # Benign request control engine
│   │   │   ├── proof_of_execution.py    # Per-type proof checks (25+ methods)
│   │   │   ├── confidence_scorer.py     # Numeric 0-100 scoring
│   │   │   └── validation_judge.py      # Sole authority for finding approval
│   │   ├── request_engine.py            # Retry, rate limit, circuit breaker
│   │   ├── waf_detector.py              # 16 WAF signatures, 13 techniques + composite evasion
│   │   ├── strategy_adapter.py          # Mid-scan strategy + confidence-based pivoting
│   │   ├── chain_engine.py              # 10 exploit chain rules
│   │   ├── auth_manager.py              # Multi-user auth management
│   │   ├── xss_context_analyzer.py      # 8-context XSS analysis
│   │   ├── poc_generator.py             # 20+ per-type PoC generators
│   │   ├── autonomous_scanner.py        # AutonomousScanner (fallback for <10 endpoints)
│   │   ├── recon_integration.py         # 40+ tool recon orchestration (3 depth levels)
│   │   └── report_engine/               # OHVR report generator
│   ├── models/                          # 15 SQLAlchemy model files (21 model classes)
│   │   ├── scan.py                      # Scan
│   │   ├── vulnerability.py             # Vulnerability, VulnerabilityTest
│   │   ├── memory.py                    # AgentMemoryEntry, AgentOperation, AgentOperationPlan, AttackPatternMemory, TargetFingerprint, SuccessfulPayload
│   │   ├── bugbounty_submission.py      # BugBountySubmission
│   │   ├── governance_profile.py        # GovernanceProfileRecord
│   │   ├── governance_violation.py      # GovernanceViolationRecord
│   │   ├── report.py                    # Report
│   │   ├── endpoint.py                  # Endpoint
│   │   ├── target.py                    # Target
│   │   ├── prompt.py                    # Prompt
│   │   ├── agent_task.py                # AgentTask
│   │   ├── llm_test_result.py           # LlmTestResult
│   │   ├── trace.py                     # TraceSpan
│   │   ├── tradecraft.py                # Tradecraft, ScanTradecraft
│   │   └── vuln_lab.py                  # VulnLabChallenge
│   ├── services/
│   │   └── scan_service.py              # Scan orchestration (LLMDrivenAgent path)
│   ├── db/                              # Database layer
│   ├── config.py                        # Pydantic settings
│   └── main.py                          # FastAPI app entry
│
├── core/                                # Shared core modules
│   ├── mcp_server.py                    # MCP server (34+ tools, stdio)
│   ├── mcp_tools_pd.py                  # 9 ProjectDiscovery MCP tool handlers
│   ├── mcp_tools_proxy.py              # 7 mitmproxy MCP tool handlers
│   ├── sandbox_manager.py               # BaseSandbox ABC + opsec-aware sandbox
│   ├── kali_sandbox.py                  # Per-scan Kali container manager
│   ├── container_pool.py                # Global container pool coordinator
│   ├── opsec_manager.py                 # Opsec profile system (stealth/balanced/aggressive)
│   ├── tool_registry.py                 # 56 tool install recipes for Kali
│   ├── scheduler.py                     # APScheduler scan scheduling
│   └── browser_validator.py             # Playwright browser validation
│
├── frontend/                            # React + TypeScript Frontend
│   ├── src/
│   │   ├── pages/                       # 21 page components
│   │   ├── components/                  # Reusable UI components
│   │   ├── services/api.ts              # API client layer
│   │   └── types/index.ts              # TypeScript interfaces
│   └── package.json
│
├── docker/
│   ├── Dockerfile.kali                  # Multi-stage Kali sandbox (20 Go tools)
│   ├── Dockerfile.backend               # Backend container
│   ├── Dockerfile.frontend              # Frontend container
│   ├── docker-compose.kali.yml          # Kali sandbox build
│   └── docker-compose.sandbox.yml       # Legacy sandbox
│
├── prompts/
│   ├── md_library/                      # 16 prompt templates
│   ├── task_library.json                # 12 preset task definitions
│   └── library.json                     # Prompt categorization by attack phase
│
├── config/
│   ├── config.json                      # Profiles, tools, sandbox, MCP, opsec, 3-tier routing
│   └── opsec_profiles.json              # Stealth/balanced/aggressive opsec profiles
├── vendor/
│   └── PayloadsAllTheThings/            # PATT git submodule (33,500+ payloads)
├── data/
│   ├── vuln_knowledge_base.json         # Vuln type definitions
│   ├── execution_history.json           # Cross-scan learning data
│   └── access_control_learning.json     # BOLA/BFLA adaptive data
│
├── scripts/
│   └── build-kali.sh                    # Build/rebuild Kali image
├── tools/
│   └── benchmark_runner.py              # 104 CTF challenges
├── agents/base_agent.py                 # BaseAgent class
├── sploitai.py                          # CLI entry point
└── requirements.txt
```

---

## LLM-Driven Agent

The LLM-Driven Agent (`backend/core/llm_agent.py`) is the sole autonomous agent. The LLM has full execution control — it decides what to do at every step, choosing tools, forming hypotheses, and pivoting based on results.

### 18 Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `shell_execute` | Execute shell commands in Docker sandbox (nmap, sqlmap, nuclei, httpx, etc.). Output truncated to 30KB. |
| 2 | `http_request` | Send HTTP requests with full method/header/body control for API testing, IDOR checks, auth bypass |
| 3 | `browser_navigate` | Navigate headless browser to URL with JS rendering. Returns title, final URL, content summary |
| 4 | `browser_extract_links` | Extract all links from current browser page (anchors, forms, JavaScript) |
| 5 | `browser_extract_forms` | Extract forms with actions, methods, fields, hidden inputs. Identifies injection points and CSRF tokens |
| 6 | `browser_submit_form` | Fill in and submit forms. Tests login, registration, and interactive HTML forms. Preserves hidden fields |
| 7 | `browser_screenshot` | Capture full-page screenshot for evidence documentation |
| 8 | `browser_execute_js` | Execute JavaScript in browser context for DOM extraction, XSS testing, cookie reading |
| 9 | `memory_store` | Store observations in persistent memory (6 categories: recon, finding, credential, observation, hypothesis, evidence) |
| 10 | `memory_search` | Search stored memories by keyword or semantic similarity |
| 11 | `save_artifact` | Save evidence/data files to operation artifacts directory |
| 12 | `report_finding` | Report confirmed vulnerability with evidence, CVSS, CWE, PoC. HIGH/CRITICAL require artifacts |
| 13 | `update_plan` | Update operation plan at start and checkpoints (20%/40%/60%/80%) |
| 14 | `get_payloads` | Retrieve curated payloads (100+ vuln types, 526+ payloads including PATT) with WAF bypass variants |
| 15 | `get_vuln_info` | Get CWE IDs, severity, descriptions, remediation from VulnerabilityRegistry (100+ types) |
| 16 | `spawn_subagent` | Spawn lightweight FAST-tier sub-agent for parallel recon (max 3 concurrent, 120s timeout, shared budget) |
| 17 | `create_tool` | Create custom tools at runtime with Python code. AST validation blocks dangerous modules (os, subprocess, sys) |
| 18 | `stop` | Terminate operation with reason and summary |

### Cognitive Framework

The agent follows a KNOW/THINK/TEST/VALIDATE cycle at every step:

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌──────────┐
│  KNOW   │────▶│  THINK  │────▶│  TEST   │────▶│ VALIDATE │
│         │     │         │     │         │     │          │
│ What do │     │ Form    │     │ Run the │     │ Assess   │
│ I know? │     │ explicit│     │ highest │     │ outcome, │
│ Recon,  │     │ hypo-   │     │ value   │     │ update   │
│ tech,   │     │ thesis  │     │ action  │     │ confi-   │
│ prior   │     │ with %  │     │ to con- │     │ dence,   │
│ results │     │ confi-  │     │ firm or │     │ decide   │
│         │     │ dence   │     │ refute  │     │ next     │
└─────────┘     └─────────┘     └─────────┘     └──────────┘
                                                      │
                                          ┌───────────┤
                                          ▼           ▼
                                     >70%: Escalate  <50%: Pivot
```

### Confidence-Driven Actions

| Confidence | Action |
|-----------|--------|
| **>75%** | Attempt direct exploitation |
| **40–75%** | Run targeted tests to confirm |
| **<40%** | Gather more information before testing |

### Stuck Detection

- 3 method failures → switch method within class
- 5 approach failures → switch vulnerability class
- >40% budget with zero findings → advance phase
- 60% budget with no findings → focus top 3 targets
- 80% budget → stop testing, begin reporting
- 90% budget → emergency stop

### Plan Lifecycle

4 phases with checkpoint updates at 20%, 40%, 60%, and 80% of step budget:

| Phase | Budget | Focus |
|-------|--------|-------|
| **Discovery** | 0–25% | Port scan, service detection, tech fingerprinting, endpoint enumeration, auth mapping |
| **Hypothesis** | 25–50% | Identify high-value targets, form vulnerability hypotheses, prioritize by likelihood/impact |
| **Validation** | 50–80% | Test hypotheses with crafted requests, collect evidence, verify with negative controls |
| **Reporting** | 80–100% | Document confirmed findings, save artifacts, generate final summary |

### Sub-Agents (spawn_subagent)

The agent can spawn lightweight sub-agents for parallel recon:
- **FAST-tier** LLM routing (lowest cost)
- **Max 3 concurrent** sub-agents
- **120-second timeout** per sub-agent
- **Shared budget** — sub-agent steps count against the parent budget
- **Limited tool set** — sub-agents have access to a subset of tools
- **Governance-checked** — sub-agents inherit the parent's scope restrictions

### Dynamic Tools (create_tool)

Runtime Python tool creation for one-off analysis:
- **AST validation** — code is parsed and validated before execution
- **Blocked modules**: `os`, `subprocess`, `sys`, `shutil`, `socket`, `ctypes`
- **Allowed modules**: `json`, `re`, `base64`, `urllib.parse`, `hashlib`, `html`, `math`, `collections`, `itertools`, `string`, `binascii`, `hmac`

### Persistent Memory

- **TF-IDF vector search** with recency boosting (no external dependencies)
- **Per-target persistence** across operations — cross-engagement learning
- **6 categories**: recon, finding, credential, observation, hypothesis, evidence
- Stores to SQLite, loads prior knowledge for repeat targets

### Quality Evaluation

Post-operation quality scoring across 5 dimensions:

| Dimension | Weight | Measures |
|-----------|--------|----------|
| **Coverage** | 20% | Tool diversity (6 categories), finding diversity, recon depth |
| **Efficiency** | 15% | Finding rate per step, budget utilization (50–90% ideal) |
| **Evidence** | 30% | Evidence substance (>100 chars), reproduction steps, HTTP details |
| **Methodology** | 15% | Plan updates (3+), memory usage, recon-first, evidence capture |
| **Reporting** | 20% | Title, severity, description, endpoint, remediation completeness |

### Context Management

- **Sliding-window trimming** — older messages compressed when conversation exceeds 200K tokens
- **Tool result truncation** — large outputs capped to fit context budget
- **Parallel tool execution** — multiple tool_use blocks dispatched via `asyncio.gather` (max 8 concurrent)

---

## Governance

Governance enforcement uses a **2-layer architecture** controlled by a unified facade (`governance_facade.py`). Scope cannot be widened after scan creation.

### Layer 1: Scope Enforcement (governance.py)

Controls **what** can be tested — domains, vulnerability types, phases, recon depth.

#### 6 Scope Profiles

| Profile | Use Case | Restrictions |
|---------|----------|-------------|
| **full_auto** | Comprehensive autonomous scanning | All phases, all vuln types, full recon |
| **vuln_lab** | Single-vulnerability testing | Tight scope, single vuln type, no subdomain enum |
| **ctf** | Capture-the-flag challenges | All phases, all vuln types, full recon |
| **recon_only** | Reconnaissance without exploitation | Recon phases only, no active testing |
| **bug_bounty** | Bug bounty programs | Scoped to program rules, submission tracking |
| **custom** | User-defined | Configurable per-field |

#### ScanScope Fields

| Field | Type | Description |
|-------|------|-------------|
| `profile` | ScopeProfile | Baseline restrictiveness level |
| `allowed_domains` | FrozenSet | Permitted target domains (empty = all) |
| `allowed_vuln_types` | FrozenSet | Permitted vulnerability types (None = all) |
| `allowed_phases` | FrozenSet | Permitted scan phases (empty = all) |
| `skip_subdomain_enum` | bool | Skip subdomain enumeration |
| `skip_port_scan` | bool | Skip port scanning |
| `max_recon_depth` | str | "quick" / "medium" / "full" |
| `nuclei_template_tags` | Optional[str] | Nuclei template tags for scoping |
| `include_subdomains` | bool | *.example.com in scope if example.com allowed |
| `allowed_cidrs` | FrozenSet | CIDR ranges (e.g. "192.168.1.0/24") |
| `bugbounty_context` | Any | Optional bug bounty context |

### Layer 2: Phase-Action Gating (governance_gate.py)

Controls **when** actions can happen — prevents exploitation during recon, blocks post-exploitation unless explicitly authorized.

#### 7 Action Categories

(ordered from least to most intrusive)

| Category | Description |
|----------|-------------|
| `PASSIVE_RECON` | DNS lookups, WHOIS, certificate inspection |
| `ACTIVE_RECON` | Port scanning, web crawling, tech fingerprinting |
| `ANALYSIS` | Data analysis, pattern matching, report formatting |
| `VULNERABILITY_SCAN` | Vulnerability probing, payload injection |
| `EXPLOITATION` | Exploiting confirmed vulnerabilities |
| `POST_EXPLOITATION` | Post-exploit actions (data extraction, pivoting) |
| `REPORTING` | Report generation and documentation |

#### 9 Phases

`initializing`, `passive_recon`, `recon`, `analyzing`, `testing`, `exploitation`, `full_auto`, `reporting`, `completed`

Each phase defines which action categories are allowed and which are denied. For example, the `recon` phase allows passive recon, active recon, analysis, and reporting — but denies vulnerability scanning, exploitation, and post-exploitation.

### 3 Governance Modes

| Mode | Behavior |
|------|----------|
| **strict** | Block prohibited actions, record violation |
| **warn** | Log violation but allow action to proceed |
| **off** | No enforcement |

### Scope-Aware Prompts

Recon-scoped operations receive a dedicated execution prompt (`execution_prompt_recon.md`) that reinforces recon-only behavior in the LLM's system prompt, complementing the enforcement layers.

---

## Opsec Profiles

Configurable operational security postures that control scan behavior per tool. Set via the `opsec_profile` parameter on any MCP tool call or scan.

### Profiles

| Setting | Stealth | Balanced (default) | Aggressive |
|---------|---------|-------------------|------------|
| **Request Jitter** | 500–3000ms | 100–500ms | None |
| **Random User-Agent** | Yes | Yes | Yes |
| **DNS-over-HTTPS** | Yes | No | No |
| **Proxy Routing** | Auto (use if up) | Opt-in | Off |
| **Header Randomization** | Yes | No | No |

### Per-Tool Tuning (examples)

| Tool | Stealth | Balanced | Aggressive |
|------|---------|----------|------------|
| nuclei | rate-limit 10, concurrency 2 | rate-limit 50, concurrency 10 | rate-limit 150, concurrency 25 |
| naabu | rate 100, SYN scan, top-ports 100 | rate 500, top-ports 1000 | rate 1000 |
| httpx | rate-limit 5, delay 1–3s | rate-limit 50 | No rate limit |
| katana | delay 2s, depth 2 | delay 0.5s, depth 3 | depth 5 |
| nmap | -T2, --scan-delay 1s | -T3 | -T4 |
| ffuf | rate 10, 2 threads | rate 50, 10 threads | rate 150, 40 threads |

Profiles are defined in `config/opsec_profiles.json`. User-supplied flags always override profile defaults.

---

## OSINT Integration

14 API clients in `backend/core/osint/` provide automated intelligence gathering from external sources. The `aggregator.py` module runs parallel multi-source queries.

| Client | File | Source |
|--------|------|--------|
| **Shodan** | `shodan_client.py` | Host info, open ports, services, known vulnerabilities |
| **Censys** | `censys_client.py` | Hosts, certificates, search |
| **VirusTotal** | `virustotal_client.py` | URL/domain scan, reputation |
| **SecurityTrails** | `securitytrails.py` | Subdomains, DNS history, associated domains |
| **BuiltWith** | `builtwith_client.py` | Technology profiling |
| **NVD** | `nvd_client.py` | CVE data, CVSS scores, affected products |
| **ExploitDB** | `exploitdb_client.py` | Known exploits, PoC availability |
| **ZoomEye** | `zoomeye.py` | Open ports, banners, OS fingerprints |
| **FOFA** | `fofa.py` | Open ports, services, technologies |
| **PublicWWW** | `publicwww.py` | Sites using specific code/libraries |
| **GitHub Dork** | `github_dork.py` | Leaked secrets, config files, API keys in repos |
| **GrayhatWarfare** | `grayhat_warfare.py` | Exposed S3/Azure/GCS buckets |
| **Have I Been Pwned** | `hibp.py` | Breach history, paste appearances |
| **DeHashed** | `dehashed.py` | Breach data, exposed credentials |

Each client requires its own API key set via environment variables (e.g., `SHODAN_API_KEY`, `CENSYS_API_ID`).

---

## MCP Server & Tools

The MCP server (`core/mcp_server.py`) exposes 34+ tools over stdio for AI agent integration.

### Tool Categories

| Category | Tools | Description |
|----------|-------|-------------|
| **Scanning** | `execute_nuclei`, `execute_naabu`, `sandbox_exec` | Vulnerability scanning with opsec profile support |
| **Reconnaissance** | `execute_httpx`, `execute_subfinder`, `execute_katana`, `execute_dnsx`, `execute_uncover`, `execute_nmap`, `execute_ffuf` | Target discovery and enumeration |
| **ProjectDiscovery** | `execute_cvemap`, `execute_tlsx`, `execute_asnmap`, `execute_mapcidr`, `execute_alterx`, `execute_shuffledns`, `execute_cloudlist`, `execute_interactsh`, `execute_notify` | Full PD suite with structured output |
| **Proxy** | `proxy_status`, `proxy_flows`, `proxy_capture`, `proxy_replay`, `proxy_intercept`, `proxy_clear`, `proxy_export` | mitmproxy control (requires `--profile proxy`) |
| **Utility** | `browser_navigate`, `browser_screenshot` | Browser automation |

```bash
# Start the MCP server
python3 -m core.mcp_server
```

---

## Prompt & Task Library

### Prompt Templates (`prompts/md_library/`)

16 Markdown-based prompt templates with standardized `## User Prompt` / `## System Prompt` structure:

| Template | Focus |
|----------|-------|
| **Pentestfull** | Elite pentester with full OWASP WSTG v4.2, CVE analysis, zero-day methodology |
| **pentest / pentest_generalist** | Professional workflow with tool execution and documentation format |
| **recon_specialist** | AI-enhanced reconnaissance with attack surface analysis and strategic recommendations |
| **red_team_agent** | Red team attack simulation with real tool execution |
| **bug_bounty_hunter** | Bug bounty focused assessment |
| **owasp_expert / owasp** | OWASP Top 10 assessment |
| **cwe_expert** | CWE Top 25 analysis |
| **exploit_expert** | Exploit development guidance |
| **blue_team_agent** | Defensive security analysis |
| **malware_analyst / malware_analysis** | Malware analysis |
| **replay_attack / replay_attack_specialist** | Replay attack testing |
| **apt_ttp_profiles** | APT group profiles (APT1, Lazarus, Cozy Bear) with OPSEC decision trees |

### Task Presets (`prompts/task_library.json`)

12 preset tasks selectable from the scan UI:

| Category | Tasks |
|----------|-------|
| **Recon** | Full Reconnaissance, Passive Reconnaissance, AI-Enhanced Reconnaissance |
| **Vulnerability** | OWASP Top 10, API Security, Injection Testing |
| **Full Auto** | Bug Bounty Hunter Mode, Full Penetration Test |
| **Custom** | Custom Prompt (Full AI Mode), Analysis Only |
| **Reporting** | Executive Summary Report, Technical Security Report |

---

## Vulnerability Engine

### 100 Base Types + 19 PATT Extended

100 vulnerability types across **12 tester categories** in `backend/core/vuln_engine/testers/`:

| Category | Module | Examples |
|----------|--------|---------|
| **Injection** | `injection.py` | SQLi (error/union/blind/time), NoSQLi, LDAP, XPath, command injection |
| **Advanced Injection** | `advanced_injection.py` | SSTI, CRLF, header injection, log injection, GraphQL injection |
| **Authentication** | `auth.py` | Auth bypass, session fixation, credential stuffing, password reset, MFA bypass |
| **Authorization** | `authorization.py` | BOLA, BFLA, IDOR, privilege escalation, forced browsing |
| **Client-Side** | `client_side.py` | XSS (reflected/stored/DOM), CORS, clickjacking, open redirect, DOM clobbering, prototype pollution |
| **Cloud/Supply Chain** | `cloud_supply.py` | Cloud metadata, S3 misconfiguration, dependency confusion, third-party scripts |
| **Data Exposure** | `data_exposure.py` | Info disclosure, debug endpoints, source code exposure, backup files |
| **Deserialization** | `deserialization.py` | Insecure deserialization, Java RMI, GWT deserialization |
| **File Access** | `file_access.py` | LFI, RFI, path traversal, file upload, XXE |
| **Infrastructure** | `infrastructure.py` | SSL/TLS, HTTP methods, subdomain takeover, host header, CNAME hijacking |
| **Logic** | `logic.py` | Business logic, race conditions, JWT manipulation, OAuth flaws, cache poisoning |
| **Request Forgery** | `request_forgery.py` | SSRF, CSRF, cloud metadata, DNS rebinding |

### 19 PATT Extended Types

Conditionally visible when the PATT submodule is initialized:

| Type | Severity | CWE |
|------|----------|-----|
| Account Takeover | Critical | CWE-284 |
| Client-Side Path Traversal | Medium | CWE-22 |
| Denial of Service | Medium | CWE-400 |
| Dependency Confusion | Critical | CWE-427 |
| DNS Rebinding | High | CWE-350 |
| External Variable Modification | High | CWE-473 |
| GWT Deserialization | High | CWE-502 |
| Headless Browser Abuse | High | CWE-94 |
| Java RMI Exploitation | Critical | CWE-502 |
| LaTeX Injection | High | CWE-94 |
| LLM Prompt Injection | High | CWE-77 |
| ReDoS | Medium | CWE-1333 |
| Reverse Proxy Misconfiguration | High | CWE-441 |
| SAML Injection | Critical | CWE-287 |
| SSI Injection | High | CWE-97 |
| Virtual Host Enumeration | Medium | CWE-200 |
| Web Cache Deception | High | CWE-525 |
| Cross-Site Leak (XS-Leak) | Medium | CWE-203 |
| XSLT Injection | High | CWE-91 |

### Payload Engine

- **34,000+ total payloads** — 665 curated + 33,500 from PayloadsAllTheThings
- **Curated-first ordering** — curated payloads always tried first, PATT payloads appended (deduplicated)
- **Available at all scan depths** — quick (3), standard (10), thorough (20), exhaustive (all) draw from the merged pool
- **DB-specific SQLi payloads** — MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB (auto-selected via error fingerprinting)
- **Polyglot payloads** — multi-context payloads combining SQL+XSS, Cmd+XSS, SSTI+XSS
- **WAF-adaptive transformation** — 13 techniques + composite per-WAF evasion
- Per-type AI decision prompts with anti-hallucination directives

### Top Payload Counts

| Vuln Type | PATT Payloads |
|-----------|---------------|
| Path Traversal | 22,582 |
| LFI | 4,758 |
| XSS Reflected | 2,162 |
| Web Cache Deception | 1,125 |
| SQLi (error+union+blind+time) | 1,537 |
| Command Injection | 491 |
| Open Redirect | 305 |
| SSTI | 183 |
| XXE | 102 |

---

## PayloadsAllTheThings Integration

sploit.ai integrates [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (PATT) as a git submodule, providing 33,500+ community-maintained payloads across 61 mapped categories.

### Setup

```bash
# Initialize the PATT submodule (one time)
git submodule update --init

# Or via the PATT CLI
python -m backend.core.vuln_engine.patt.cli update
```

### How It Works

- **61 PATT categories** mapped to sploit.ai vuln types (1:1, 1:N fan-out, and 19 new types)
- **Parser pipeline** extracts payloads from Intruder wordlists and Markdown code blocks, filtering out prose, language-tagged code examples, and duplicates
- **Merge strategy**: curated payloads come first in ordering, PATT payloads are appended (deduplicated), available at all scan depths
- **Dynamic diminishing returns**: strategy adapter scales testing thresholds based on available payload pool size
- **Graceful degradation**: returns empty lists when submodule is not initialized; all base functionality works without PATT

### PATT CLI

```bash
# Show submodule status and payload counts per vuln type
python -m backend.core.vuln_engine.patt.cli status

# Parse a single PATT category and preview results
python -m backend.core.vuln_engine.patt.cli parse "SQL Injection"

# Dump all PATT payloads for a vuln type
python -m backend.core.vuln_engine.patt.cli dump command_injection

# Update submodule to latest
python -m backend.core.vuln_engine.patt.cli update
```

---

## Kali Sandbox System

Each scan runs in its own **isolated Kali Linux Docker container**, providing:

- **Complete Isolation** — no interference between concurrent scans
- **On-Demand Tools** — 56 tools installed only when needed
- **Auto Cleanup** — containers destroyed when scan completes
- **Resource Limits** — per-container memory (2GB) and CPU (2 cores) limits

### Pre-Installed Tools (38)

| Category | Tools |
|----------|-------|
| **Scanners** | nuclei, naabu, httpx, nmap, nikto, masscan, whatweb |
| **Discovery** | subfinder, katana, dnsx, uncover, ffuf, gobuster, waybackurls |
| **ProjectDiscovery** | tlsx, asnmap, cvemap, mapcidr, alterx, shuffledns, cloudlist, interactsh-client, notify |
| **Exploitation** | dalfox, sqlmap |
| **DNS** | massdns (+ bundled resolvers file) |
| **System** | curl, wget, git, python3, pip3, go, jq, dig, whois, openssl, netcat, bash |

### On-Demand Tools (28 more)

Installed automatically inside the container when first requested:

- **APT**: wpscan, dirb, hydra, john, hashcat, testssl, sslscan, enum4linux, dnsrecon, amass, medusa, crackmapexec, etc.
- **Go**: gau, gitleaks, anew, httprobe
- **Pip**: dirsearch, wfuzz, arjun, wafw00f, sslyze, commix, trufflehog, retire

### Container Pool

```
ContainerPool (global coordinator, max 5 concurrent)
  ├── KaliSandbox(scan_id="abc") → docker: sploitai-abc
  ├── KaliSandbox(scan_id="def") → docker: sploitai-def
  └── KaliSandbox(scan_id="ghi") → docker: sploitai-ghi
```

- **TTL enforcement** — containers auto-destroyed after 60 min
- **Orphan cleanup** — stale containers removed on server startup
- **Graceful fallback** — falls back to shared container if Docker unavailable
- **Network** — all containers on `sploitai-network` for inter-container communication

---

## Anti-Hallucination & Validation

sploit.ai uses a multi-layered validation pipeline to eliminate false positives:

### Validation Pipeline

```
Finding Candidate
    │
    ▼
┌─────────────────────┐
│ Negative Controls    │  Send benign/empty requests as controls
│ Same behavior = FP   │  -60 confidence if same response
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Proof of Execution   │  25+ per-vuln-type proof methods
│ XSS: context check   │  SSRF: metadata markers
│ SQLi: DB errors       │  BOLA: data comparison
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ AI Interpretation    │  LLM with anti-hallucination prompts
│ Per-type system msgs │  17 composable prompt templates
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Confidence Scorer    │  0-100 numeric score
│ ≥90 = confirmed      │  +proof, +impact, +controls
│ ≥60 = likely          │  -baseline_only, -same_behavior
│ <60 = rejected        │  Breakdown visible in UI
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Validation Judge     │  Final verdict authority
│ approve / reject     │  Records for adaptive learning
└─────────────────────┘
```

### Anti-Hallucination System Prompts

17 composable prompts applied across 8 task contexts (testing, verification, confirmation, strategy, reporting, interpretation, poc_generation, recon_analysis):
- `anti_hallucination` — core truthfulness directives
- `proof_of_execution` — require concrete evidence
- `negative_controls` — compare with benign requests
- `anti_severity_inflation` — accurate severity ratings
- `access_control_intelligence` — BOLA/BFLA data comparison methodology
- `operational_humility` — uncertainty over false confidence
- `decision_confidence` — cognitive loop with confidence thresholds and adaptive triggers

### Access Control Adaptive Learning

- Records TP/FP outcomes per domain for BOLA/BFLA/IDOR
- 9 default response patterns, 6 known FP patterns (WSO2, Keycloak, etc.)
- Historical FP rate influences future confidence scoring

---

## Unified LLM Layer

The unified LLM layer (`backend/core/llm/`) provides 3-tier model routing, native tool calling, structured JSON output, and per-session cost tracking across 6 providers.

### 3-Tier Model Routing

| Tier | Default Model | Task Types | Use Case |
|------|--------------|------------|----------|
| **Fast** | Claude Haiku 4.5 | Classification, formatting, simple extraction, status checks, log parsing | High-volume, low-complexity calls |
| **Balanced** | Claude Sonnet 4.6 | Testing decisions, strategy, analysis, report generation, prompt processing | Core agent reasoning |
| **Deep** | Claude Opus 4.5 | Exploit validation, chain analysis, zero-day research, complex auth testing, novel attack planning | High-stakes decisions |

Per-tier model overrides are available via environment variables (`LLM_MODEL_FAST`, `LLM_MODEL_BALANCED`, `LLM_MODEL_DEEP`) or the Settings UI.

### 6 Providers

| Provider | Authentication | Models |
|----------|---------------|--------|
| **Anthropic** | `ANTHROPIC_API_KEY` | Claude Haiku, Sonnet, Opus |
| **OpenAI** | `OPENAI_API_KEY` | GPT-4o-mini, GPT-4o |
| **Google Gemini** | `GEMINI_API_KEY` | Gemini 2.0 Flash, Gemini 2.0 Pro |
| **AWS Bedrock** | AWS credential chain | Claude models via Bedrock |
| **Ollama** | Local (no key) | Any Ollama model |
| **LM Studio** | Local (no key) | Any LM Studio model |

> **OpenRouter**: Supported via `OPENROUTER_API_KEY` environment variable. Requests are routed through the OpenAI-compatible provider — there is no dedicated OpenRouter provider module.

### Cost Tracking

Per-session budget enforcement with configurable limits (default $5.00/scan). Tracks input/output tokens per tier with warning thresholds at 80% budget utilization. Full cost reports available per scan with tier-level breakdowns.

---

## mitmproxy Integration

Opt-in HTTP/HTTPS proxy for traffic inspection, replay, and routing scan traffic through an intercepting proxy.

### Setup

```bash
# Start mitmproxy (not started by default)
docker compose --profile proxy up -d
```

| Endpoint | URL | Description |
|----------|-----|-------------|
| **Proxy** | `http://localhost:8081` | HTTP/HTTPS proxy port |
| **Web UI** | `http://localhost:8082` | mitmweb interface + REST API |

### MCP Tools

| Tool | Description |
|------|-------------|
| `proxy_status` | Health check, flow count, connection info |
| `proxy_flows` | Retrieve captured flows with optional filter |
| `proxy_capture` | Set/clear view filter for flow capture |
| `proxy_replay` | Replay a captured flow with optional header/body modifications |
| `proxy_intercept` | Set/clear intercept breakpoints (pause matching flows) |
| `proxy_clear` | Clear all captured flows |
| `proxy_export` | Export a flow as curl command or raw request/response |

### Proxy Routing

When an opsec profile has proxy routing enabled (stealth: auto, balanced: opt-in), scan containers automatically route HTTP/HTTPS traffic through mitmproxy. TLS interception is supported — the mitmproxy CA certificate is auto-installed in sandbox containers.

---

## interactsh OOB Server

Self-hosted out-of-band (OOB) interaction server for detecting blind vulnerabilities (SSRF, blind XSS, blind SQLi, etc.).

```bash
# Start interactsh server (not started by default)
docker compose --profile oob up -d
```

The stealth opsec profile automatically routes `interactsh-client` to the self-hosted server (`-server http://sploitai-interactsh`) instead of public servers. Balanced and aggressive profiles use the default public interactsh infrastructure.

Configure the domain via the `INTERACTSH_DOMAIN` environment variable (defaults to `interact.local`).

---

## Vulnerability Enrichment

Automated CVE and exploit cross-referencing for discovered vulnerabilities via NVD and ExploitDB.

### NVD API Integration

- Queries the NIST National Vulnerability Database for CVE details
- Retrieves CVSS scores, affected products (CPE), and reference links
- Rate-limited with configurable API key for higher throughput

### ExploitDB CSV Lookup

- Cross-references findings against the ExploitDB CSV database
- Matches by CVE ID, vulnerability type, and keyword
- Returns exploit IDs, descriptions, and proof-of-concept availability

### Processing

- **Queue-based** — enrichment jobs processed asynchronously to avoid blocking scans
- **Rate-limited** — respects NVD API rate limits (configurable delay between requests)
- **Batch support** — enrich all findings for a scan in one call (`POST /enrichment/scans/{scan_id}/enrich`)
- **On-demand** — manually trigger enrichment for individual vulnerabilities

---

## Tradecraft Library

35 built-in TTP entries accessible via the `/api/v1/tradecraft` endpoint, including 23 LOLBin techniques for red team operations.

### LOLBin Techniques (23)

| Platform | Techniques |
|----------|-----------|
| **Windows** (10) | PowerShell Download Cradle, CertUtil, BITSAdmin, MSBuild, RegSvr32, WMI, Scheduled Task, SC Service, Rundll32, NET Command |
| **Linux** (10) | Bash Reverse Shell, Curl/Wget, Cron Persistence, SSH Key Persistence, Python Reverse Shell, Systemd Persistence, Find Discovery, Netcat, Perl Reverse Shell, SSH Tunneling |
| **macOS** (3) | LaunchAgent Persistence, Python Reverse Shell, AppleScript Execution |

Each entry includes MITRE ATT&CK technique IDs and detection probability profiles across 8 vectors (AV, IDS, EDR, Heuristic, Sandbox, Traffic, Logs, Memory).

---

## Bug Bounty Support

sploit.ai includes purpose-built support for bug bounty programs:

- **BUG_BOUNTY scope profile** — governance profile that scopes the agent to program rules
- **`bugbounty.py` API router** — CRUD endpoints for bug bounty submission tracking
- **`BugBountySubmission` model** — SQLAlchemy model for persisting submissions
- **`BugBountyPage.tsx`** — dedicated frontend page for managing submissions
- **Agent prompt injection** — bug bounty instructions injected into the agent's system prompt when the BUG_BOUNTY profile is active

---

## Web GUI

### 21 Pages

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Stats overview, severity distribution, recent activity feed |
| **Agent** | `/agent` | Start operations, view agent status, re-run |
| **Agent Detail** | `/agent/:operationId` | Operation detail with decision log, findings, re-run & compare |
| **Operations** | `/operations` | Operations list (redirects to Agent) |
| **Operation Detail** | `/operations/:id` | Operation detail (redirects to Agent Detail) |
| **Vuln Lab** | `/vuln-lab` | Per-type vulnerability testing (100+ types, 12 categories + PATT) |
| **Terminal Agent** | `/terminal` | AI-powered interactive security chat + tool execution |
| **Sandboxes** | `/sandboxes` | Real-time Docker container monitoring + management |
| **Scan Details** | `/scan/:scanId` | Findings with confidence badges, pause/resume/stop |
| **New Scan** | `/scan/new` | Create new scan (redirects to Agent) |
| **Scheduler** | `/scheduler` | Cron/interval automated scan scheduling |
| **Reports** | `/reports` | Report generation and listing |
| **Report View** | `/reports/:reportId` | HTML report viewer |
| **Tradecraft** | `/tradecraft` | TTP tradecraft library browser |
| **Governance** | `/governance` | Governance profiles and violation viewer |
| **Settings** | `/settings` | LLM providers, model routing, feature toggles |
| **Compare Scans** | `/compare` | Side-by-side scan comparison |
| **Prompts** | `/prompts` | Prompt template library |
| **Task Library** | `/tasks` | Task preset management |
| **Realtime** | `/realtime` | Realtime interactive agent sessions |
| **Bug Bounty** | `/bugbounty` | Bug bounty submission tracking |

### Sandbox Dashboard

Real-time monitoring of per-scan Kali containers:
- **Pool stats** — active/max containers, Docker status, TTL
- **Capacity bar** — visual utilization indicator
- **Per-container cards** — name, scan link, uptime, installed tools, status
- **Actions** — health check, destroy (with confirmation), cleanup expired/orphans
- **5-second auto-polling** for real-time updates

---

## API Reference

### Base URL

```
http://localhost:8000/api/v1
```

### Endpoints

#### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scans` | Create new scan |
| `GET` | `/scans` | List all scans |
| `GET` | `/scans/{id}` | Get scan details |
| `POST` | `/scans/{id}/start` | Start scan |
| `POST` | `/scans/{id}/stop` | Stop scan |
| `POST` | `/scans/{id}/pause` | Pause scan |
| `POST` | `/scans/{id}/resume` | Resume scan |
| `DELETE` | `/scans/{id}` | Delete scan |

#### LLM-Driven Agent

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/agent-v2/start` | Start LLM-driven autonomous assessment |
| `POST` | `/agent-v2/{id}/stop` | Stop running agent |
| `POST` | `/agent-v2/{id}/pause` | Pause running agent |
| `POST` | `/agent-v2/{id}/resume` | Resume paused agent |
| `POST` | `/agent-v2/{id}/prompt` | Inject custom prompt into running agent |
| `GET` | `/agent-v2/by-scan/{scan_id}` | Reverse-lookup operation by scan ID |
| `GET` | `/agent-v2/{id}/status` | Get agent operation status |
| `GET` | `/agent-v2/{id}/findings` | Get findings from operation |
| `GET` | `/agent-v2/{id}/decisions` | Get decision log (LLM reasoning + tool calls) |
| `GET` | `/agent-v2/operations` | List all agent operations |
| `POST` | `/agent-v2/{id}/report` | Generate HTML/JSON report |
| `GET` | `/agent-v2/{id}/report/download` | Download report |

#### Task Library

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/tasks` | List task presets |
| `POST` | `/tasks` | Create task preset |
| `PUT` | `/tasks/{id}` | Update task preset |
| `DELETE` | `/tasks/{id}` | Delete task preset |

#### Realtime Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/realtime/start` | Start realtime interactive session |
| `POST` | `/realtime/{id}/message` | Send message to running session |
| `POST` | `/realtime/{id}/stop` | Stop realtime session |
| `GET` | `/realtime/{id}/status` | Get session status |

#### Bug Bounty

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/bugbounty/submissions` | List bug bounty submissions |
| `POST` | `/bugbounty/submissions` | Create submission |
| `GET` | `/bugbounty/submissions/{id}` | Get submission details |
| `PUT` | `/bugbounty/submissions/{id}` | Update submission |
| `DELETE` | `/bugbounty/submissions/{id}` | Delete submission |

#### Enrichment

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/enrichment/vulnerabilities/{vuln_id}/enrich` | Trigger enrichment for single vulnerability |
| `POST` | `/enrichment/scans/{scan_id}/enrich` | Batch enrich all vulnerabilities in scan |
| `GET` | `/enrichment/vulnerabilities/{vuln_id}/enrichment` | Get enrichment data for vulnerability |

#### Governance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/governance/scans/{scan_id}/governance/violations` | List governance violations for scan |
| `GET` | `/governance/scans/{scan_id}/governance/stats` | Get governance stats for scan |

#### Memory

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/memory/stats` | Get persistent memory statistics |
| `GET` | `/memory/target/{domain}` | Get cumulative knowledge about a target |
| `GET` | `/memory/payloads` | Get highest-success payloads by vuln type |
| `GET` | `/memory/vuln-types` | Get vuln types ranked by historical success |
| `DELETE` | `/memory/clear` | Clear all persistent memory |

#### Traces

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/traces/scan/{scan_id}` | Get all trace spans for a scan |
| `GET` | `/traces/span/{span_id}` | Get detailed span info |
| `GET` | `/traces/stats` | Get global tracing statistics |

#### Sandbox

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/sandbox` | List containers + pool status |
| `GET` | `/sandbox/{scan_id}` | Health check container |
| `DELETE` | `/sandbox/{scan_id}` | Destroy container |
| `POST` | `/sandbox/cleanup` | Remove expired containers |
| `POST` | `/sandbox/cleanup-orphans` | Remove orphan containers |

#### Scheduler

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/scheduler` | List scheduled jobs |
| `POST` | `/scheduler` | Create scheduled job |
| `DELETE` | `/scheduler/{id}` | Delete job |
| `POST` | `/scheduler/{id}/pause` | Pause job |
| `POST` | `/scheduler/{id}/resume` | Resume job |

#### Vulnerability Lab

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/vuln-lab/types` | List vuln types by category (includes PATT Extended when available) |
| `POST` | `/vuln-lab/run` | Run per-type vulnerability test |
| `GET` | `/vuln-lab/challenges` | List challenge runs |
| `GET` | `/vuln-lab/stats` | Detection rate stats |

#### Tradecraft

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/tradecraft` | List all tradecraft TTP entries |
| `GET` | `/tradecraft/{id}` | Get tradecraft entry details |

#### Reports & Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/reports` | Generate report |
| `POST` | `/reports/ai-generate` | AI-powered report |
| `GET` | `/reports/{id}/view` | View HTML report |
| `GET` | `/dashboard/stats` | Dashboard statistics |
| `GET` | `/dashboard/activity-feed` | Recent activity |

### WebSocket

```
ws://localhost:8000/ws/scan/{scan_id}              # Scan events
ws://localhost:8000/api/v1/agent-v2/{id}/ws        # LLM agent real-time events
```

Scan events: `scan_started`, `progress_update`, `finding_discovered`, `scan_completed`, `scan_error`

Agent events: `status`, `tool_call`, `tool_result`, `finding`, `plan_update`, `decision`, `error`, `complete`

### API Docs

Interactive docs available at:
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

---

## Configuration

### Environment Variables

```bash
# LLM API Keys (at least one required)
ANTHROPIC_API_KEY=your-key
OPENAI_API_KEY=your-key
GEMINI_API_KEY=your-key
OPENROUTER_API_KEY=your-key   # Routed through OpenAI-compatible provider

# AWS Bedrock (uses AWS credential chain - no API key needed)
AWS_BEDROCK_REGION=us-east-1
AWS_BEDROCK_MODEL=us.anthropic.claude-sonnet-4-6-v1:0

# Local LLM (optional)
OLLAMA_BASE_URL=http://localhost:11434
LMSTUDIO_BASE_URL=http://localhost:1234

# 3-tier model overrides (optional)
LLM_MODEL_FAST=claude-haiku-4-5-20251001
LLM_MODEL_BALANCED=claude-sonnet-4-6-20250514
LLM_MODEL_DEEP=claude-opus-4-5-20250514

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/sploitai.db

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

### AWS Bedrock Setup

AWS Bedrock lets you use Claude models through your AWS account with no separate API key. Authentication uses the standard AWS credential chain:

1. **Environment variables** — `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
2. **Shared credentials** — `~/.aws/credentials` (set `AWS_PROFILE` if not default)
3. **IAM role** — automatic on EC2/ECS/Lambda
4. **SSO** — `aws sso login --profile your-profile`

Your IAM principal needs the `bedrock:InvokeModel` permission.

### config/config.json

```json
{
  "llm": {
    "default_profile": "gemini_pro_default",
    "profiles": { ... }
  },
  "agent_roles": {
    "pentest_generalist": { "vuln_coverage": 119 },
    "bug_bounty_hunter": { "vuln_coverage": 119 }
  },
  "sandbox": {
    "mode": "per_scan",
    "kali": {
      "enabled": true,
      "image": "sploitai-kali:latest",
      "max_concurrent": 5,
      "container_ttl_minutes": 60
    }
  },
  "opsec": {
    "default_profile": "balanced",
    "profiles_file": "config/opsec_profiles.json"
  },
  "mcp_servers": {
    "sploitai_tools": {
      "transport": "stdio",
      "command": "python3",
      "args": ["-m", "core.mcp_server"]
    }
  }
}
```

---

## Development

### Backend

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# API docs: http://localhost:8000/api/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # Dev server at http://localhost:5173
npm run build      # Production build
```

### Build Kali Sandbox

```bash
./scripts/build-kali.sh --test    # Build + health check
```

### MCP Server

```bash
python3 -m core.mcp_server        # Starts stdio MCP server (34+ tools)
```

### PATT Payload Library

```bash
# Initialize/update PayloadsAllTheThings submodule
git submodule update --init

# Check status and payload counts
python3 -m backend.core.vuln_engine.patt.cli status
```

---

## Security Notice

**This tool is for authorized security testing only.**

- Only test systems you own or have explicit written permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Unauthorized access to computer systems is illegal

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Python, FastAPI, SQLAlchemy, Pydantic, aiohttp |
| **Frontend** | React 18, TypeScript, TailwindCSS, Vite |
| **AI/LLM** | Anthropic Claude, OpenAI GPT, Google Gemini, AWS Bedrock, Ollama, LM Studio (3-tier routing, native tool calling, structured JSON) |
| **Sandbox** | Docker, Kali Linux, 20 ProjectDiscovery tools, Nmap, SQLMap, Nikto |
| **Tools** | Nuclei, Naabu, httpx, Subfinder, Katana, tlsx, asnmap, cvemap, mapcidr, alterx, shuffledns, cloudlist, interactsh, FFuf, Dalfox |
| **Proxy** | mitmproxy (opt-in traffic interception, replay, TLS inspection) |
| **OOB** | interactsh-server (self-hosted out-of-band interaction server) |
| **OSINT** | Shodan, Censys, VirusTotal, SecurityTrails, BuiltWith, NVD, ExploitDB, ZoomEye, FOFA, PublicWWW, GitHub Dork, GrayhatWarfare, HIBP, DeHashed |
| **Payloads** | PayloadsAllTheThings (33,500+ community payloads via git submodule, 61 mapped categories) |
| **Infra** | Docker Compose, MCP Protocol (34+ tools), Playwright, APScheduler |

---

**sploit.ai v3** — *AI-Powered Autonomous Penetration Testing Platform*

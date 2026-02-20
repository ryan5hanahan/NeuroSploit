# sploit.ai v3

![sploit.ai](https://img.shields.io/badge/sploit.ai-AI--Powered%20Pentesting-blueviolet)
![Version](https://img.shields.io/badge/Version-3.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)
![React](https://img.shields.io/badge/React-18-61dafb)
![Vuln Types](https://img.shields.io/badge/Vuln%20Types-119-red)
![Payloads](https://img.shields.io/badge/Payloads-34K+-orange)
![Docker](https://img.shields.io/badge/Docker-Kali%20Sandbox-informational)
![LLM Agent](https://img.shields.io/badge/LLM%20Agent-13%20Tools-purple)

**AI-Powered Autonomous Penetration Testing Platform**

sploit.ai v3 is an advanced security assessment platform that combines AI-driven autonomous agents with an LLM-driven agent (13 tools, KNOW/THINK/TEST/VALIDATE cognitive cycle, persistent memory), 119 vulnerability types, 34,000+ payloads (665 curated + 33,500 from PayloadsAllTheThings), 3-tier LLM model routing (fast/balanced/deep), governance scope enforcement (5 profiles), NVD & ExploitDB vulnerability enrichment, per-scan isolated Kali Linux containers, configurable opsec profiles (stealth/balanced/aggressive), the full ProjectDiscovery tool suite (20 tools), opt-in mitmproxy traffic inspection, false-positive hardening with decision confidence scoring, exploit chaining, DB-specific payload selection, composite WAF evasion, and a modern React web interface with real-time monitoring.

---

## Highlights

- **119 Vulnerability Types** across 11 categories with AI-driven testing prompts
- **34,000+ Payloads** - 665 curated + 33,500 from PayloadsAllTheThings (PATT), merged at all scan depths
- **3-Tier LLM Routing** - Fast (Haiku) / Balanced (Sonnet) / Deep (Opus) with 18 mapped call sites, per-tier cost tracking
- **5 Agent Modes** - Full auto, auto pentest, recon-only (with AI analysis), prompt-only, analyze-only
- **Opsec Profiles** - Stealth/balanced/aggressive profiles controlling rate limits, jitter, proxy routing, and DNS-over-HTTPS per tool
- **Full ProjectDiscovery Suite** - 20 Go tools pre-compiled (nuclei, httpx, katana, subfinder, tlsx, asnmap, cvemap, and more)
- **LLM-Driven Agent** - Autonomous reasoning agent with 13 tools, KNOW/THINK/TEST/VALIDATE cognitive cycle, persistent memory, plan lifecycle, and quality scoring
- **Governance Scoping** - 5 scope profiles (full_auto/vuln_lab/ctf/recon_only/custom) with immutable enforcement across 4 layers
- **NVD & ExploitDB Enrichment** - Automated CVE lookup and exploit cross-reference for findings via rate-limited queue processing
- **Quality Scoring** - 5-dimension post-operation quality evaluation (coverage, efficiency, evidence, methodology, reporting)
- **34+ MCP Tools** - Scanning, reconnaissance, proxy control, and ProjectDiscovery tool handlers via MCP protocol
- **Per-Scan Kali Containers** - Each scan runs in its own isolated Docker container
- **mitmproxy Integration** - Opt-in HTTP/HTTPS traffic interception, flow capture, replay, and export
- **Self-Hosted OOB Server** - Optional interactsh-server for out-of-band vulnerability testing
- **Anti-Hallucination Pipeline** - Negative controls, proof-of-execution, decision confidence scoring with adaptive pivoting
- **Exploit Chain Engine** - Automatically chains findings (SSRF->internal, SQLi->DB-specific, etc.)
- **WAF Detection & Bypass** - 16 WAF signatures, 13 bypass techniques, composite WAF-specific evasion
- **DB-Specific Payloads** - Auto-detect database type from error signatures, select MySQL/Postgres/MSSQL/Oracle/SQLite/MongoDB payloads
- **Smart Strategy Adaptation** - Dead endpoint detection, dynamic diminishing returns (scales with payload pool size), confidence-based pivoting, priority recomputation
- **Multi-Provider LLM** - Claude, GPT, Gemini, AWS Bedrock, Ollama, LMStudio, OpenRouter
- **Tradecraft Library** - 35 built-in TTP entries including 23 LOLBin techniques with MITRE ATT&CK mapping and detection profiles
- **Real-Time Dashboard** - WebSocket-powered live scan progress, findings, and reports
- **Sandbox Dashboard** - Monitor running Kali containers, tools, health checks in real-time

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Autonomous Agent](#autonomous-agent)
- [LLM-Driven Agent](#llm-driven-agent)
- [Governance](#governance)
- [Opsec Profiles](#opsec-profiles)
- [MCP Server & Tools](#mcp-server--tools)
- [Prompt & Task Library](#prompt--task-library)
- [119 Vulnerability Types](#119-vulnerability-types)
- [PayloadsAllTheThings Integration](#payloadsallthethings-integration)
- [Kali Sandbox System](#kali-sandbox-system)
- [mitmproxy Integration](#mitmproxy-integration)
- [interactsh OOB Server](#interactsh-oob-server)
- [Anti-Hallucination & Validation](#anti-hallucination--validation)
- [Unified LLM Layer](#unified-llm-layer)
- [Vulnerability Enrichment](#vulnerability-enrichment)
- [Tradecraft Library](#tradecraft-library)
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
npm run dev
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

Access the web interface at **http://localhost:8000** (production build) or **http://localhost:5173** (dev mode).

---

## Architecture

```
sploit.ai/
├── backend/                         # FastAPI Backend
│   ├── api/v1/                      # REST API (19 routers)
│   │   ├── scans.py                 # Scan CRUD + pause/resume/stop
│   │   ├── agent.py                 # AI Agent control (V1)
│   │   ├── agent_v2.py              # LLM-Driven Agent (13 endpoints + WebSocket)
│   │   ├── agent_tasks.py           # Scan task tracking
│   │   ├── dashboard.py             # Stats + activity feed
│   │   ├── enrichment.py            # NVD/ExploitDB vulnerability enrichment
│   │   ├── governance.py            # Governance scope violations + stats
│   │   ├── reports.py               # Report generation (HTML/PDF/JSON)
│   │   ├── scheduler.py             # Cron/interval scheduling
│   │   ├── vuln_lab.py              # Per-type vulnerability lab
│   │   ├── terminal.py              # Terminal agent (10 endpoints)
│   │   ├── sandbox.py               # Sandbox container monitoring
│   │   ├── targets.py               # Target validation
│   │   ├── prompts.py               # Preset prompts
│   │   ├── vulnerabilities.py       # Vulnerability management
│   │   ├── tradecraft.py            # TTP tradecraft library (35 entries)
│   │   ├── memory.py                # Agent memory management
│   │   ├── traces.py                # LLM call tracing
│   │   └── settings.py              # Runtime settings
│   ├── core/
│   │   ├── autonomous_agent.py      # Main AI agent (~7600 lines)
│   │   ├── llm_agent.py             # LLM-Driven Agent (full LLM execution control)
│   │   ├── llm_agent_tools.py       # 13 tool schemas for LLM agent
│   │   ├── governance.py            # Governance scope enforcement (5 profiles)
│   │   ├── llm/                     # Unified LLM layer (3-tier routing)
│   │   │   ├── client.py            # UnifiedLLMClient (generate, generate_json, generate_with_tools)
│   │   │   ├── router.py            # 3-tier ModelRouter (fast/balanced/deep)
│   │   │   ├── providers/           # 6 provider implementations
│   │   │   ├── prompt_composer.py   # Tier-aware system prompt composition
│   │   │   ├── tool_adapter.py      # MCP-to-provider tool format conversion
│   │   │   ├── conversation.py      # Multi-turn message history
│   │   │   ├── cost_tracker.py      # Per-tier token/cost tracking with budget enforcement
│   │   │   ├── meta_tools.py        # 7 structured decision schemas
│   │   │   └── tool_executor.py     # Tool dispatch for LLM agent with governance
│   │   ├── tools/                   # LLM agent tool implementations
│   │   │   ├── shell_tool.py        # Docker sandbox shell execution
│   │   │   ├── browser_tool.py      # Playwright browser automation
│   │   │   ├── http_tool.py         # HTTP request handler
│   │   │   └── parallel_executor.py # Parallel tool execution (asyncio.gather)
│   │   ├── memory/                  # Persistent memory system
│   │   │   ├── vector_memory.py     # TF-IDF semantic search, per-target persistence
│   │   │   └── plan_manager.py      # Plan lifecycle with checkpoints
│   │   ├── prompts/                 # Cognitive prompt framework
│   │   │   ├── agent_system_prompt.md # KNOW/THINK/TEST/VALIDATE cognitive framework
│   │   │   ├── execution_prompt_general.md # Web pentest execution guidance
│   │   │   └── prompt_composer.py   # Dynamic prompt assembly with plan/memory injection
│   │   ├── observability/           # Operation metrics
│   │   │   ├── operation_tracker.py # Token/cost/tool metrics tracking
│   │   │   └── quality_evaluator.py # Post-op quality scoring (5 dimensions)
│   │   ├── vuln_engine/             # 119-type vulnerability engine
│   │   │   ├── registry.py          # 119 VULNERABILITY_INFO entries (100 base + 19 PATT)
│   │   │   ├── payload_generator.py # 34K+ payloads (665 curated + PATT merge)
│   │   │   ├── injection_context.py # DB type detection from error signatures
│   │   │   ├── ai_prompts.py        # Per-vuln AI decision prompts (119 types)
│   │   │   ├── system_prompts.py    # 17 composable prompts, 8 task contexts
│   │   │   ├── patt/               # PayloadsAllTheThings integration
│   │   │   │   ├── category_map.py  # 61 PATT category mappings
│   │   │   │   ├── parser.py        # Intruder wordlist + markdown parsers
│   │   │   │   ├── loader.py        # PATTLoader with lazy loading + caching
│   │   │   │   └── cli.py           # PATT CLI (status/parse/dump/update)
│   │   │   └── testers/             # 10 category tester modules
│   │   ├── validation/              # False-positive hardening
│   │   │   ├── negative_control.py  # Benign request control engine
│   │   │   ├── proof_of_execution.py # Per-type proof checks (25+ methods)
│   │   │   ├── confidence_scorer.py # Numeric 0-100 scoring
│   │   │   └── validation_judge.py  # Sole authority for finding approval
│   │   ├── request_engine.py        # Retry, rate limit, circuit breaker
│   │   ├── waf_detector.py          # 16 WAF signatures, 13 techniques + composite evasion
│   │   ├── strategy_adapter.py      # Mid-scan strategy + confidence-based pivoting
│   │   ├── chain_engine.py          # 10 exploit chain rules
│   │   ├── auth_manager.py          # Multi-user auth management
│   │   ├── xss_context_analyzer.py  # 8-context XSS analysis
│   │   ├── poc_generator.py         # 20+ per-type PoC generators
│   │   ├── execution_history.py     # Cross-scan learning
│   │   ├── access_control_learner.py # Adaptive BOLA/BFLA/IDOR learning
│   │   ├── response_verifier.py     # 4-signal response verification
│   │   ├── agent_memory.py          # Bounded dedup agent memory
│   │   ├── recon_integration.py     # 40+ tool recon orchestration (3 depth levels)
│   │   ├── ai_prompt_processor.py   # LLM-based prompt analysis
│   │   ├── task_library.py          # Task/prompt lifecycle management
│   │   └── report_engine/           # OHVR report generator
│   ├── models/                      # SQLAlchemy ORM models
│   ├── db/                          # Database layer
│   ├── config.py                    # Pydantic settings
│   └── main.py                      # FastAPI app entry
│
├── core/                            # Shared core modules
│   ├── llm_manager.py               # Legacy LLM routing (deprecated, see backend/core/llm/)
│   ├── sandbox_manager.py           # BaseSandbox ABC + opsec-aware sandbox
│   ├── kali_sandbox.py              # Per-scan Kali container manager
│   ├── container_pool.py            # Global container pool coordinator
│   ├── opsec_manager.py             # Opsec profile system (stealth/balanced/aggressive)
│   ├── tool_registry.py             # 56 tool install recipes for Kali
│   ├── mcp_server.py                # MCP server (34+ tools, stdio)
│   ├── mcp_tools_pd.py              # 9 ProjectDiscovery MCP tool handlers
│   ├── mcp_tools_proxy.py           # 7 mitmproxy MCP tool handlers
│   ├── scheduler.py                 # APScheduler scan scheduling
│   └── browser_validator.py         # Playwright browser validation
│
├── frontend/                        # React + TypeScript Frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── HomePage.tsx             # Dashboard with stats
│   │   │   ├── AutoPentestPage.tsx      # 3-stream auto pentest
│   │   │   ├── VulnLabPage.tsx          # Per-type vulnerability lab
│   │   │   ├── TerminalAgentPage.tsx    # AI terminal chat
│   │   │   ├── SandboxDashboardPage.tsx # Container monitoring
│   │   │   ├── ScanDetailsPage.tsx      # Findings + validation
│   │   │   ├── SchedulerPage.tsx        # Cron/interval scheduling
│   │   │   ├── SettingsPage.tsx         # Configuration
│   │   │   └── ReportsPage.tsx          # Report management
│   │   ├── components/              # Reusable UI components
│   │   ├── services/api.ts          # API client layer
│   │   └── types/index.ts           # TypeScript interfaces
│   └── package.json
│
├── docker/
│   ├── Dockerfile.kali              # Multi-stage Kali sandbox (20 Go tools)
│   ├── Dockerfile.sandbox           # Legacy Debian sandbox
│   ├── Dockerfile.backend           # Backend container
│   ├── Dockerfile.frontend          # Frontend container
│   ├── docker-compose.kali.yml      # Kali sandbox build
│   └── docker-compose.sandbox.yml   # Legacy sandbox
│
├── prompts/
│   ├── md_library/                  # 16 prompt templates (pentest, recon, OWASP, APT TTPs, etc.)
│   ├── task_library.json            # 12 preset task definitions
│   └── library.json                 # Prompt categorization by attack phase
│
├── config/
│   ├── config.json                  # Profiles, tools, sandbox, MCP, opsec
│   └── opsec_profiles.json          # Stealth/balanced/aggressive opsec profiles
├── vendor/
│   └── PayloadsAllTheThings/        # PATT git submodule (33,500+ payloads)
├── data/
│   ├── vuln_knowledge_base.json     # 119 vuln type definitions
│   ├── execution_history.json       # Cross-scan learning data
│   └── access_control_learning.json # BOLA/BFLA adaptive data
│
├── scripts/
│   └── build-kali.sh               # Build/rebuild Kali image
├── tools/
│   └── benchmark_runner.py          # 104 CTF challenges
├── agents/base_agent.py             # BaseAgent class
├── sploitai.py                   # CLI entry point
└── requirements.txt
```

---

## Autonomous Agent

The AI agent (`autonomous_agent.py`) orchestrates security assessments across 5 operation modes.

### Operation Modes

| Mode | Description |
|------|-------------|
| **Full Auto** | 5-phase workflow: recon, AI attack surface analysis, vulnerability testing (119 types), AI finding enhancement, report generation |
| **Auto Pentest** | 3-stream parallel architecture (see below) with deep analysis and comprehensive 119-type testing |
| **Recon Only** | Tool-based reconnaissance (3 depth levels) + WAF detection + AI-powered attack surface analysis with technology risk mapping, auth boundary identification, and strategic recommendations |
| **Prompt Only** | AI-driven mode where the LLM plans and executes the full assessment based on a user prompt or task preset |
| **Analyze Only** | Passive analysis of provided data without active testing |

### Recon Depth Levels

| Depth | Phases | Includes |
|-------|--------|----------|
| **Quick** | 3 | DNS resolution, HTTP probing, basic path discovery |
| **Medium** | 8 | Quick + subdomain enumeration, URL collection, port scan (top 100), tech detection, web crawling |
| **Full** | 14 | Medium + full port scan, parameter discovery, JS analysis, directory fuzzing, nuclei scan, screenshots |

When an LLM is configured, recon-only scans include an AI analysis phase that produces structured intelligence: technology-to-CVE mapping, authentication boundary mapping, high-value target prioritization, infrastructure assessment, and strategic P1-P4 recommendations. Falls back to tool-only output when no LLM is available.

### 3-Stream Parallel Architecture (Auto Pentest)

```
                    ┌─────────────────────┐
                    │   Auto Pentest      │
                    │   Target URL(s)     │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
   │  Stream 1    │ │  Stream 2    │ │  Stream 3    │
   │  Recon       │ │  Junior Test │ │  Tool Runner │
   │  ─────────── │ │  ─────────── │ │  ─────────── │
   │  Crawl pages │ │  Test target │ │  Nuclei scan │
   │  Find params │ │  AI-priority │ │  Naabu ports │
   │  Tech detect │ │  3 payloads  │ │  AI decides  │
   │  WAF detect  │ │  per endpoint│ │  extra tools │
   └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
          │                │                │
          └────────────────┼────────────────┘
                           ▼
              ┌─────────────────────┐
              │  Deep Analysis      │
              │  119 vuln types     │
              │  Full payload sets  │
              │  Chain exploitation │
              └─────────┬───────────┘
                        ▼
              ┌─────────────────────┐
              │  Report Generation  │
              │  AI executive brief │
              │  PoC code per find  │
              └─────────────────────┘
```

### Agent Autonomy Modules

| Module | Description |
|--------|-------------|
| **Request Engine** | Retry with backoff, per-host rate limiting, circuit breaker, adaptive timeouts |
| **WAF Detector** | 16 WAF signatures (Cloudflare, AWS, Akamai, Imperva, etc.), 13 bypass techniques, composite WAF-specific evasion (per-WAF technique chaining) |
| **Strategy Adapter** | Dead endpoint detection, dynamic diminishing returns (scales with payload pool size), 403 bypass, confidence-based pivoting (<30% auto-pivot, 3+ failures force switch), priority recomputation |
| **Chain Engine** | 10 chain rules (SSRF->internal, SQLi->DB-specific, LFI->config, IDOR pattern transfer) |
| **Auth Manager** | Multi-user contexts (user_a, user_b, admin), login form detection, session management |
| **Injection Context** | Auto-detect database type from error signatures (MySQL, Postgres, MSSQL, Oracle, SQLite), select DB-specific payloads |
| **Cost Tracker** | Per-tier token and cost tracking with configurable budget limits and warning thresholds |

### Scan Features

- **Pause / Resume / Stop** with checkpoints
- **Manual Validation** - Confirm or reject AI findings
- **Screenshot Capture** on confirmed findings (Playwright)
- **Cross-Scan Learning** - Historical success rates influence future priorities
- **CVE Testing** - Regex detection + AI-generated payloads

---

## LLM-Driven Agent

The LLM-Driven Agent (`llm_agent.py`) is a second-generation autonomous agent where the LLM has full execution control. Unlike the code-driven pipeline of `AutonomousAgent`, the LLM decides what to do at every step — choosing tools, forming hypotheses, and pivoting based on results.

### AutonomousAgent vs LLM-Driven Agent

| | AutonomousAgent | LLM-Driven Agent |
|--|----------------|------------------|
| **Control** | Code-driven pipeline with LLM advisory | LLM controls execution end-to-end |
| **Tools** | MCP tools (34+) via sandbox | 13 purpose-built tools with governance |
| **Reasoning** | Anti-hallucination prompts | KNOW/THINK/TEST/VALIDATE cognitive cycle |
| **Memory** | Bounded dedup memory | TF-IDF vector search, per-target persistence |
| **Planning** | Fixed phase progression | Dynamic plan lifecycle with checkpoints |
| **API** | `/api/v1/agent/*` | `/api/v1/agent-v2/*` |

### 13 Tools

| Tool | Description |
|------|-------------|
| `shell_execute` | Execute shell commands in Docker sandbox (nmap, sqlmap, nuclei, httpx, etc.) |
| `http_request` | Send HTTP requests with full method/header/body control |
| `browser_navigate` | Navigate headless browser to URL with JS rendering |
| `browser_extract_links` | Extract all links from current browser page |
| `browser_extract_forms` | Extract forms with actions, methods, fields, hidden inputs |
| `browser_screenshot` | Capture full-page screenshot with label |
| `browser_execute_js` | Execute JavaScript in browser context |
| `memory_store` | Store observations in persistent memory (6 categories) |
| `memory_search` | Search stored memories by keyword/semantic similarity |
| `save_artifact` | Save evidence/data to operation artifacts directory |
| `report_finding` | Report confirmed vulnerability with evidence, CVSS, CWE, PoC |
| `update_plan` | Update operation plan at start and checkpoints |
| `stop` | Terminate operation with reason and summary |

### Cognitive Framework

The agent follows a KNOW/THINK/TEST/VALIDATE cycle:

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

Governance scope enforcement (`governance.py`) restricts what agents can do based on configurable scope profiles. Enforcement is immutable — scope cannot be widened after scan creation.

### Scope Profiles

| Profile | Use Case | Restrictions |
|---------|----------|-------------|
| **full_auto** | Comprehensive autonomous scanning | All phases, all vuln types, full recon |
| **vuln_lab** | Single-vulnerability testing | Tight scope, single vuln type, no subdomain enum |
| **ctf** | Capture-the-flag challenges | All phases, all vuln types, full recon |
| **recon_only** | Reconnaissance without exploitation | Recon phases only, no active testing |
| **custom** | User-defined | Configurable per-field |

### ScanScope Fields

| Field | Type | Description |
|-------|------|-------------|
| `profile` | ScopeProfile | Baseline restrictiveness level |
| `allowed_domains` | FrozenSet | Permitted target domains (empty = all) |
| `allowed_vuln_types` | FrozenSet | Permitted vulnerability types (empty = all) |
| `allowed_phases` | FrozenSet | Permitted scan phases (empty = all) |
| `skip_subdomain_enum` | bool | Skip subdomain enumeration |
| `skip_port_scan` | bool | Skip port scanning |
| `max_recon_depth` | str | "quick" / "medium" / "full" |
| `nuclei_template_tags` | Optional[str] | Nuclei template tags for scoping |

### Enforcement Layers

Governance is enforced at multiple levels — tool execution, API requests, scan orchestration, and agent decision-making — ensuring scope constraints cannot be bypassed.

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
| **apt_ttp_profiles** | APT group profiles (APT1, Lazarus, Cozy Bear) with OPSEC decision trees, stealth scoring, and campaign lifecycle |

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

## 119 Vulnerability Types

### Categories

| Category | Types | Examples |
|----------|-------|---------|
| **Injection** | 38 | XSS (reflected/stored/DOM), SQLi, NoSQLi, Command Injection, SSTI, LDAP, XPath, CRLF, Header Injection, Log Injection, GraphQL Injection |
| **Inspection** | 21 | Security Headers, CORS, Clickjacking, Info Disclosure, Debug Endpoints, Error Disclosure, Source Code Exposure |
| **AI-Driven** | 41 | BOLA, BFLA, IDOR, Race Condition, Business Logic, JWT Manipulation, OAuth Flaws, Prototype Pollution, WebSocket Hijacking, Cache Poisoning, HTTP Request Smuggling |
| **Authentication** | 8 | Auth Bypass, Session Fixation, Credential Stuffing, Password Reset Flaws, MFA Bypass, Default Credentials |
| **Authorization** | 6 | BOLA, BFLA, IDOR, Privilege Escalation, Forced Browsing, Function-Level Access Control |
| **File Access** | 5 | LFI, RFI, Path Traversal, File Upload, XXE |
| **Request Forgery** | 4 | SSRF, CSRF, Cloud Metadata, DNS Rebinding |
| **Client-Side** | 8 | CORS, Clickjacking, Open Redirect, DOM Clobbering, Prototype Pollution, PostMessage, CSS Injection |
| **Infrastructure** | 6 | SSL/TLS, HTTP Methods, Subdomain Takeover, Host Header, CNAME Hijacking |
| **Cloud/Supply** | 4 | Cloud Metadata, S3 Bucket Misconfiguration, Dependency Confusion, Third-Party Script |
| **PATT Extended** | 19 | Account Takeover, Prompt Injection, SAML Injection, Web Cache Deception, ReDoS, LaTeX Injection, XSLT Injection, SSI Injection, Java RMI, GWT Deserialization, XS-Leak, and more |

### PATT Extended Types (19)

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

Each new type includes full AI testing prompts, proof-of-execution requirements, and knowledge base entries. Types are conditionally visible in the Vuln Lab when the PATT submodule is initialized.

### Payload Engine

- **34,000+ total payloads** - 665 curated + 33,500 from PayloadsAllTheThings
- **Curated-first ordering** - Curated payloads always tried first, PATT payloads appended (deduplicated)
- **Available at all scan depths** - Quick (3), standard (10), thorough (20), exhaustive (all) draw from the merged pool
- **73 XSS stored payloads** + 5 context-specific sets + 2,162 PATT XSS payloads
- **DB-specific SQLi payloads** - MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB (auto-selected via error fingerprinting) + 1,537 PATT SQLi payloads
- **22,582 path traversal payloads** from PATT Intruder wordlists
- **Polyglot payloads** - Multi-context payloads combining SQL+XSS, Cmd+XSS, SSTI+XSS
- **Extended XXE** - Parameter entity, blind XXE with external DTD, SVG-based, XInclude
- **Extended SSRF** - AWS/GCP/Azure/DigitalOcean cloud metadata paths
- Per-type AI decision prompts with anti-hallucination directives (119 types)
- WAF-adaptive payload transformation (13 techniques + composite per-WAF evasion)

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

## Kali Sandbox System

Each scan runs in its own **isolated Kali Linux Docker container**, providing:

- **Complete Isolation** - No interference between concurrent scans
- **On-Demand Tools** - 56 tools installed only when needed
- **Auto Cleanup** - Containers destroyed when scan completes
- **Resource Limits** - Per-container memory (2GB) and CPU (2 cores) limits

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

- **TTL enforcement** - Containers auto-destroyed after 60 min
- **Orphan cleanup** - Stale containers removed on server startup
- **Graceful fallback** - Falls back to shared container if Docker unavailable
- **Network** - All containers on `sploitai-network` for inter-container communication

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
- `anti_hallucination` - Core truthfulness directives
- `proof_of_execution` - Require concrete evidence
- `negative_controls` - Compare with benign requests
- `anti_severity_inflation` - Accurate severity ratings
- `access_control_intelligence` - BOLA/BFLA data comparison methodology
- `operational_humility` - Uncertainty over false confidence
- `decision_confidence` - Cognitive loop (KNOW/THINK/TEST/VALIDATE) with confidence thresholds (>75% exploit, 40-75% test more, <40% pivot) and adaptive triggers

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
| **Deep** | Claude Opus 4.5 | Exploit validation, chain analysis, zero-day research, complex auth testing, novel attack planning, executive reporting, architecture review, threat modeling | High-stakes decisions |

All 18 LLM call sites in the agent use `task_type=` routing. Per-tier model overrides are available via environment variables (`LLM_MODEL_FAST`, `LLM_MODEL_BALANCED`, `LLM_MODEL_DEEP`) or the Settings UI.

### Providers

| Provider | Authentication | Models |
|----------|---------------|--------|
| **Anthropic** | `ANTHROPIC_API_KEY` | Claude Haiku, Sonnet, Opus |
| **OpenAI** | `OPENAI_API_KEY` | GPT-4o-mini, GPT-4o |
| **Google Gemini** | `GEMINI_API_KEY` | Gemini 2.0 Flash, Gemini 2.0 Pro |
| **AWS Bedrock** | AWS credential chain | Claude models via Bedrock |
| **Ollama** | Local (no key) | Any Ollama model |
| **LM Studio** | Local (no key) | Any LM Studio model |

### Cost Tracking

Per-session budget enforcement with configurable limits (default $5.00/scan). Tracks input/output tokens per tier with warning thresholds at 80% budget utilization. Full cost reports available per scan with tier-level breakdowns.

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

## Web GUI

### Pages

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Stats overview, severity distribution, recent activity feed |
| **Agent** | `/agent` | Unified agent dashboard — start operations, view status, re-run |
| **Agent Detail** | `/agent/:id` | Operation detail with decision log, findings, re-run & compare |
| **Auto Pentest** | `/auto` | One-click autonomous pentest with 3-stream live display |
| **Vuln Lab** | `/vuln-lab` | Per-type vulnerability testing (119 types, 11 categories + PATT Extended) |
| **Terminal Agent** | `/terminal` | AI-powered interactive security chat + tool execution |
| **Sandboxes** | `/sandboxes` | Real-time Docker container monitoring + management |
| **Compare Scans** | `/compare` | Side-by-side scan comparison |
| **Scan Details** | `/scan/:id` | Findings with confidence badges, pause/resume/stop |
| **Scheduler** | `/scheduler` | Cron/interval automated scan scheduling |
| **Reports** | `/reports` | HTML/PDF/JSON report generation and viewing |
| **Tradecraft** | `/tradecraft` | TTP tradecraft library browser |
| **Settings** | `/settings` | LLM providers, model routing, feature toggles |

### Sandbox Dashboard

Real-time monitoring of per-scan Kali containers:
- **Pool stats** - Active/max containers, Docker status, TTL
- **Capacity bar** - Visual utilization indicator
- **Per-container cards** - Name, scan link, uptime, installed tools, status
- **Actions** - Health check, destroy (with confirmation), cleanup expired/orphans
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

#### AI Agent (V1)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/agent/run` | Launch autonomous agent |
| `GET` | `/agent/status/{id}` | Get agent status + findings |
| `GET` | `/agent/by-scan/{scan_id}` | Get agent by scan ID |
| `POST` | `/agent/stop/{id}` | Stop agent |
| `POST` | `/agent/pause/{id}` | Pause agent |
| `POST` | `/agent/resume/{id}` | Resume agent |
| `GET` | `/agent/findings/{id}` | Get findings with details |
| `GET` | `/agent/logs/{id}` | Get agent logs |

#### LLM-Driven Agent (V2)

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
| `GET` | `/vuln-lab/types` | List 119 vuln types by category (includes PATT Extended when available) |
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
OPENROUTER_API_KEY=your-key

# AWS Bedrock (uses AWS credential chain - no API key needed)
# Authenticate via env vars, ~/.aws/credentials, IAM role, or SSO
AWS_BEDROCK_REGION=us-east-1
AWS_BEDROCK_MODEL=us.anthropic.claude-sonnet-4-6-v1:0
# AWS_ACCESS_KEY_ID=your-access-key
# AWS_SECRET_ACCESS_KEY=your-secret-key
# AWS_PROFILE=default

# Local LLM (optional)
OLLAMA_BASE_URL=http://localhost:11434
LMSTUDIO_BASE_URL=http://localhost:1234

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/sploitai.db

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
```

### AWS Bedrock Setup

AWS Bedrock lets you use Claude models through your AWS account with no separate API key. Authentication uses the standard AWS credential chain:

1. **Environment variables** - `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
2. **Shared credentials** - `~/.aws/credentials` (set `AWS_PROFILE` if not default)
3. **IAM role** - Automatic on EC2/ECS/Lambda
4. **SSO** - `aws sso login --profile your-profile`

Your IAM principal needs the `bedrock:InvokeModel` permission. To enable Bedrock as the default provider, set `default_profile` to `bedrock_claude_default` in `config/config.json`.

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

# Run PATT integration tests
pytest tests/test_patt_integration.py -v
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

MIT License - See [LICENSE](LICENSE) for details.

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Python, FastAPI, SQLAlchemy, Pydantic, aiohttp |
| **Frontend** | React 18, TypeScript, TailwindCSS, Vite |
| **AI/LLM** | Anthropic Claude, OpenAI GPT, Google Gemini, AWS Bedrock, Ollama, LMStudio, OpenRouter (3-tier routing, native tool calling, structured JSON) |
| **Sandbox** | Docker, Kali Linux, 20 ProjectDiscovery tools, Nmap, SQLMap, Nikto |
| **Tools** | Nuclei, Naabu, httpx, Subfinder, Katana, tlsx, asnmap, cvemap, mapcidr, alterx, shuffledns, cloudlist, interactsh, FFuf, Dalfox |
| **Proxy** | mitmproxy (opt-in traffic interception, replay, TLS inspection) |
| **OOB** | interactsh-server (self-hosted out-of-band interaction server) |
| **OSINT** | NVD API (CVE lookup, CVSS scores), ExploitDB (exploit cross-reference, PoC availability) |
| **Payloads** | PayloadsAllTheThings (33,500+ community payloads via git submodule, 61 mapped categories) |
| **Infra** | Docker Compose, MCP Protocol (34+ tools), Playwright, APScheduler |

---

**sploit.ai v3** - *AI-Powered Autonomous Penetration Testing Platform*

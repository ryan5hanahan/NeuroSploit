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

sploit.ai v3 is a security assessment platform built around a single LLM-driven autonomous agent with 18 tools and a KNOW/THINK/TEST/VALIDATE cognitive framework. The agent operates inside per-scan isolated Kali Linux containers, governed by 2-layer scope and phase-action enforcement (6 profiles, 3 modes), with 3-tier LLM model routing across 6 providers, 100+ vulnerability types with 34,000+ payloads, 14 OSINT API clients, and a 21-page React dashboard with WebSocket real-time updates.

---

## Provenance

sploit.ai is a fork of [**NeuroSploit**](https://github.com/CyberSecurityUP/NeuroSploit) by **Joas Antonio dos Santos** (CyberSecurityUP). The original project was created on **August 17, 2025** and reached **v3.1** with 57 commits by February 11, 2026.

This fork was created on **February 13, 2026** from the v3.1 state. Since then, **148 commits** across **25 pull requests** have been made over 9 days, changing **331 files** with **56,675 insertions** and **13,503 deletions** (~43,000 net new lines of code). The codebase was rebranded from NeuroSploit to **sploit.ai**.

The two codebases have fully diverged and are not merge-compatible.

### What the Original NeuroSploit v3.1 Shipped

The upstream project provided a working foundation:

- **100 vulnerability types** across 10 tester categories
- **AutonomousAgent** — a 3-stream parallel pentest pipeline (recon + junior tester + tool runner) with code-driven phase progression
- **AIPentestAgent** — a secondary agent for prompt-driven assessments
- **Per-scan Kali Linux containers** with Docker isolation
- **Anti-hallucination pipeline** — negative controls, proof-of-execution, confidence scoring, validation judge
- **Exploit chain engine** — 10 rules for chaining findings (SSRF→internal, SQLi→DB-specific, etc.)
- **WAF detection** — 16 WAF signatures, 12 bypass techniques
- **Multi-provider LLM** — Claude, GPT, Gemini, Ollama, LM Studio, OpenRouter
- **React dashboard** with WebSocket real-time updates
- **MCP server** with 34+ tools (scanning, recon, ProjectDiscovery)
- **SQLAlchemy + SQLite** backend with FastAPI
- **Strategy adaptation** — dead endpoint detection, diminishing returns, confidence-based pivoting

### What This Fork Has Changed

Every major system has been rewritten, replaced, or substantially extended. The sections below detail each area.

---

## Table of Contents

- [Provenance](#provenance)
- [New: LLM-Driven Agent (Replaces Both Original Agents)](#new-llm-driven-agent-replaces-both-original-agents)
- [New: 2-Layer Governance System](#new-2-layer-governance-system)
- [New: Unified LLM Layer with 3-Tier Routing](#new-unified-llm-layer-with-3-tier-routing)
- [New: 14 OSINT API Clients](#new-14-osint-api-clients)
- [New: PayloadsAllTheThings Integration (33K+ Payloads)](#new-payloadsallthethings-integration-33k-payloads)
- [New: Swarm Sub-Agents and Dynamic Tool Creation](#new-swarm-sub-agents-and-dynamic-tool-creation)
- [New: Bug Bounty Support](#new-bug-bounty-support)
- [New: NVD and ExploitDB Enrichment](#new-nvd-and-exploitdb-enrichment)
- [New: Agent Observability and Cost Optimization](#new-agent-observability-and-cost-optimization)
- [New: Tradecraft TTP Library](#new-tradecraft-ttp-library)
- [New: ProjectDiscovery Suite, Opsec Profiles, mitmproxy](#new-projectdiscovery-suite-opsec-profiles-mitmproxy)
- [Extended: Vulnerability Engine (10→12 Categories, PATT Extended Types)](#extended-vulnerability-engine-1012-categories-patt-extended-types)
- [Extended: Frontend (21 Pages, Unified Agent UI)](#extended-frontend-21-pages-unified-agent-ui)
- [Extended: API (21 Routers, V1 Agent Retired)](#extended-api-21-routers-v1-agent-retired)
- [Inherited: Kali Sandbox System](#inherited-kali-sandbox-system)
- [Inherited: Anti-Hallucination and Validation Pipeline](#inherited-anti-hallucination-and-validation-pipeline)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Development](#development)
- [Security Notice](#security-notice)

---

## New: LLM-Driven Agent (Replaces Both Original Agents)

**PR #8, #10, #11, #12, #13** — The original codebase had two agents: `AutonomousAgent` (3-stream code-driven pipeline, ~7,600 lines) and `AIPentestAgent` (prompt-driven). Both have been **deleted** and replaced with a single `LLMDrivenAgent` (`backend/core/llm_agent.py`) where the LLM has full execution control.

### What Changed

| | Original (AutonomousAgent + AIPentestAgent) | Fork (LLMDrivenAgent) |
|--|---|---|
| **Control** | Code-driven pipeline with LLM advisory | LLM controls execution end-to-end |
| **Tools** | MCP tools (34+) via sandbox | 18 purpose-built tools with governance |
| **Reasoning** | Anti-hallucination prompts | KNOW/THINK/TEST/VALIDATE cognitive cycle |
| **Memory** | Bounded dedup memory | TF-IDF vector search, per-target persistence |
| **Planning** | Fixed phase progression | Dynamic plan lifecycle with checkpoints |
| **Sub-agents** | None | FAST-tier swarm sub-agents (max 3 concurrent) |
| **Dynamic tools** | None | Runtime Python tool creation with AST validation |
| **API** | `/api/v1/agent/*` (deleted) | `/api/v1/agent-v2/*` |

### 18 Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `shell_execute` | Execute shell commands in Docker sandbox (nmap, sqlmap, nuclei, etc.) |
| 2 | `http_request` | Send HTTP requests with full method/header/body control |
| 3 | `browser_navigate` | Navigate headless browser to URL with JS rendering |
| 4 | `browser_extract_links` | Extract all links from current browser page |
| 5 | `browser_extract_forms` | Extract forms with actions, methods, fields, hidden inputs |
| 6 | `browser_submit_form` | Fill in and submit forms, preserving hidden fields |
| 7 | `browser_screenshot` | Capture full-page screenshot for evidence |
| 8 | `browser_execute_js` | Execute JavaScript in browser context |
| 9 | `memory_store` | Store observations in persistent memory (6 categories) |
| 10 | `memory_search` | Search stored memories by keyword or semantic similarity |
| 11 | `save_artifact` | Save evidence files to operation artifacts directory |
| 12 | `report_finding` | Report confirmed vulnerability with evidence, CVSS, CWE, PoC |
| 13 | `update_plan` | Update operation plan at start and checkpoints |
| 14 | `get_payloads` | Retrieve payloads (526+ including PATT) with WAF bypass variants |
| 15 | `get_vuln_info` | Get CWE, severity, remediation from VulnerabilityRegistry |
| 16 | `spawn_subagent` | Spawn FAST-tier sub-agent for parallel recon |
| 17 | `create_tool` | Create custom tools at runtime with AST-validated Python |
| 18 | `stop` | Terminate operation with reason and summary |

Tools 6, 14–17 are **new to this fork** (original agent had 13 tools).

### Cognitive Framework

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
| **Discovery** | 0–25% | Port scan, service detection, tech fingerprinting, endpoint enumeration |
| **Hypothesis** | 25–50% | Identify high-value targets, form vulnerability hypotheses, prioritize |
| **Validation** | 50–80% | Test hypotheses with crafted requests, collect evidence, verify with controls |
| **Reporting** | 80–100% | Document confirmed findings, save artifacts, generate summary |

### Persistent Memory

- **TF-IDF vector search** with recency boosting (no external dependencies)
- **Per-target persistence** across operations — cross-engagement learning
- **6 categories**: recon, finding, credential, observation, hypothesis, evidence

### Quality Evaluation

Post-operation scoring across 5 dimensions (coverage 20%, efficiency 15%, evidence 30%, methodology 15%, reporting 20%).

---

## New: 2-Layer Governance System

**PR #2, #16, #24** — The original had no governance enforcement. This fork adds a 2-layer system controlled by a unified facade (`governance_facade.py`).

### Layer 1: Scope Enforcement (`governance.py`)

Controls **what** can be tested — domains, vulnerability types, phases, recon depth. Scope is immutable after scan creation.

| Profile | Use Case |
|---------|----------|
| **full_auto** | Comprehensive autonomous scanning — all phases, all vuln types |
| **vuln_lab** | Single-vulnerability testing — tight scope, no subdomain enum |
| **ctf** | Capture-the-flag challenges — all phases, all vuln types |
| **recon_only** | Reconnaissance without exploitation — recon phases only |
| **bug_bounty** | Bug bounty programs — scoped to program rules |
| **custom** | User-defined per-field configuration |

### Layer 2: Phase-Action Gating (`governance_gate.py`)

Controls **when** actions can happen — prevents exploitation during recon, blocks post-exploitation unless authorized.

**7 Action Categories** (least to most intrusive): `PASSIVE_RECON`, `ACTIVE_RECON`, `ANALYSIS`, `VULNERABILITY_SCAN`, `EXPLOITATION`, `POST_EXPLOITATION`, `REPORTING`

**9 Phases**: `initializing`, `passive_recon`, `recon`, `analyzing`, `testing`, `exploitation`, `full_auto`, `reporting`, `completed`

**3 Modes**: strict (block), warn (log + allow), off

### Additional Governance Features

- **Scope-aware prompts** — recon-scoped operations receive a dedicated execution prompt reinforcing recon-only behavior
- **GovernancePage** — frontend dashboard for viewing profiles and violations
- **WebSocket events** — real-time governance violation notifications
- **Audit trail** — all violations persisted to database with full context
- **69 unit tests** for the governance system

---

## New: Unified LLM Layer with 3-Tier Routing

**PR #3, #4** — The original used a monolithic `LLMManager` with flat model selection. This fork replaces it with a unified layer (`backend/core/llm/`) that provides 3-tier routing, native tool calling, structured JSON output, and per-session cost tracking.

### 3-Tier Model Routing

| Tier | Default Model | Use Case |
|------|--------------|----------|
| **Fast** | Claude Haiku 4.5 | Classification, formatting, simple extraction, log parsing |
| **Balanced** | Claude Sonnet 4.6 | Testing decisions, strategy, analysis, report generation |
| **Deep** | Claude Opus 4.5 | Exploit validation, chain analysis, zero-day research, threat modeling |

Per-tier model overrides via `LLM_MODEL_FAST`, `LLM_MODEL_BALANCED`, `LLM_MODEL_DEEP` env vars or the Settings UI.

### 6 Providers

| Provider | Authentication |
|----------|---------------|
| **Anthropic** | `ANTHROPIC_API_KEY` |
| **OpenAI** | `OPENAI_API_KEY` |
| **Google Gemini** | `GEMINI_API_KEY` |
| **AWS Bedrock** | AWS credential chain (new to this fork) |
| **Ollama** | Local (no key) |
| **LM Studio** | Local (no key) |

OpenRouter is supported via `OPENROUTER_API_KEY` routed through the OpenAI-compatible provider — there is no dedicated OpenRouter module.

### Cost Tracking

Per-session budget enforcement (default $5.00/scan), input/output token tracking per tier, warning at 80% utilization, tier-level breakdowns per scan. Agent operation cost was reduced ~50–60% in PR #20.

---

## New: 14 OSINT API Clients

**PR #21** + earlier commits — The original had no OSINT integration. This fork adds 14 clients in `backend/core/osint/`:

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

`aggregator.py` provides parallel multi-source queries across all clients.

---

## New: PayloadsAllTheThings Integration (33K+ Payloads)

**PR #5** — The original had 665 curated payloads. This fork integrates [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) as a git submodule, adding 33,500+ community-maintained payloads across 61 mapped categories.

- **Curated-first ordering** — original payloads tried first, PATT appended (deduplicated)
- **Available at all scan depths** — quick (3), standard (10), thorough (20), exhaustive (all)
- **19 new PATT-conditional vulnerability types** (account takeover, SAML injection, ReDoS, XSLT injection, etc.)
- **Parser pipeline** — extracts from Intruder wordlists and Markdown code blocks, filters prose and duplicates
- **Graceful degradation** — works without the submodule; `git submodule update --init` to enable

### Top Payload Counts

| Vuln Type | PATT Payloads |
|-----------|---------------|
| Path Traversal | 22,582 |
| LFI | 4,758 |
| XSS Reflected | 2,162 |
| Web Cache Deception | 1,125 |
| SQLi (all variants) | 1,537 |
| Command Injection | 491 |

---

## New: Swarm Sub-Agents and Dynamic Tool Creation

**PR #22** — Two new capabilities added to the LLM-driven agent:

### spawn_subagent

Spawns lightweight sub-agents for parallel reconnaissance:
- **FAST-tier** LLM routing (lowest cost)
- **Max 3 concurrent** sub-agents
- **120-second timeout** per sub-agent
- **Shared budget** — sub-agent steps count against the parent
- **Governance-checked** — inherits parent scope restrictions

### create_tool

Runtime Python tool creation for one-off analysis:
- **AST validation** — code parsed and validated before execution
- **Blocked modules**: `os`, `subprocess`, `sys`, `shutil`, `socket`, `ctypes`
- **Allowed modules**: `json`, `re`, `base64`, `urllib.parse`, `hashlib`, `html`, `math`, `collections`, `itertools`, `string`, `binascii`, `hmac`

---

## New: Bug Bounty Support

**PR #19** + earlier commits — The original had no bug bounty features. This fork adds:

- **BUG_BOUNTY governance profile** — scopes the agent to program rules
- **`bugbounty.py` API router** — CRUD endpoints for submission tracking
- **`BugBountySubmission` model** — SQLAlchemy persistence
- **`BugBountyPage.tsx`** — frontend page for managing submissions
- **Agent prompt injection** — bug bounty context injected into system prompt when BUG_BOUNTY profile is active
- **Multi-platform provider abstraction** — HackerOne integration with extensible provider pattern

---

## New: NVD and ExploitDB Enrichment

**PR #14** — The original had no vulnerability enrichment. This fork adds automated CVE and exploit cross-referencing:

- **NVD API** — CVSS scores, affected products (CPE), reference links
- **ExploitDB CSV** — exploit IDs, descriptions, PoC availability
- **Queue-based processing** — asynchronous to avoid blocking scans
- **Rate-limited** — respects NVD API limits
- **Batch support** — enrich all findings for a scan in one call

---

## New: Agent Observability and Cost Optimization

**PR #9, #20** — Two new systems:

### Observability

- **Decision logging** — every LLM reasoning step and tool call persisted to database
- **Decision log UI** — Steps tab in AgentDetailPage shows reasoning, tool calls, results
- **Two-tier reports** — summary (dashboard) + detailed (downloadable)
- **Plan persistence** — phases, confidence, quality evaluation stored in database
- **5-dimension quality evaluation** — coverage, efficiency, evidence, methodology, reporting

### Cost Optimization

- Agent operation cost reduced **~50–60%** through:
  - Phase-based tier routing (recon uses FAST tier, exploitation uses DEEP)
  - Tool result truncation to fit context budget
  - Sliding-window conversation trimming at 200K tokens
  - Parallel tool dispatch via `asyncio.gather` (max 8 concurrent)

---

## New: Tradecraft TTP Library

35 built-in TTP entries with CRUD UI and agent prompt injection:

- **23 LOLBin techniques** — Windows (10), Linux (10), macOS (3)
- **MITRE ATT&CK mapping** — technique IDs for each entry
- **Detection profiles** — probability across 8 vectors (AV, IDS, EDR, Heuristic, Sandbox, Traffic, Logs, Memory)
- **Agent integration** — tradecraft entries injected into agent prompts for operational awareness

---

## New: ProjectDiscovery Suite, Opsec Profiles, mitmproxy

**PR #1** — Three major additions in one PR:

### ProjectDiscovery Suite

20 Go tools pre-compiled in the Kali sandbox: nuclei, httpx, katana, subfinder, tlsx, asnmap, cvemap, mapcidr, alterx, shuffledns, cloudlist, interactsh-client, notify, and more. Each exposed as an MCP tool with structured output parsing.

### Opsec Profiles

Configurable operational security postures (stealth/balanced/aggressive) controlling per-tool rate limits, jitter, proxy routing, DNS-over-HTTPS, and header randomization. Defined in `config/opsec_profiles.json`.

| Setting | Stealth | Balanced (default) | Aggressive |
|---------|---------|-------------------|------------|
| **Request Jitter** | 500–3000ms | 100–500ms | None |
| **DNS-over-HTTPS** | Yes | No | No |
| **Proxy Routing** | Auto | Opt-in | Off |

### mitmproxy Integration

Opt-in HTTP/HTTPS traffic interception with 7 MCP tools (status, flows, capture, replay, intercept, clear, export). TLS interception supported with auto-installed CA certificates.

### interactsh OOB Server

Self-hosted out-of-band interaction server for blind vulnerability detection. Stealth profile auto-routes to self-hosted server.

---

## Extended: Vulnerability Engine (10→12 Categories, PATT Extended Types)

The original had 100 types across 10 tester categories. This fork adds 2 new tester modules and 19 PATT-conditional types:

### 12 Tester Categories

| Category | Module | Status |
|----------|--------|--------|
| `injection.py` | SQLi, NoSQLi, LDAP, XPath, command injection | Inherited |
| `advanced_injection.py` | SSTI, CRLF, header, log, GraphQL injection | Inherited |
| `auth.py` | Auth bypass, session fixation, credential stuffing | Inherited |
| `authorization.py` | BOLA, BFLA, IDOR, privilege escalation | Inherited |
| `client_side.py` | XSS, CORS, clickjacking, open redirect, DOM clobbering | Inherited |
| `cloud_supply.py` | Cloud metadata, S3 misconfig, dependency confusion | Inherited |
| `file_access.py` | LFI, RFI, path traversal, file upload, XXE | Inherited |
| `infrastructure.py` | SSL/TLS, HTTP methods, subdomain takeover | Inherited |
| `logic.py` | Business logic, race conditions, JWT, OAuth | Inherited |
| `request_forgery.py` | SSRF, CSRF, DNS rebinding | Inherited |
| **`data_exposure.py`** | Info disclosure, debug endpoints, source code exposure | **New** |
| **`deserialization.py`** | Insecure deserialization, Java RMI, GWT | **New** |

### 19 PATT Extended Types (New)

Account Takeover, Client-Side Path Traversal, Denial of Service, Dependency Confusion, DNS Rebinding, External Variable Modification, GWT Deserialization, Headless Browser Abuse, Java RMI Exploitation, LaTeX Injection, LLM Prompt Injection, ReDoS, Reverse Proxy Misconfiguration, SAML Injection, SSI Injection, Virtual Host Enumeration, Web Cache Deception, Cross-Site Leak (XS-Leak), XSLT Injection.

---

## Extended: Frontend (21 Pages, Unified Agent UI)

**PR #13, #17, #18** — The original had ~12 pages with separate V1 and V2 agent UIs. This fork consolidates to a single unified agent UI and adds 9 new pages:

| Page | Route | Status |
|------|-------|--------|
| HomePage | `/` | Redesigned (4-panel layout) |
| **AgentPage** | `/agent` | **New** (unified V1+V2) |
| **AgentDetailPage** | `/agent/:operationId` | **New** (decision log, re-run, compare) |
| VulnLabPage | `/vuln-lab` | Extended (CTF mode, PATT types) |
| TerminalAgentPage | `/terminal` | Migrated to UnifiedLLMClient |
| SandboxDashboardPage | `/sandboxes` | Inherited |
| ScanDetailsPage | `/scan/:scanId` | Inherited |
| SchedulerPage | `/scheduler` | Inherited |
| ReportsPage | `/reports` | Inherited |
| **ReportViewPage** | `/reports/:reportId` | **New** |
| SettingsPage | `/settings` | Extended (per-tier provider, model listing) |
| **CompareScanPage** | `/compare` | **New** |
| **PromptsPage** | `/prompts` | **New** |
| **TaskLibraryPage** | `/tasks` | **New** |
| **RealtimeTaskPage** | `/realtime` | **New** |
| **BugBountyPage** | `/bugbounty` | **New** |
| **GovernancePage** | `/governance` | **New** |
| **TradecraftPage** | `/tradecraft` | **New** |
| OperationsPage | `/operations` | Legacy (redirects to `/agent`) |
| OperationDetailPage | `/operations/:id` | Legacy (redirects to `/agent/:id`) |
| NewScanPage | `/scan/new` | Legacy (redirects to `/agent`) |

Theme system with sploit.ai branding added in PR #18.

---

## Extended: API (21 Routers, V1 Agent Retired)

The original had 19 API routers including `agent.py` (V1 agent control). This fork deletes `agent.py` and adds 4 new routers:

| Router | Status |
|--------|--------|
| `agent_v2.py` | Extended (V2 agent, sole agent API) |
| **`bugbounty.py`** | **New** — bug bounty submission CRUD |
| **`realtime.py`** | **New** — realtime interactive sessions |
| **`task_library.py`** | **New** — task preset management |
| `agent.py` | **Deleted** — V1 agent API removed entirely |
| *17 other routers* | Inherited (scans, dashboard, enrichment, governance, reports, etc.) |

---

## Inherited: Kali Sandbox System

Carried forward from the original with no major changes:

- **Per-scan isolated containers** — each scan in its own Kali Linux Docker container
- **38 pre-installed tools** (nuclei, naabu, httpx, nmap, sqlmap, subfinder, katana, etc.)
- **28 on-demand tools** — installed automatically when first requested
- **Container pool** — max 5 concurrent, 60-min TTL, orphan cleanup
- **Resource limits** — 2GB memory, 2 CPU cores per container

---

## Inherited: Anti-Hallucination and Validation Pipeline

Carried forward from the original with no major changes:

```
Finding Candidate
    ▼
┌─────────────────────┐
│ Negative Controls    │  Benign requests as controls (-60 if same response)
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Proof of Execution   │  25+ per-vuln-type proof methods
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ AI Interpretation    │  LLM with 17 composable anti-hallucination prompts
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Confidence Scorer    │  0-100 score (≥90 confirmed, ≥60 likely, <60 rejected)
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Validation Judge     │  Final verdict with adaptive learning
└─────────────────────┘
```

---

## Architecture

```
sploit.ai/
├── backend/
│   ├── api/v1/                          # 21 API routers
│   │   ├── agent_v2.py                  # LLM-Driven Agent (sole agent API)
│   │   ├── bugbounty.py                 # Bug bounty submissions [NEW]
│   │   ├── realtime.py                  # Realtime interactive sessions [NEW]
│   │   ├── task_library.py              # Task library CRUD [NEW]
│   │   ├── scans.py                     # Scan CRUD + pause/resume/stop
│   │   ├── dashboard.py                 # Stats + activity feed
│   │   ├── enrichment.py                # NVD/ExploitDB enrichment [NEW]
│   │   ├── governance.py                # Governance violations + stats [NEW]
│   │   ├── reports.py                   # Report generation
│   │   ├── settings.py                  # Runtime settings + per-tier config
│   │   └── ... (11 more routers)
│   ├── core/
│   │   ├── llm_agent.py                 # LLMDrivenAgent [NEW — sole agent]
│   │   ├── llm_agent_tools.py           # 18 tool schemas [NEW]
│   │   ├── governance.py                # Layer 1: Scope enforcement [NEW]
│   │   ├── governance_gate.py           # Layer 2: Phase-action gating [NEW]
│   │   ├── governance_facade.py         # Unified governance interface [NEW]
│   │   ├── llm/                         # Unified LLM layer [NEW]
│   │   │   ├── client.py               # UnifiedLLMClient
│   │   │   ├── router.py               # 3-tier ModelRouter
│   │   │   ├── providers/              # 6 providers (anthropic, openai, gemini, bedrock, ollama, lmstudio)
│   │   │   ├── cost_tracker.py         # Per-tier cost tracking
│   │   │   └── tool_executor.py        # Tool dispatch with governance
│   │   ├── tools/                       # 6 tool implementations
│   │   │   ├── shell_tool.py           # Docker sandbox shell
│   │   │   ├── browser_tool.py         # Playwright browser
│   │   │   ├── http_tool.py            # HTTP requests
│   │   │   ├── parallel_executor.py    # Parallel execution
│   │   │   ├── dynamic_tool.py         # Runtime tool creation [NEW]
│   │   │   └── swarm_tool.py           # Sub-agent spawning [NEW]
│   │   ├── osint/                       # 14 OSINT clients [NEW]
│   │   ├── memory/                      # TF-IDF vector memory + plan manager [NEW]
│   │   ├── prompts/                     # Cognitive prompt framework [NEW]
│   │   ├── observability/               # Operation metrics [NEW]
│   │   ├── vuln_engine/
│   │   │   ├── registry.py             # 100 base types (+ 19 PATT)
│   │   │   ├── payload_generator.py    # 34K+ payloads (PATT merged)
│   │   │   ├── patt/                   # PATT integration [NEW]
│   │   │   └── testers/                # 12 category modules (was 10)
│   │   ├── validation/                  # Anti-hallucination pipeline [inherited]
│   │   ├── chain_engine.py             # Exploit chaining [inherited]
│   │   └── waf_detector.py             # WAF detection [inherited]
│   ├── models/                          # 15 model files, 21 model classes
│   └── services/scan_service.py         # Scan orchestration
│
├── core/                                # MCP server, sandbox, opsec
│   ├── mcp_server.py                    # 34+ MCP tools
│   ├── kali_sandbox.py                  # Per-scan Kali containers
│   ├── opsec_manager.py                 # Opsec profiles [NEW]
│   └── container_pool.py               # Container pool coordinator
│
├── frontend/src/pages/                  # 21 page components (9 new)
├── config/config.json                   # 3-tier routing, sandbox, opsec config
├── vendor/PayloadsAllTheThings/         # PATT submodule [NEW]
└── requirements.txt
```

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository with submodules
git clone --recurse-submodules https://github.com/ryan5hanahan/sploitai.git
cd sploitai

# If already cloned without submodules
git submodule update --init

# Copy environment file and add your API keys
cp .env.example .env
nano .env  # Add at least one LLM API key

# Start all services
docker compose up -d
```

Access the web interface at **http://localhost:8080** (Docker) or **http://localhost:5173** (dev mode).

### Option 2: Manual Setup

```bash
git submodule update --init

# Backend
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend && npm install && npm run dev
```

### Optional Services

```bash
# mitmproxy for traffic interception
docker compose --profile proxy up -d

# interactsh for OOB testing
docker compose --profile oob up -d
```

---

## Configuration

### Environment Variables

```bash
# LLM API Keys (at least one required)
ANTHROPIC_API_KEY=your-key
OPENAI_API_KEY=your-key
GEMINI_API_KEY=your-key
OPENROUTER_API_KEY=your-key   # Routed through OpenAI-compatible provider

# AWS Bedrock (uses AWS credential chain)
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
```

---

## API Reference

### Base URL: `http://localhost:8000/api/v1`

#### LLM-Driven Agent (`/agent-v2`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/agent-v2/start` | Start LLM-driven assessment |
| `POST` | `/agent-v2/{id}/stop` | Stop running agent |
| `POST` | `/agent-v2/{id}/pause` | Pause agent |
| `POST` | `/agent-v2/{id}/resume` | Resume agent |
| `POST` | `/agent-v2/{id}/prompt` | Inject custom prompt |
| `GET` | `/agent-v2/{id}/status` | Get operation status |
| `GET` | `/agent-v2/{id}/findings` | Get findings |
| `GET` | `/agent-v2/{id}/decisions` | Get decision log |
| `GET` | `/agent-v2/operations` | List all operations |
| `POST` | `/agent-v2/{id}/report` | Generate report |

#### New Routers

| Router | Key Endpoints |
|--------|-------------|
| **Bug Bounty** (`/bugbounty`) | CRUD for submissions |
| **Task Library** (`/tasks`) | CRUD for task presets |
| **Realtime** (`/realtime`) | Start/message/stop interactive sessions |
| **Enrichment** (`/enrichment`) | NVD/ExploitDB enrichment per vuln or per scan |
| **Governance** (`/governance`) | Violations and stats per scan |

#### Inherited Routers

Scans, Dashboard, Reports, Scheduler, Sandbox, Vulnerability Lab, Terminal, Tradecraft, Memory, Traces, Targets, Prompts, Vulnerabilities, Settings — all carried forward from the original.

### WebSocket

```
ws://localhost:8000/ws/scan/{scan_id}           # Scan events
ws://localhost:8000/api/v1/agent-v2/{id}/ws     # Agent events (tool calls, findings, decisions)
```

### API Docs

- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

---

## Development

```bash
# Backend
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend && npm install && npm run dev

# Kali sandbox
./scripts/build-kali.sh --test

# MCP server
python3 -m core.mcp_server

# PATT payload library
git submodule update --init
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

The original NeuroSploit is also MIT licensed by Joas Antonio dos Santos.

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Python, FastAPI, SQLAlchemy, Pydantic, aiohttp |
| **Frontend** | React 18, TypeScript, TailwindCSS, Vite |
| **AI/LLM** | Anthropic Claude, OpenAI GPT, Google Gemini, AWS Bedrock, Ollama, LM Studio |
| **Sandbox** | Docker, Kali Linux, 20 ProjectDiscovery tools, Nmap, SQLMap |
| **OSINT** | Shodan, Censys, VirusTotal, SecurityTrails, BuiltWith, NVD, ExploitDB, ZoomEye, FOFA, PublicWWW, GitHub Dork, GrayhatWarfare, HIBP, DeHashed |
| **Payloads** | PayloadsAllTheThings (33,500+ payloads, 61 mapped categories) |
| **Proxy** | mitmproxy (opt-in interception, replay, TLS inspection) |
| **OOB** | interactsh-server (self-hosted out-of-band testing) |
| **Infra** | Docker Compose, MCP Protocol (34+ tools), Playwright, APScheduler |

---

**sploit.ai v3** — Fork of [NeuroSploit](https://github.com/CyberSecurityUP/NeuroSploit) by Joas Antonio dos Santos, with 148 commits of new architecture, governance, OSINT, and agent capabilities.

# Agent Architecture

## Overview

Two distinct agent implementations serve different execution paths. BaseAgent runs synchronously for CLI usage and is not included in Docker containers. AutonomousAgent runs asynchronously within the FastAPI backend for web UI scans.

## BaseAgent (CLI Path)

File: `agents/base_agent.py`

### Purpose

Command-line security testing agent driven by `config.json` agent role definitions. Performs autonomous discovery, AI-driven attack planning, adaptive exploitation, and report generation -- all orchestrated through LLM prompts and subprocess tool execution.

### Constructor

```python
BaseAgent(agent_name: str, config: Dict, llm_manager: LLMManager, context_prompts: Dict)
```

- `agent_name` -- Key into `config['agent_roles']` (e.g. `"pentest_generalist"`, `"bug_bounty_hunter"`)
- `config` -- Full config dict (not just `{"llm": ...}`) since model routing wiring
- `llm_manager` -- LLMManager instance for LLM calls (uses `task_type` param for model routing)
- `context_prompts` -- Dict with `system_prompt` and other prompt templates

Reads from `config['agent_roles'][agent_name]`:
- `tools_allowed` -- List of allowed tool names
- `description` -- Agent role description
- `methodology` -- Testing methodology list (OWASP-WSTG, PTES, etc.)

### Feature Integration

**Knowledge Augmentation** (opt-in):
- Reads `ENABLE_KNOWLEDGE_AUGMENTATION` env var
- Initializes `KnowledgeAugmentor` from `core/knowledge_augmentor.py`
- Dataset path from `config['knowledge_augmentation']['dataset_path']` (default: `models/bug-bounty/bugbounty_finetuning_dataset.json`)
- Wired into `_ai_analyze_context()` -- injects bug bounty patterns into LLM prompts for XSS, SQLi, SSRF, and detected vuln types

**MCP Client** (opt-in):
- Reads `config['mcp_servers']['enabled']`
- Initializes `MCPToolClient` from `core/mcp_client.py`
- `run_mcp_tool(tool_name, arguments)` tries MCP first, returns None for subprocess fallback

**Browser Validation** (opt-in):
- Reads `ENABLE_BROWSER_VALIDATION` env var
- `run_browser_validation(finding_id, url, payload)` calls `validate_finding_sync()` from `core/browser_validator.py`
- Screenshots saved to `reports/screenshots/{agent_name}/`

### State

```python
self.discovered_endpoints = []  # URLs found during discovery
self.discovered_params = []     # Parameter names found
self.discovered_forms = []      # Form action URLs and input names
self.tech_stack = {}            # Detected technologies
self.vulnerabilities = []       # Confirmed vulnerability dicts
self.interesting_findings = []  # Notable non-vuln findings
self.tool_history = []          # All command execution results
```

### Execution Flow

`execute(user_input, campaign_data=None, recon_context=None)` is the main entry point.

**With recon_context** (adaptive mode via `_execute_with_context`):
1. Phase 1: AI analyzes context sufficiency -- LLM determines if available recon data covers user's request
2. Phase 2: Fill gaps -- runs tools (curl, nmap) for missing data (XSS, SQLi, LFI, SSRF, RCE, crawling, port scanning)
3. Phase 3: Final AI analysis -- LLM generates comprehensive report from all collected data

**Without recon_context** (legacy mode via `_autonomous_assessment`):
1. Phase 1: Discovery -- `_discover_attack_surface()` via curl: base response, headers, links, forms, parameters, common files (robots.txt, .git/config, .env, etc.), technology detection
2. Phase 2: AI attack surface analysis -- LLM generates 20+ targeted curl commands
3. Phase 3: Adaptive exploitation loop -- up to 10 iterations of LLM analyzing results and generating follow-up tests. Stops on `[DONE]` response.
4. Phase 4: Deep exploitation -- for each confirmed vuln, LLM generates 5 deeper exploitation commands

### Tool Execution

```python
run_command(tool: str, args: str, timeout: int = 60) -> Dict
```

- Resolves tool path from `config['tools']` or `shutil.which()`
- Executes via `subprocess.run(shell=True)` with timeout
- Output capped at 8000 chars
- Results appended to `self.tool_history`

### Vulnerability Detection

`_check_vuln_indicators(result)` scans command output for regex patterns:

| Type | Patterns |
|------|----------|
| SQL Injection | `mysql.*error`, `syntax.*error.*sql`, `odbc.*driver`, `ora-\d{5}`, etc. |
| XSS | `<script>alert`, `onerror=alert`, `<svg.*onload` |
| LFI | `root:x:0:0`, `[boot loader]`, `<?php` |
| Information Disclosure | `phpinfo()`, `stack.*trace`, `debug.*mode` |

### AI Command Parsing

`_parse_ai_commands(response)` extracts commands from LLM output using two patterns:
- `[EXEC] tool: arguments` -- exploitation loop format
- `[TEST] curl arguments` -- attack planning format

Allowed tools: `curl`, `nmap`, `sqlmap`, `nikto`, `nuclei`, `ffuf`, `gobuster`, `whatweb`

### NOT Included in Docker

The `agents/` directory is **not** copied into Docker containers. BaseAgent is CLI-only. The web UI uses AutonomousAgent instead.

---

## AutonomousAgent (Web Path)

File: `backend/core/autonomous_agent.py`

### Purpose

Async AI-powered security testing agent for the web UI scan workflow. Multi-turn vulnerability discovery with finding persistence, real-time WebSocket updates, and a 12-engine verification pipeline to minimize false positives.

### Operation Modes

```python
class OperationMode(Enum):
    RECON_ONLY = "recon_only"
    FULL_AUTO = "full_auto"
    PROMPT_ONLY = "prompt_only"
    ANALYZE_ONLY = "analyze_only"
    AUTO_PENTEST = "auto_pentest"
```

### Constructor

Takes:
- `target_url` -- URL to test
- `mode` -- OperationMode
- Async callbacks: `log_callback`, `progress_callback`, `finding_callback`
- `auth_headers` -- Optional auth headers dict
- `custom_prompt` -- Optional user-provided prompt
- `lab_context` -- Optional vuln lab scope constraints
- `governance` -- GovernanceAgent instance for scope enforcement

### LLM Client (Embedded)

`LLMClient` class inside `autonomous_agent.py` handles direct provider SDK calls:
- **Claude**: `anthropic.Anthropic` SDK
- **OpenAI**: `openai.OpenAI` SDK
- **Gemini**: HTTP API via `GEMINI_URL`
- **Bedrock**: `boto3.client('bedrock-runtime')` with extended thinking support
- **Ollama**: HTTP API to `localhost:11434`
- **LM Studio**: HTTP API to `localhost:1234`

Provider selection order: `DEFAULT_LLM_PROVIDER` preferred, then fallback through `claude -> openai -> gemini -> bedrock -> ollama -> lmstudio`.

Per-provider model override via `DEFAULT_LLM_MODEL` env var.

`MAX_OUTPUT_TOKENS` env var controls default max tokens (fallback: 4096).

### Component Stack (12 Engines)

| # | Component | File | Purpose |
|---|-----------|------|---------|
| 1 | VulnerabilityRegistry | `vuln_engine/registry.py` | 100+ vulnerability type definitions across 11 categories |
| 2 | PayloadGenerator | `vuln_engine/payload_generator.py` | Test payload generation per vulnerability type |
| 3 | ResponseVerifier | `response_verifier.py` | Response analysis for vulnerability indicators |
| 4 | NegativeControlEngine | `negative_control.py` | Baseline requests to reduce false positives |
| 5 | ProofOfExecution | `proof_of_execution.py` | Evidence collection for confirmed findings |
| 6 | ConfidenceScorer | `confidence_scorer.py` | Multi-signal confidence scoring (0-100) |
| 7 | ValidationJudge | `validation_judge.py` | Final pass/fail decision on findings |
| 8 | AccessControlLearner | `access_control_learner.py` | Auth pattern learning during scan |
| 9 | RequestEngine | `request_engine.py` | HTTP execution with error classification (`ErrorType` enum) |
| 10 | WAFDetector | `waf_detector.py` | WAF detection and identification |
| 11 | StrategyAdapter | `strategy_adapter.py` | Strategy adjustment based on WAF presence and errors |
| 12 | ChainEngine | `chain_engine.py` | Multi-step exploit chains |

### Optional Integrations

| Component | Condition | Purpose |
|-----------|-----------|---------|
| BrowserValidator | `ENABLE_BROWSER_VALIDATION` + Playwright installed | Playwright-based DOM testing and screenshot capture |
| ReconIntegration | `HAS_RECON_INTEGRATION` | Enhanced recon with Go security tools |
| SandboxManager | `HAS_SANDBOX` + Docker available | Docker container-based tool execution |
| MCPToolClient | `HAS_MCP_CLIENT` | MCP tool server client for tool invocation |
| AgentMemory | `ENABLE_PERSISTENT_MEMORY` | Cross-scan learning from attack patterns, target fingerprints, successful payloads |
| AuthManager | Always | Manages auth headers and session state |

### Data Classes

```python
@dataclass
class Finding:
    id: str
    title: str
    severity: str
    vulnerability_type: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    description: str
    affected_endpoint: str
    parameter: str
    payload: str
    evidence: str
    request: str
    response: str
    impact: str
    poc_code: str
    remediation: str
    references: List[str]
    screenshots: List[str]
    affected_urls: List[str]
    ai_verified: bool
    confidence: str          # "0"-"100"
    confidence_score: int    # 0-100
    confidence_breakdown: Dict
    proof_of_execution: str
    negative_controls: str
    ai_status: str           # "confirmed" | "rejected" | "pending"
    rejection_reason: str

@dataclass
class ReconData:
    subdomains: List[str]
    live_hosts: List[str]
    endpoints: List[Dict]
    parameters: Dict[str, List[str]]
    technologies: List[str]
    forms: List[Dict]
    js_files: List[str]
    api_endpoints: List[str]
    ports: List[str]
    dns_records: List[str]
    urls: List[str]
    interesting_paths: List[Dict]
    secrets: List[str]
    waf_info: Optional[Dict]
    recon_depth: str         # "basic"
```

### Context Manager

Implements `async with` for proper resource cleanup:
- Closes browser (BrowserValidator)
- Shuts down sandbox containers
- Disconnects MCP connections

### Key Differences from BaseAgent

| Aspect | BaseAgent | AutonomousAgent |
|--------|-----------|-----------------|
| Runtime | Synchronous | Async (asyncio) |
| Execution | CLI (`agents/base_agent.py`) | Web UI (`backend/core/autonomous_agent.py`) |
| LLM calls | Via LLMManager (uses `task_type` routing) | Direct provider SDK (anthropic/openai/boto3) |
| Finding storage | In-memory `self.vulnerabilities` list | DB persistence via async callbacks |
| Real-time updates | Print statements to stdout | WebSocket via `log_callback`, `progress_callback` |
| Docker | Not included in container | Included in container |
| Feature toggles | Env vars on init | Env vars on init |
| Verification | Regex pattern matching | 12-engine pipeline (negative controls, confidence scoring, validation judge) |
| Tool execution | `subprocess.run` | `aiohttp` + optional sandbox Docker exec |

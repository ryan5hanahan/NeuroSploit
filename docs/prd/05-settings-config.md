# Settings and Configuration

## Overview

sploit.ai uses a two-layer configuration system:

1. **Static configuration** (`config/config.json`): Defines LLM profiles, agent roles, methodologies, tool paths, MCP server configuration, OPSEC profiles, sandbox settings, and model routing rules. Read at startup and used as structural configuration.

2. **Dynamic settings** (API/UI): Feature toggles, runtime options, LLM provider selection, and API keys. Persisted to three layers (in-memory dict, `os.environ`, and `.env` file) and configurable at runtime through the Settings UI or API.

## config.json Structure

Located at `config/config.json`. This file defines the structural configuration for the platform.

### llm

LLM provider profiles. Each profile defines a provider, model, API key (supports `${ENV_VAR}` interpolation), and generation parameters.

```json
{
  "default_profile": "gemini_pro_default",
  "profiles": {
    "gemini_pro_default": {
      "provider": "gemini",
      "model": "gemini-pro",
      "api_key": "${GEMINI_API_KEY}",
      "temperature": 0.7,
      "max_tokens": 4096,
      "input_token_limit": 30720,
      "output_token_limit": 2048,
      "cache_enabled": true,
      "search_context_level": "medium",
      "pdf_support_enabled": true,
      "guardrails_enabled": true,
      "hallucination_mitigation_strategy": "consistency_check"
    },
    "bedrock_claude_default": {
      "provider": "bedrock",
      "model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
      "region": "us-east-1",
      "temperature": 0.7,
      "max_tokens": 4096,
      "input_token_limit": 200000,
      "output_token_limit": 4096,
      "extended_thinking": true,
      "thinking_budget_tokens": 10000,
      "hallucination_mitigation_strategy": "self_reflection"
    }
  }
}
```

### agent_roles

Defines agent behavior profiles. Each role specifies allowed tools, description, methodology references, vulnerability coverage percentage, and prompt configuration.

| Role | Description |
|------|-------------|
| `pentest_generalist` | Comprehensive penetration testing across domains. Tools: nmap, metasploit, burpsuite, sqlmap, hydra. Methodologies: OWASP-WSTG, PTES, OWASP-Top10-2021 |
| `bug_bounty_hunter` | Web application vulnerability focus with 100 vuln types. Tools: subfinder, nuclei, burpsuite, sqlmap. Methodologies: OWASP-WSTG, OWASP-Top10-2021 |

### methodologies

Boolean flags for enabled testing methodologies: `owasp_top10`, `cwe_top25`, `network_pentest`, `ad_pentest`, `web_security`.

### tools

File system paths to security tools: `nmap`, `metasploit`, `burpsuite`, `sqlmap`, `hydra`.

### mcp_servers

MCP (Model Context Protocol) server configuration. The `sploitai_tools` server exposes pentest tools via direct transport:

```json
{
  "enabled": true,
  "servers": {
    "sploitai_tools": {
      "transport": "direct",
      "args": ["-m", "core.mcp_server"],
      "description": "sploit.ai pentest tools: screenshots, payload delivery, DNS, port scan, tech detect, subdomain enum, findings, AI prompts, sandbox execution, full ProjectDiscovery suite, mitmproxy integration, opsec profiles"
    }
  }
}
```

### opsec

OPSEC (Operational Security) configuration. References an external profiles file and sets the default profile.

```json
{
  "default_profile": "balanced",
  "profiles_file": "config/opsec_profiles.json"
}
```

### sandbox

Docker-based security tool sandbox configuration:

| Setting | Description |
|---------|-------------|
| `kali.image` | Docker image name (`sploitai-kali:latest`) |
| `kali.max_concurrent` | Maximum concurrent containers (5) |
| `kali.container_ttl_minutes` | Container lifetime before auto-cleanup (60 min) |
| `kali.auto_cleanup_orphans` | Auto-remove orphaned containers |
| `resources.memory_limit` | Container memory limit (`2g`) |
| `resources.cpu_limit` | Container CPU limit (2.0) |
| `tools` | List of 30+ installed security tools (nuclei, naabu, nmap, httpx, subfinder, katana, dnsx, ffuf, gobuster, dalfox, nikto, sqlmap, whatweb, curl, dig, whois, masscan, dirsearch, wfuzz, arjun, wafw00f, waybackurls, interactsh-client, cvemap, alterx, shuffledns, mapcidr, asnmap, tlsx, cloudlist, notify, massdns) |
| `nuclei.rate_limit` | Nuclei requests per second (150) |
| `nuclei.timeout` | Nuclei scan timeout in seconds (600) |
| `nuclei.severity_filter` | Nuclei severity filter (`critical,high,medium`) |
| `nuclei.auto_update_templates` | Auto-update nuclei templates |
| `naabu.rate` | Naabu scan rate (1000) |
| `naabu.top_ports` | Naabu top ports to scan (1000) |
| `naabu.timeout` | Naabu scan timeout in seconds (300) |

### model_routing

Task-based model routing configuration:

```json
{
  "enabled": false,
  "routes": {
    "reasoning": "bedrock_claude_default",
    "analysis": "gemini_pro_default",
    "generation": "gemini_pro_default",
    "validation": "gemini_pro_default",
    "default": "gemini_pro_default"
  }
}
```

Routes reasoning tasks to Bedrock Claude (extended thinking enabled) and analysis/generation/validation tasks to Gemini Pro. Only active when the `ENABLE_MODEL_ROUTING` toggle is enabled.

### output

Output format settings: `format` (json), `verbose` (true), `save_artifacts` (true).

## Feature Toggles

Eight boolean feature toggles are available through the Settings UI and API:

| Toggle | Env Variable | Default | Description |
|--------|-------------|---------|-------------|
| Model Routing | `ENABLE_MODEL_ROUTING` | `false` | Route LLM calls to different providers based on task type (reasoning vs. analysis vs. generation vs. validation) |
| Knowledge Augmentation | `ENABLE_KNOWLEDGE_AUGMENTATION` | `false` | Augment vulnerability testing with context from the bug bounty fine-tuning dataset (1,826 entries) |
| Browser Validation | `ENABLE_BROWSER_VALIDATION` | `false` | Use Playwright/Chromium for browser-based validation (DOM XSS, screenshots, hidden pages) |
| Extended Thinking | `ENABLE_EXTENDED_THINKING` | `false` | Enable Claude's extended thinking mode for deeper analysis (requires Bedrock or Anthropic provider) |
| Aggressive Mode | `AGGRESSIVE_MODE` | `false` | Increase testing depth ("thorough") and payload limit (15 vs 5) |
| Tracing | `ENABLE_TRACING` | `false` | Enable execution tracing and logging of agent decisions |
| Persistent Memory | `ENABLE_PERSISTENT_MEMORY` | `true` | Enable persistent memory across agent sessions |
| Bug Bounty Integration | `ENABLE_BUGBOUNTY_INTEGRATION` | `false` | Enable HackerOne bug bounty platform integration |

## Runtime Settings

Non-boolean runtime settings configurable via the API:

| Setting | Env Variable | Default | Description |
|---------|-------------|---------|-------------|
| LLM Provider | `DEFAULT_LLM_PROVIDER` | Auto-detected | Active LLM provider: `claude`, `openai`, `gemini`, `bedrock`, `openrouter`, `ollama` |
| LLM Model | `DEFAULT_LLM_MODEL` | Provider default | Specific model name override |
| Max Concurrent Scans | `MAX_CONCURRENT_SCANS` | `3` | Maximum simultaneous running scans |
| Default Scan Type | `DEFAULT_SCAN_TYPE` | `full` | Default scan type when client doesn't specify: `quick`, `full`, `custom` |
| Recon Enabled by Default | `RECON_ENABLED_BY_DEFAULT` | `true` | Default recon phase toggle when client doesn't specify |
| Max Output Tokens | `MAX_OUTPUT_TOKENS` | Provider default | Override max output tokens for LLM responses |
| AWS Bedrock Region | `AWS_BEDROCK_REGION` | `us-east-1` | AWS region for Bedrock API calls |
| AWS Bedrock Model | `AWS_BEDROCK_MODEL` | (empty) | Specific Bedrock model ID override |

## API Keys

### LLM Provider Keys
| Key | Env Variable | Description |
|-----|-------------|-------------|
| Anthropic | `ANTHROPIC_API_KEY` | Claude API key |
| OpenAI | `OPENAI_API_KEY` | GPT API key |
| OpenRouter | `OPENROUTER_API_KEY` | OpenRouter API key (access to any model) |
| AWS Access Key | `AWS_ACCESS_KEY_ID` | AWS IAM access key for Bedrock |
| AWS Secret Key | `AWS_SECRET_ACCESS_KEY` | AWS IAM secret key for Bedrock |
| AWS Session Token | `AWS_SESSION_TOKEN` | AWS temporary session token (optional) |

### OSINT API Keys
| Key | Env Variable | Description |
|-----|-------------|-------------|
| Shodan | `SHODAN_API_KEY` | Shodan internet device search |
| Censys ID | `CENSYS_API_ID` | Censys internet scan platform |
| Censys Secret | `CENSYS_API_SECRET` | Censys API secret |
| VirusTotal | `VIRUSTOTAL_API_KEY` | VirusTotal file/URL analysis |
| BuiltWith | `BUILTWITH_API_KEY` | BuiltWith technology profiling |

### Bug Bounty Platform
| Key | Env Variable | Description |
|-----|-------------|-------------|
| HackerOne Token | `HACKERONE_API_TOKEN` | HackerOne API token |
| HackerOne Username | `HACKERONE_USERNAME` | HackerOne username |

## Persistence Pattern

Settings follow a three-layer persistence pattern:

1. **UI Toggle** (frontend): User clicks a toggle in the Settings page
2. **API Call**: `PUT /api/v1/settings` with the updated setting
3. **Three-layer write**:
   - **In-memory dict** (`_settings`): Immediate runtime effect
   - **`os.environ`**: Available to all Python code via `os.getenv()` for the current process
   - **`.env` file**: Persists across server restarts

On server startup, `_load_settings_from_env()` reads the `.env` file (using `python-dotenv`) and populates the `_settings` dict from environment variables. This ensures settings survive restarts.

The `.env` file updater (`_update_env_file()`) handles:
- Updating existing key=value lines (including commented-out lines)
- Appending new keys that don't exist in the file
- Preserving comments and blank lines
- Sanitizing values to prevent newline injection attacks (removes `\n`, `\r`, `\0`, wraps special characters in quotes)

### Provider Auto-detection
If no `DEFAULT_LLM_PROVIDER` is set, the system auto-detects the provider based on which API keys are present, in this priority order:
1. `ANTHROPIC_API_KEY` present: `claude`
2. `OPENAI_API_KEY` present: `openai`
3. `OPENROUTER_API_KEY` present: `openrouter`
4. `AWS_ACCESS_KEY_ID` or `AWS_PROFILE` present: `bedrock`
5. Fallback: `claude`

## Settings API

### Get Current Settings
```
GET /api/v1/settings
```
Returns current settings state. Secrets are masked -- API keys are returned as boolean `has_*_key` flags rather than actual values.

### Update Settings
```
PUT /api/v1/settings
```
Accepts a `SettingsUpdate` body with any combination of settings fields. Only provided fields are updated. Persists to all three layers.

### Test LLM Connection
```
POST /api/v1/settings/test-llm
```
Tests the currently configured LLM provider by sending a simple prompt and verifying a response is received. Returns success/failure with error details.

### Clear Database
```
POST /api/v1/settings/clear-database
```
Deletes all scan data, findings, reports, and challenge records from the database. Resets the system to a clean state. Does not affect settings or API keys.

### Get Statistics
```
GET /api/v1/settings/stats
```
Returns database statistics: total scans, total findings by severity, total reports, total endpoints.

### Check Installed Tools
```
GET /api/v1/settings/tools
```
Checks which security tools are installed and available on the system. Returns a list of tool names with their installation status and version (when available). Used by the frontend to show which tools are available in the current deployment.

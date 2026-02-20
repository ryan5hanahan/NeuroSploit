# Security

## Overview

Security measures for credential handling, input sanitization, scope enforcement, container isolation, and operational security (OPSEC) proxy integration.

## Credential Handling

### API Key Storage

- API keys stored in `.env` file and loaded via `pydantic_settings` (`BaseSettings` with `env_file = ".env"`)
- In-memory `_settings` dict in the Settings API holds runtime values
- Settings API (`backend/api/v1/settings.py`) never returns raw API keys -- uses `has_X_key` boolean flags instead

### .env File Protection

`_sanitize_env_value(value)` applied to all values written to `.env`:
- Strips `\n`, `\r`, `\0` characters to prevent newline injection (which could create extra `KEY=VALUE` lines)
- Values containing spaces, quotes, `#`, `=`, `$`, or backticks are wrapped in escaped double quotes

`_update_env_file(updates)` handles `.env` file updates:
- Matches existing keys (including commented-out `# KEY=...` lines) via regex
- Replaces with uncommented `KEY=sanitized_value`
- Appends new keys not found in existing file
- Preserves comments and blank lines
- Writes back with trailing newline

### Scan Credential Redaction

`Scan._redact_credentials(creds)` in `backend/models/scan.py`:
- Applied in `Scan.to_dict()` before API serialization
- Values longer than 4 characters: `first2chars****last2chars` (e.g. `"se****et"`)
- Values 4 characters or shorter: fully masked as `"***"`

```python
@staticmethod
def _redact_credentials(creds: dict) -> dict:
    if not creds:
        return {}
    redacted = {}
    for key, value in creds.items():
        if isinstance(value, str) and len(value) > 4:
            redacted[key] = value[:2] + "*" * (len(value) - 4) + value[-2:]
        else:
            redacted[key] = "***"
    return redacted
```

## Input Validation

### .env Injection Prevention

The `_sanitize_env_value()` function prevents a class of attacks where injected newlines in a value could create additional `KEY=VALUE` lines in the `.env` file:

```python
def _sanitize_env_value(value: str) -> str:
    sanitized = value.replace("\n", "").replace("\r", "").replace("\0", "")
    if any(c in sanitized for c in (" ", "'", '"', "#", "=", "$", "`")):
        sanitized = '"' + sanitized.replace('"', '\\"') + '"'
    return sanitized
```

### Scan Creation

- Target URLs parsed via `urlparse` -- hostname, port, protocol extracted and stored separately
- Tradecraft IDs validated against database before association with scans
- Scan type validated against allowed values (`quick`, `full`, `custom`)
- Auth credentials stored as JSON but redacted in all API responses

## Governance Agent

File: `backend/core/governance.py`

The `GovernanceAgent` enforces scope boundaries for all agent operations at the data level, not just the prompt level.

### Scope Creation Methods

- `create_vuln_lab_scope()` -- Restricts agent to a single target URL and specific vulnerability type. Maps vulnerability types to allowed Nuclei template tags.
- `create_ctf_scope()` -- Broader scope for CTF testing. Allows multiple attack techniques against a single target.

### Enforcement

- Validates all HTTP request URLs against the scope's allowed domains/paths
- Restricts Nuclei template tags to those relevant for the scoped vulnerability type
- Consulted via method calls by the AutonomousAgent before each operation

### Vulnerability Type Mapping

Maps 60+ internal vulnerability types (e.g. `sqli_error`, `xss_reflected`, `ssrf`) to Nuclei template tags (e.g. `sqli`, `xss`, `ssrf`) for constrained tool execution.

## OPSEC Proxy

### Configuration

File: `config/opsec_profiles.json`

Three profiles:

| Profile | Request Jitter | User Agent | DNS-over-HTTPS | Proxy Routing | Header Randomization |
|---------|---------------|------------|----------------|---------------|---------------------|
| **stealth** | 500-3000ms | Random | Yes | Auto | Yes |
| **balanced** | 100-500ms | Random | No | Opt-in | No |
| **aggressive** | 0ms | Random | No | Off | No |

Each profile also defines per-tool rate limits and concurrency settings for: nuclei, naabu, httpx, katana, nmap, dnsx, ffuf, tlsx, shuffledns, interactsh-client, subfinder.

### Proxy Integration

- mitmproxy runs as a Docker Compose service (profile: `proxy`)
- Sandbox containers route through mitmproxy when the OPSEC profile's `proxy_routing` is `"auto"` or `"opt-in"`
- Proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`) set to `http://sploitai-mitmproxy:8081` via `_get_proxy_env()` in `core/sandbox_manager.py`
- MCP server exposes 7 proxy tools: `proxy_status`, `proxy_flows`, `proxy_capture`, `proxy_replay`, `proxy_intercept`, `proxy_clear`, `proxy_export`

## Container Isolation (Sandbox)

File: `core/sandbox_manager.py`

### Architecture

- Persistent sandbox container (`sploitai-sandbox`) runs on `sploitai-network`
- Tools executed via `docker exec` for sub-second startup (no container creation per command)
- Output collected from container stdout + output files

### Resource Limits

| Limit | Value |
|-------|-------|
| Memory | 2G |
| CPU | 2.0 |
| Container TTL | 60 minutes (configurable) |
| Max concurrent containers | 5 |

### Lifecycle

- Auto-cleanup of orphan containers on backend startup
- Container health monitoring
- Network isolation with controlled egress (via `sploitai-network`)

### Docker SDK

Uses the Python `docker` SDK (guarded import -- features degrade gracefully when Docker is unavailable):
```python
try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
```

## Exception Handling

- Production code uses specific exception types instead of bare `except:` blocks
- Error messages are logged but stack traces are not exposed in API responses
- LLM API call errors return user-friendly messages:
  - 401/403: "Authentication failed" / "Access denied"
  - Timeout: "Connection timed out"
  - Connection refused: "Is the provider endpoint reachable?"

## Feature Degradation

The system gracefully degrades when optional components are unavailable:

| Component | Guard | Effect when missing |
|-----------|-------|-------------------|
| Playwright | `HAS_PLAYWRIGHT` import guard | Browser validation disabled |
| Docker SDK | `HAS_DOCKER` import guard | Sandbox features disabled |
| MCP package | `HAS_MCP` import guard | MCP server/client disabled |
| Recon tools | `HAS_RECON_INTEGRATION` import guard | Enhanced recon disabled |
| anthropic SDK | `ANTHROPIC_AVAILABLE` import guard | Claude provider unavailable |
| openai SDK | `OPENAI_AVAILABLE` import guard | OpenAI provider unavailable |
| boto3 SDK | `BOTO3_AVAILABLE` import guard | Bedrock provider unavailable |

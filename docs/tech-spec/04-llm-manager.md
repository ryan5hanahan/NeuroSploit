# LLM Manager

## Overview
Unified interface for multiple LLM providers. Manages profiles, API keys, token limits, prompt loading, optional model routing, hallucination mitigation, and guardrails.

## Class: LLMManager
File: `core/llm_manager.py`

### Constructor
```python
LLMManager(config: Optional[Dict] = None, _routing_disabled: bool = False)
```
- `config`: Full application config dict. Must contain `'llm'` key for profile configuration. May contain `'model_routing'` for task-based routing. Defaults to `{}` when not provided.
- `_routing_disabled`: Internal flag to prevent recursive router creation. Set to `True` for child instances created by `ModelRouter` profile factory.

### Initialization Flow
1. Store full config as `_full_config`, extract `config['llm']` as `self.config`
2. Load default profile name from `llm.default_profile` (default: `'gemini_pro_default'`)
3. Load profile dict from `llm.profiles[default_profile_name]`
4. Extract from active profile: `provider`, `model`, `api_key`, `temperature` (default 0.7), `max_tokens` (default 4096)
5. Resolve API key: if string matches `${ENV_VAR}` syntax, read from `os.getenv(ENV_VAR)`
6. Load extended profile settings: `input_token_limit`, `output_token_limit`, `cache_enabled`, `search_context_level`, `pdf_support_enabled`, `guardrails_enabled`, `hallucination_mitigation_strategy`
7. Initialize `_mitigation_lock` (threading.Lock) for thread-safe hallucination mitigation
8. Apply `MAX_OUTPUT_TOKENS` env override if set (overrides both `max_tokens` and `output_token_limit`)
9. Initialize tracer hook slot (`_tracer_hook = None`)
10. If not `_routing_disabled`: call `_init_model_router()` to set up task-based routing
11. Load prompts from `prompts/library.json` (JSON) and `prompts/` + `prompts/md_library/` (Markdown files with `## User Prompt` / `## System Prompt` sections)

### Provider Support

| Provider | API Method | Key Env Var | Default Model | Notes |
|----------|-----------|-------------|---------------|-------|
| claude | HTTP POST to `api.anthropic.com/v1/messages` via `requests` | ANTHROPIC_API_KEY | claude-sonnet-4-5-20250929 | Extended thinking support via `anthropic-beta` header. Token usage reported to tracer hook. |
| gpt | HTTP POST to `api.openai.com/v1/chat/completions` via `requests` | OPENAI_API_KEY | gpt-4o | Standard OpenAI chat completions format. |
| gemini | HTTP POST to `generativelanguage.googleapis.com/v1beta` via `requests` | GEMINI_API_KEY (sent as `x-goog-api-key` header) | gemini-pro | System prompt concatenated with user prompt (not separate field). |
| bedrock | `boto3.client('bedrock-runtime').converse()` | AWS credentials (env, ~/.aws/credentials, IAM role, SSO) | us.anthropic.claude-sonnet-4-5-20250929-v1:0 | Extended thinking support for Claude models. Region from profile or `AWS_BEDROCK_REGION` env (default us-east-1). |
| ollama | HTTP POST to `localhost:11434/api/generate` | None | llama3.2 | Local model. `stream: False` for synchronous response. |
| openrouter | HTTP POST to `openrouter.ai/api/v1/chat/completions` | OPENROUTER_API_KEY | anthropic/claude-sonnet-4-5-20250929 | OpenAI-compatible API. Sends `HTTP-Referer` and `X-Title` headers. 180s timeout. |
| gemini-cli | Subprocess `gemini chat -m <model>` | None | N/A | Pipes prompt to stdin, reads stdout. 120s timeout. |
| lmstudio | HTTP POST to `localhost:1234/v1/chat/completions` | None | N/A | OpenAI-compatible local server. |

### generate() Method
```python
def generate(self, prompt: str, system_prompt: Optional[str] = None, task_type: Optional[str] = None) -> str
```
1. If `task_type` provided and `_model_router` enabled: try `_model_router.generate(prompt, system_prompt, task_type)`
2. If routing returns a result (not `None`): return it
3. Otherwise: dispatch to provider-specific method (`_generate_claude`, `_generate_gpt`, etc.)
4. If `guardrails_enabled`: apply guardrails (keyword filtering, length check, ethical check)
5. If `hallucination_mitigation_strategy` is set: apply mitigation (grounding, self_reflection, or consistency_check)
6. Return response string

### Retry Logic
All provider methods implement the same retry pattern:
- `MAX_RETRIES = 3`
- `RETRY_DELAY = 1.0` seconds base
- `RETRY_MULTIPLIER = 2.0` exponential backoff
- Retried errors: rate limits (429), server errors (5xx), timeouts, connection errors
- Non-retried errors: auth failures (401/403), validation errors -- raised immediately
- Final failure: raises `ConnectionError` or `ValueError`

### Extended Thinking
Available for `claude` and `bedrock` providers:
- Enabled via `ENABLE_EXTENDED_THINKING` env var or profile `extended_thinking: true`
- Budget from profile `thinking_budget_tokens` (default 10000)
- Claude API: requires `temperature: 1` and `anthropic-beta: interleaved-thinking-2025-05-14` header
- Bedrock: uses `additionalModelRequestFields.thinking` in converse params
- Response extraction: filters `content` blocks to only `type: "text"` (skipping thinking blocks)

### Model Router Integration
`_init_model_router()`:
1. Import `ModelRouter` from `core.model_router` (graceful ImportError handling)
2. Create profile factory: `_profile_factory(profile_name)` returns new `LLMManager` with `_routing_disabled=True` and the specified profile as default
3. Create `ModelRouter(full_config, _profile_factory)`
4. If `router.enabled`: store as `_model_router`
5. Configured routes: reasoning -> bedrock_claude, analysis/generation/validation -> gemini, default -> gemini

### Hallucination Mitigation
Thread-safe via `_mitigation_lock`. Three strategies:

1. **grounding**: Re-prompts LLM as fact-checker, asking to verify response against original context only
2. **self_reflection**: Re-prompts LLM to critically review its own output for inaccuracies and inconsistencies
3. **consistency_check**: Generates 3 responses for the same prompt. If all identical, returns one. If varying, synthesizes a consistent answer from all three.

All strategies temporarily disable `hallucination_mitigation_strategy` during recursive `generate()` calls to prevent infinite loops, then restore the original state in a `finally` block.

### Guardrails
When `guardrails_enabled`:
- Keyword filtering: replaces harmful keywords with `[REDACTED_HARMFUL_CONTENT]`
- Length check: truncates responses exceeding `output_token_limit * 1.5` estimated words
- Ethical check: flags responses containing explicit unethical instruction phrases

### Prompt Loading
`_load_all_prompts()` returns dict with two keys:
- `json_prompts`: Loaded from `prompts/library.json` -- nested dict of categories and prompt names
- `md_prompts`: Loaded from `prompts/*.md` and `prompts/md_library/*.md` -- each file parsed for `## User Prompt` / `## System Prompt` sections. Files without structured sections use entire content as system prompt. `md_library/` files take priority over `prompts/` root files.

Access via `get_prompt(library_type, category, name, default)`.

### Tracer Hook
- `_tracer_hook`: Optional callable set externally by agent code
- Called with `(input_tokens, output_tokens)` after each Claude API response
- Used for execution tracing when `ENABLE_TRACING` is active

### Profile Configuration
Each profile in `config.json` under `llm.profiles`:
```json
{
  "provider": "claude|gpt|gemini|bedrock|ollama|openrouter|gemini-cli|lmstudio",
  "model": "model-name",
  "api_key": "${ENV_VAR_NAME}",
  "temperature": 0.7,
  "max_tokens": 4096,
  "input_token_limit": 4096,
  "output_token_limit": 4096,
  "cache_enabled": false,
  "search_context_level": "low|medium|high",
  "pdf_support_enabled": false,
  "guardrails_enabled": false,
  "hallucination_mitigation_strategy": "consistency_check|self_reflection|grounding|null",
  "extended_thinking": false,
  "thinking_budget_tokens": 10000,
  "region": "us-east-1"
}
```

### Convenience Methods
- `analyze_vulnerability(vulnerability_data)` -- prompts LLM for severity, exploitation difficulty, impact, techniques. Returns parsed JSON or `{"raw_response": ...}`.
- `generate_payload(target_info, vulnerability_type)` -- prompts LLM for exploit payload with obfuscation and cleanup. Returns raw string.
- `suggest_privilege_escalation(system_info)` -- prompts LLM for top 5 privesc vectors. Returns list of technique dicts.
- `analyze_network_topology(scan_results)` -- prompts LLM for attack paths and lateral movement. Returns parsed JSON.
- `analyze_web_vulnerability(vulnerability_type, vulnerability_data)` -- dynamically loads prompt templates by vuln type (ssrf, sql_injection, xss, lfi, broken_object, broken_auth). Returns parsed JSON.

All convenience methods use `task_type` parameter for model routing (analysis, generation, reasoning).

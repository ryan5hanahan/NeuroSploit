# LLM Integration

## Overview

sploit.ai supports multiple LLM providers through a unified interface (`LLMManager`). The system can route requests to different models based on task type, allowing operators to optimize cost, latency, and capability per workload.

## Supported Providers

| Provider | API Library | Default Model | Env Variable | Notes |
|----------|------------|---------------|--------------|-------|
| Claude (Anthropic) | Anthropic API | claude-sonnet-4-5-20250929 | `ANTHROPIC_API_KEY` | Direct Anthropic access |
| GPT (OpenAI) | OpenAI API | gpt-4o | `OPENAI_API_KEY` | |
| Gemini (Google) | Google Generative AI | gemini-pro | `GEMINI_API_KEY` | Default profile in config |
| AWS Bedrock | boto3 | us.anthropic.claude-sonnet-4-5-20250929-v1:0 | Region-based config | Supports extended thinking |
| Ollama | HTTP API | llama3.2 | None required | Local models, no API key needed |
| OpenRouter | OpenRouter API | anthropic/claude-sonnet-4-5-20250929 | `OPENROUTER_API_KEY` | Multi-provider gateway |

## LLM Profiles

Profiles are defined in `config/config.json` under `llm.profiles`. Each profile specifies:

- `provider` -- The LLM provider (anthropic, openai, google, bedrock, ollama, openrouter)
- `model` -- The model identifier
- `api_key` -- Supports `${ENV_VAR}` syntax for environment variable substitution
- `temperature` -- Sampling temperature
- `max_tokens` -- Maximum token generation limit
- `input_token_limit` -- Maximum input context size
- `output_token_limit` -- Maximum output size
- `cache_enabled` -- Enable response caching
- `search_context_level` -- Context retrieval depth
- `pdf_support_enabled` -- Enable PDF document processing
- `guardrails_enabled` -- Enable output safety guardrails
- `hallucination_mitigation_strategy` -- Either `consistency_check` or `self_reflection`
- `extended_thinking` -- Enable extended reasoning (Bedrock Claude only)
- `thinking_budget_tokens` -- Token budget for extended thinking

The default profile is set via `llm.default_profile` in config.json.

## Model Routing

When `ENABLE_MODEL_ROUTING` is enabled, the `ModelRouter` routes requests to different LLM profiles based on task type:

| Task Type | Target Profile | Rationale |
|-----------|---------------|-----------|
| `reasoning` | bedrock_claude_default | Complex logic and multi-step reasoning |
| `analysis` | gemini_pro_default | Pattern recognition and data analysis |
| `generation` | gemini_pro_default | Content and payload generation |
| `validation` | gemini_pro_default | Result verification |
| `default` | gemini_pro_default | Fallback for unspecified task types |

Routes are configured in `config.json` under `model_routing.routes`. The `ModelRouter` caches `LLMManager` instances per profile to avoid repeated initialization. Child `LLMManager` instances are created with `_routing_disabled=True` to prevent recursive routing.

The `LLMManager.generate()` method accepts a `task_type` parameter. When model routing is active, the request is dispatched to the appropriate profile's LLMManager. When routing is disabled or the toggle is off, requests go to the default profile.

## Provider Selection at Runtime

The Settings UI allows switching providers dynamically. Provider resolution order:

1. `DEFAULT_LLM_PROVIDER` environment variable
2. First available API key detected (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`)
3. Falls back to `claude`

Model resolution order:

1. `DEFAULT_LLM_MODEL` environment variable
2. Provider-specific default model

## Extended Thinking

Claude via AWS Bedrock supports extended thinking with a configurable token budget (`thinking_budget_tokens`). This is enabled per-profile in `config.json` and toggled via `ENABLE_EXTENDED_THINKING`. Extended thinking allows the model to reason through complex security analysis before producing its final response.

## MAX_OUTPUT_TOKENS Override

The `MAX_OUTPUT_TOKENS` environment variable overrides per-profile output limits globally. Maximum supported value is 64000 for Claude models.

## Retry Logic

All LLM calls use exponential backoff on failure:

- `MAX_RETRIES`: 3
- `RETRY_DELAY`: 1.0 second (initial)
- `RETRY_MULTIPLIER`: 2.0 (exponential backoff factor)

Retry sequence: 1s, 2s, 4s.

## Test Connection

`POST /api/v1/settings/test-llm` sends the prompt "Respond with exactly: CONNECTION_OK" to the configured provider. Returns success/failure status with response time in milliseconds. Results are persisted to the `LlmTestResult` database table for historical tracking.

## Architecture Notes

- `LLMManager(config)` takes the full config dictionary (not just the `llm` subsection) since the model routing wiring was added.
- `LLMManager()` with no arguments works; config defaults to `{}`.
- `sploitai.py` passes `self.config` (full config) to LLMManager.
- The Settings API persists provider configuration to both in-memory dict and `.env` file via `PUT /api/v1/settings`.

## Limitations

- No streaming support in LLMManager (full response only).
- Token counting is approximate (not exact tokenizer-based).
- No automatic failover between providers on error.
- Gemini Pro is the default profile -- requires `GEMINI_API_KEY` to be set.

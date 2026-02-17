# Non-Functional Requirements

## Performance

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| NFR-001 | System shall support configurable concurrent scan limits (default 3, enforced via DB count of running scans, returns HTTP 429 when exceeded) | Implemented | High |
| NFR-002 | Quick-win CTF probes shall complete within 2 minutes (10 parallel aiohttp probes) | Implemented | Medium |
| NFR-003 | Browser probes shall complete within 3 minutes (5 URLs x 2 payloads for DOM XSS, plus hidden page discovery with SPA fallback) | Implemented | Medium |
| NFR-004 | LLM API calls shall retry up to 3 times with exponential backoff (1s, 2s, 4s) | Implemented | High |
| NFR-005 | WebSocket updates shall be delivered in real-time (sub-second latency) via `/ws/scan/{scan_id}` | Implemented | High |
| NFR-006 | BaseAgent shall cap tool execution output at 8000 characters per command | Implemented | Low |
| NFR-007 | BaseAgent adaptive exploitation loop shall run at most 10 iterations before stopping | Implemented | Medium |
| NFR-008 | BaseAgent tool execution shall have configurable timeout (default 60 seconds) | Implemented | Medium |
| NFR-009 | Report scan results output shall be truncated to 2000 characters per tool | Implemented | Low |
| NFR-010 | CTF lab_results log buffer shall hold 200 entries (FIFO rotation) | Implemented | Low |

## Security

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| NFR-011 | API keys shall never be exposed in API responses (Settings API returns `has_X_key` booleans) | Implemented | Critical |
| NFR-012 | Scan credentials shall be redacted in API responses (first 2 chars + asterisks + last 2 chars, or full mask for short values) | Implemented | Critical |
| NFR-013 | .env file writes shall sanitize values to prevent newline injection (`\n`, `\r`, `\0` stripped, special chars quoted) | Implemented | Critical |
| NFR-014 | Sandbox containers shall enforce memory limit of 2G and CPU limit of 2.0 | Implemented | High |
| NFR-015 | Sandbox containers shall auto-cleanup after TTL of 60 minutes | Implemented | Medium |
| NFR-016 | GovernanceAgent shall enforce scope boundaries (allowed domains, paths, Nuclei template tags) for all agent operations | Implemented | High |
| NFR-017 | System shall use specific exception types instead of bare `except:` blocks in production code | Implemented | Medium |
| NFR-018 | Error messages shall be logged but stack traces shall not be exposed in API responses | Implemented | High |
| NFR-019 | OPSEC profiles shall control request jitter, user agent randomization, DNS-over-HTTPS, proxy routing, and header randomization | Implemented | Medium |

## Reliability

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| NFR-020 | System shall save partial results when scans are stopped (partial report generated with `is_partial=True`) | Implemented | High |
| NFR-021 | System shall cleanup orphan sandbox containers on startup | Implemented | Medium |
| NFR-022 | Database migrations shall be additive-only (ALTER TABLE ADD COLUMN only, no destructive schema changes) | Implemented | High |
| NFR-023 | System shall gracefully degrade when optional features are unavailable (guarded imports for Playwright, Docker SDK, MCP, anthropic, openai, boto3, ReconIntegration) | Implemented | High |
| NFR-024 | Database sessions shall auto-rollback on exception and auto-commit on success via `get_db()` dependency | Implemented | High |
| NFR-025 | LLM provider initialization shall fallback through provider list (preferred provider first, then claude, openai, gemini, bedrock, ollama, lmstudio) | Implemented | High |

## Scalability

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| NFR-026 | System shall support up to 5 concurrent sandbox containers | Implemented | Medium |
| NFR-027 | System shall support CTF pipeline with 2-6 parallel testing agents | Implemented | Medium |
| NFR-028 | Knowledge augmentation dataset shall support up to 3 patterns per query to control context size | Implemented | Low |

## Maintainability

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| NFR-029 | All database models shall provide `to_dict()` serialization methods | Implemented | Medium |
| NFR-030 | All SQLAlchemy models shall use `mapped_column` (SQLAlchemy 2.0 style) except memory and trace models | Implemented | Low |
| NFR-031 | Feature toggles shall follow consistent pattern: UI toggle -> Settings API -> .env persistence -> env var read on init | Implemented | Medium |

## Observability

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| NFR-032 | System shall support structured tracing via TraceSpan model (when ENABLE_TRACING is set) with trace_id, parent_id hierarchy | Implemented | Low |
| NFR-033 | TraceSpan shall capture span_type (phase, tool, llm, http, validation), input/output tokens, and duration_ms | Implemented | Low |
| NFR-034 | AgentTask shall track per-scan tool execution with timing, item counts, and result summaries | Implemented | Medium |
| NFR-035 | LLM connection test results shall be persisted to llm_test_results table with provider, model, response_time_ms, and success status | Implemented | Low |

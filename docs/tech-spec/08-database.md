# Database

## Overview

SQLite database accessed via async SQLAlchemy with the aiosqlite driver. Schema is defined by SQLAlchemy model classes and extended at runtime through additive-only ALTER TABLE migrations. No migration framework (Alembic) is used.

## Connection

File: `backend/db/database.py`

```python
engine = create_async_engine(
    settings.DATABASE_URL,  # "sqlite+aiosqlite:///./data/sploitai.db"
    echo=settings.DEBUG,
    future=True
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Alias for background tasks
async_session_factory = async_session_maker
```

### Session Management

`get_db()` is an async generator for FastAPI dependency injection:
- Yields an `AsyncSession`
- Auto-commits on success
- Auto-rollbacks on exception
- Always closes session in `finally`

```python
async def get_db() -> AsyncSession:
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
```

## Initialization

`init_db()` is called during FastAPI app lifespan startup:

1. `Base.metadata.create_all` -- creates all tables defined by model classes
2. `_run_migrations(conn)` -- adds missing columns via ALTER TABLE

```python
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)
```

## Models (13 files)

All models are defined in `backend/models/` and exported via `backend/models/__init__.py`.

### Scan (`scans` table)

File: `backend/models/scan.py`

Core entity. All scans cascade-delete their related records.

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | Scan UUID |
| `name` | String(255) | null | User-provided scan name |
| `status` | String(50) | `"pending"` | `pending`, `running`, `completed`, `failed`, `stopped` |
| `scan_type` | String(50) | `"full"` | `quick`, `full`, `custom` |
| `recon_enabled` | Boolean | True | Whether recon phase runs |
| `progress` | Integer | 0 | Completion percentage (0-100) |
| `current_phase` | String(50) | null | `recon`, `testing`, `reporting` |
| `config` | JSON | {} | Scan configuration dict |
| `custom_prompt` | Text | null | User-provided prompt text |
| `prompt_id` | String(36) | null | Reference to prompts table |
| `auth_type` | String(50) | null | `none`, `cookie`, `header`, `basic`, `bearer` |
| `auth_credentials` | JSON | null | Auth data (redacted in API responses) |
| `custom_headers` | JSON | null | Additional HTTP headers |
| `repeated_from_id` | String(36) | null | ID of scan this was cloned from |
| `created_at` | DateTime | utcnow | Creation timestamp |
| `started_at` | DateTime | null | Execution start time |
| `completed_at` | DateTime | null | Execution end time |
| `duration` | Integer | null | Duration in seconds |
| `error_message` | Text | null | Error details on failure |
| `total_endpoints` | Integer | 0 | Discovered endpoint count |
| `total_vulnerabilities` | Integer | 0 | Confirmed vulnerability count |
| `critical_count` | Integer | 0 | Critical severity count |
| `high_count` | Integer | 0 | High severity count |
| `medium_count` | Integer | 0 | Medium severity count |
| `low_count` | Integer | 0 | Low severity count |
| `info_count` | Integer | 0 | Info severity count |

**Relationships** (all cascade `delete-orphan`):
- `targets` -> Target
- `endpoints` -> Endpoint
- `vulnerabilities` -> Vulnerability
- `reports` -> Report
- `agent_tasks` -> AgentTask

**Credential redaction**: `_redact_credentials(creds)` masks values as `first2chars****last2chars`. Values 4 chars or shorter become `"***"`. Applied in `to_dict()`.

### Target (`targets` table)

File: `backend/models/target.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `scan_id` | FK -> scans.id | | CASCADE delete |
| `url` | String(2048) | | Full target URL |
| `hostname` | String(255) | null | Parsed hostname |
| `port` | Integer | null | Parsed port |
| `protocol` | String(10) | null | `http` or `https` |
| `path` | String(2048) | null | URL path component |
| `status` | String(50) | `"pending"` | `pending`, `scanning`, `completed`, `failed` |
| `created_at` | DateTime | utcnow | |

### Endpoint (`endpoints` table)

File: `backend/models/endpoint.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `scan_id` | FK -> scans.id | | CASCADE delete |
| `target_id` | FK -> targets.id | null | SET NULL on delete |
| `url` | Text | | Full endpoint URL |
| `method` | String(10) | `"GET"` | HTTP method |
| `path` | Text | null | URL path |
| `parameters` | JSON | [] | List of `{name, type, value}` |
| `headers` | JSON | {} | Response headers |
| `response_status` | Integer | null | HTTP status code |
| `content_type` | String(100) | null | Response content type |
| `content_length` | Integer | null | Response body size |
| `technologies` | JSON | [] | Detected technologies |
| `interesting` | Boolean | False | Flagged for testing |
| `discovered_at` | DateTime | utcnow | |

### Vulnerability (`vulnerabilities` table)

File: `backend/models/vulnerability.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `scan_id` | FK -> scans.id | | CASCADE delete |
| `test_id` | FK -> vulnerability_tests.id | null | SET NULL on delete |
| `title` | String(500) | | Finding title |
| `vulnerability_type` | String(100) | | e.g. `xss_reflected`, `sqli_union` |
| `severity` | String(20) | | `critical`, `high`, `medium`, `low`, `info` |
| `cvss_score` | Float | null | CVSS 3.1 score |
| `cvss_vector` | String(100) | null | CVSS vector string |
| `cwe_id` | String(50) | null | CWE identifier |
| `description` | Text | null | Vulnerability description |
| `affected_endpoint` | Text | null | Affected URL |
| `poc_request` | Text | null | PoC HTTP request |
| `poc_response` | Text | null | PoC HTTP response |
| `poc_payload` | Text | null | Triggering payload |
| `poc_parameter` | String(500) | null | Vulnerable parameter name |
| `poc_evidence` | Text | null | Evidence of exploitation |
| `poc_code` | Text | null | Executable PoC (HTML, Python, curl, etc.) |
| `impact` | Text | null | Impact description |
| `remediation` | Text | null | Remediation guidance |
| `references` | JSON | [] | Reference URLs |
| `ai_analysis` | Text | null | LLM-generated analysis |
| `screenshots` | JSON | [] | Base64 data URIs or filesystem paths |
| `url` | Text | null | Source URL |
| `parameter` | String(500) | null | Tested parameter |
| `validation_status` | String(20) | `"ai_confirmed"` | `ai_confirmed`, `ai_rejected`, `validated`, `false_positive`, `pending_review` |
| `ai_rejection_reason` | Text | null | Reason if AI rejected |
| `created_at` | DateTime | utcnow | |

### VulnerabilityTest (`vulnerability_tests` table)

File: `backend/models/vulnerability.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `scan_id` | FK -> scans.id | | CASCADE delete |
| `endpoint_id` | FK -> endpoints.id | null | SET NULL on delete |
| `vulnerability_type` | String(100) | | Test type identifier |
| `payload` | Text | null | Test payload |
| `request_data` | JSON | {} | Full request data |
| `response_data` | JSON | {} | Full response data |
| `is_vulnerable` | Boolean | False | Test result |
| `confidence` | Float | null | 0.0 to 1.0 |
| `evidence` | Text | null | Evidence text |
| `tested_at` | DateTime | utcnow | |

### Report (`reports` table)

File: `backend/models/report.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `scan_id` | FK -> scans.id | | CASCADE delete |
| `title` | String(255) | null | Report title |
| `format` | String(20) | `"html"` | `html`, `pdf`, `json` |
| `file_path` | Text | null | File path on disk |
| `executive_summary` | Text | null | Summary text |
| `auto_generated` | Boolean | False | True if auto-generated on completion/stop |
| `is_partial` | Boolean | False | True if from stopped/incomplete scan |
| `generated_at` | DateTime | utcnow | |

### AgentTask (`agent_tasks` table)

File: `backend/models/agent_task.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `scan_id` | FK -> scans.id | | CASCADE delete |
| `task_type` | String(50) | | `recon`, `analysis`, `testing`, `reporting` |
| `task_name` | String(255) | | Human-readable name |
| `description` | Text | null | Task description |
| `tool_name` | String(100) | null | Tool used (nmap, nuclei, claude, etc.) |
| `tool_category` | String(50) | null | `scanner`, `analyzer`, `ai`, `crawler` |
| `status` | String(20) | `"pending"` | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `started_at` | DateTime | null | |
| `completed_at` | DateTime | null | |
| `duration_ms` | Integer | null | Duration in milliseconds |
| `items_processed` | Integer | 0 | URLs tested, hosts scanned, etc. |
| `items_found` | Integer | 0 | Endpoints found, vulns found, etc. |
| `result_summary` | Text | null | Brief results |
| `error_message` | Text | null | Error on failure |
| `created_at` | DateTime | utcnow | |

Helper methods: `start()`, `complete(items_processed, items_found, summary)`, `fail(error)` -- auto-calculate `duration_ms` from `started_at`.

### VulnLabChallenge (`vuln_lab_challenges` table)

File: `backend/models/vuln_lab.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `target_url` | Text | | Target URL |
| `challenge_name` | String(255) | null | Challenge label |
| `vuln_type` | String(100) | | e.g. `xss_reflected`, `sqli_union` |
| `vuln_category` | String(50) | null | `injection`, `auth`, `client_side`, etc. |
| `auth_type` | String(20) | null | `cookie`, `bearer`, `basic`, `header` |
| `auth_value` | Text | null | Auth credential value |
| `status` | String(20) | `"pending"` | `pending`, `running`, `completed`, `failed`, `stopped` |
| `result` | String(20) | null | `detected`, `not_detected`, `error` |
| `agent_id` | String(36) | null | |
| `scan_id` | String(36) | null | |
| `findings_count` | Integer | 0 | |
| `critical_count` | Integer | 0 | |
| `high_count` | Integer | 0 | |
| `medium_count` | Integer | 0 | |
| `low_count` | Integer | 0 | |
| `info_count` | Integer | 0 | |
| `findings_detail` | JSON | [] | Finding summaries |
| `started_at` | DateTime | null | |
| `completed_at` | DateTime | null | |
| `duration` | Integer | null | Seconds |
| `notes` | Text | null | |
| `logs` | JSON | [] | Log entries |
| `endpoints_count` | Integer | 0 | |
| `ctf_mode` | Boolean | False | CTF pipeline mode |
| `ctf_flag_patterns` | JSON | null | Custom flag regex patterns |
| `ctf_flags_captured` | JSON | [] | Captured flag objects |
| `ctf_flags_count` | Integer | 0 | |
| `ctf_time_to_first_flag` | Float | null | Seconds |
| `ctf_metrics` | JSON | null | Pipeline metrics |
| `ctf_agent_count` | Integer | null | Number of parallel agents |
| `created_at` | DateTime | utcnow | |

### Prompt (`prompts` table)

File: `backend/models/prompt.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `name` | String(255) | | Prompt name |
| `description` | Text | null | |
| `content` | Text | | Prompt text |
| `is_preset` | Boolean | False | Built-in vs user-created |
| `category` | String(100) | null | `pentest`, `bug_bounty`, `api`, etc. |
| `parsed_vulnerabilities` | JSON | [] | AI-extracted vuln types |
| `created_at` | DateTime | utcnow | |
| `updated_at` | DateTime | utcnow | Auto-updated |

### Tradecraft (`tradecraft` table)

File: `backend/models/tradecraft.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `name` | String(255) | | TTP name |
| `description` | Text | null | |
| `content` | Text | | TTP definition |
| `category` | String(50) | | `evasion`, `reconnaissance`, `exploitation`, `validation` |
| `is_builtin` | Boolean | False | |
| `enabled` | Boolean | True | |
| `created_at` | DateTime | utcnow | |
| `updated_at` | DateTime | utcnow | Auto-updated |

### ScanTradecraft (`scan_tradecraft` table)

File: `backend/models/tradecraft.py`

Junction table linking scans to tradecraft TTPs.

| Column | Type | Description |
|--------|------|-------------|
| `id` | String(36) PK | uuid4 |
| `scan_id` | FK -> scans.id | CASCADE delete |
| `tradecraft_id` | FK -> tradecraft.id | CASCADE delete |
| `created_at` | DateTime | |

### LlmTestResult (`llm_test_results` table)

File: `backend/models/llm_test_result.py`

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | String(36) PK | uuid4 | |
| `success` | Boolean | False | Test passed |
| `provider` | String(50) | | Provider name |
| `model` | String(200) | `""` | Model identifier |
| `response_time_ms` | Integer | 0 | Response latency |
| `response_preview` | Text | `""` | Truncated response |
| `error` | Text | null | Error message |
| `created_at` | DateTime | utcnow | |

### Memory Models

File: `backend/models/memory.py`

Three models for cross-scan learning (used by `AgentMemory` when `ENABLE_PERSISTENT_MEMORY` is set):

**AttackPatternMemory** (`attack_pattern_memory`):
| Column | Type | Description |
|--------|------|-------------|
| `id` | String(36) PK | |
| `domain` | String(255), indexed | Target domain |
| `vuln_type` | String(100), indexed | Vulnerability type |
| `tech_stack` | JSON | e.g. `["nginx", "react", "express"]` |
| `payload` | Text | Tested payload |
| `parameter` | String(500) | Tested parameter |
| `endpoint` | Text | Tested endpoint |
| `success` | Boolean | Whether attack succeeded |
| `confidence` | Float | Confidence score |
| `severity` | String(20) | Finding severity |
| `notes` | Text | |
| `created_at` | DateTime, indexed | |

**TargetFingerprint** (`target_fingerprints`):
| Column | Type | Description |
|--------|------|-------------|
| `id` | String(36) PK | |
| `domain` | String(255), unique, indexed | Target domain |
| `tech_stack` | JSON | Detected technologies |
| `waf_detected` | String(100) | WAF identifier |
| `open_ports` | JSON | Port list |
| `interesting_paths` | JSON | Notable paths |
| `known_vulns` | JSON | `[{type, endpoint, severity}]` |
| `auth_type` | String(50) | `jwt`, `session`, `basic`, `none` |
| `scan_count` | Integer | Number of scans against this target |
| `last_scanned` | DateTime | |
| `notes` | Text | |
| `created_at` | DateTime | |
| `updated_at` | DateTime | Auto-updated |

**SuccessfulPayload** (`successful_payloads`):
| Column | Type | Description |
|--------|------|-------------|
| `id` | String(36) PK | |
| `vuln_type` | String(100), indexed | |
| `tech_stack_tag` | String(255), indexed | e.g. `"nginx+express"` |
| `payload` | Text | Confirmed payload |
| `parameter` | String(500) | |
| `endpoint_pattern` | String(500) | Generalized pattern e.g. `/api/users/{id}` |
| `success_count` | Integer | Times this payload succeeded |
| `last_success_domain` | String(255) | |
| `confidence` | Float | |
| `severity` | String(20) | |
| `created_at` | DateTime | |
| `updated_at` | DateTime | Auto-updated |

### TraceSpan (`trace_spans` table)

File: `backend/models/trace.py`

| Column | Type | Description |
|--------|------|-------------|
| `id` | String(36) PK | |
| `trace_id` | String(36), indexed | Groups spans into a trace (usually scan_id) |
| `parent_id` | String(36), indexed | Parent span for nesting |
| `name` | String(255) | e.g. `"recon"`, `"test_xss"`, `"llm_call"` |
| `span_type` | String(50) | `phase`, `tool`, `llm`, `http`, `validation` |
| `metadata_json` | JSON | Arbitrary key-value metadata |
| `input_tokens` | Integer | LLM input tokens |
| `output_tokens` | Integer | LLM output tokens |
| `start_time` | DateTime | |
| `end_time` | DateTime | |
| `duration_ms` | Integer | |
| `status` | String(20) | `running`, `completed`, `error` |
| `error_message` | Text | |
| `created_at` | DateTime | |

## Migrations

`_run_migrations(conn)` uses `PRAGMA table_info` to detect missing columns, then runs `ALTER TABLE ADD COLUMN` statements. This is purely additive -- no destructive schema changes.

Migration categories:
1. **Column additions to existing tables**: `duration` and `repeated_from_id` on scans; `auto_generated` and `is_partial` on reports; `test_id`, `poc_parameter`, `poc_evidence`, `screenshots`, `url`, `parameter`, `validation_status`, `ai_rejection_reason`, `poc_code` on vulnerabilities; `logs`, `endpoints_count`, CTF columns on vuln_lab_challenges.
2. **Table creation**: `agent_tasks`, `vulnerability_tests`, `vuln_lab_challenges` created if not exists (with indexes).

All migrations run inside `engine.begin()` -- the same transaction as `create_all`.

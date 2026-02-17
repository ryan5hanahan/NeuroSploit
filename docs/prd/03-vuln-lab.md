# Vulnerability Lab

## Overview

The vulnerability lab provides isolated vulnerability testing against labs, CTFs, and training platforms. Users can test individual vulnerability types one at a time against a target and track detection rates, or launch the full CTF pipeline for multi-agent challenge solving. Each test creates a tracked challenge record in the database with status, results, findings, logs, and metrics.

The vuln lab operates through a separate API (`/api/v1/vuln-lab/`) from the standard scan engine (`/api/v1/scans/`). It uses the same `AutonomousAgent` for individual vuln testing but invokes the `CTFCoordinator` for CTF mode. In-memory tracking via `lab_agents` and `lab_results` dictionaries provides real-time status for running tests.

## User Stories

### Test a Specific Vulnerability Type
A security researcher selects a specific vulnerability type (e.g., `xss_reflected`) and tests it against a lab target (e.g., a PortSwigger Web Security Academy lab). The system creates a challenge record, launches an AutonomousAgent focused on that single vulnerability type, and reports whether the vulnerability was detected.

### Track Detection Rates
A researcher runs tests across multiple vulnerability types and categories against a training platform. The statistics API aggregates detection rates per vulnerability type and category, showing which types the system detects reliably and which need improvement.

### Run Full CTF Pipeline
A CTF competitor enables CTF mode to launch the multi-agent pipeline (described in `02-ctf-mode.md`) against a target. The vuln lab tracks this as a challenge record with CTF-specific data (flags captured, submission results).

### Review Challenge History
A researcher views the history of all challenges tested, filtering by status, vulnerability type, or result. Detailed logs and findings for each challenge are available for analysis.

## Vulnerability Coverage

The system covers 100+ vulnerability types organized into 11 categories:

### Injection (10 types)
`xss_reflected`, `xss_stored`, `xss_dom`, `sqli_error`, `sqli_union`, `sqli_blind`, `sqli_time`, `command_injection`, `ssti`, `nosql_injection`

### Advanced Injection (11 types)
`ldap_injection`, `xpath_injection`, `graphql_injection`, `crlf_injection`, `header_injection`, `email_injection`, `el_injection`, `log_injection`, `html_injection`, `csv_injection`, `orm_injection`

### File Access (8 types)
`lfi`, `rfi`, `path_traversal`, `xxe`, `file_upload`, `arbitrary_file_read`, `arbitrary_file_delete`, `zip_slip`

### Request Forgery (4 types)
`ssrf`, `csrf`, `graphql_introspection`, `graphql_dos`

### Authentication (7 types)
`auth_bypass`, `jwt_manipulation`, `session_fixation`, `weak_password`, `default_credentials`, `two_factor_bypass`, `oauth_misconfig`

### Authorization (6 types)
`idor`, `bola`, `privilege_escalation`, `bfla`, `mass_assignment`, `forced_browsing`

### Client-Side (9 types)
`cors_misconfiguration`, `clickjacking`, `open_redirect`, `dom_clobbering`, `postmessage_vuln`, `websocket_hijack`, `prototype_pollution`, `css_injection`, `tabnabbing`

### Infrastructure (8 types)
`security_headers`, `ssl_issues`, `http_methods`, `directory_listing`, `debug_mode`, `exposed_admin_panel`, `exposed_api_docs`, `insecure_cookie_flags`

### Business Logic (9 types)
`race_condition`, `business_logic`, `rate_limit_bypass`, `parameter_pollution`, `type_juggling`, `timing_attack`, `host_header_injection`, `http_smuggling`, `cache_poisoning`

### Data Exposure (6 types)
`sensitive_data_exposure`, `information_disclosure`, `api_key_exposure`, `source_code_disclosure`, `backup_file_exposure`, `version_disclosure`

### Cloud & Supply Chain (6 types)
`s3_bucket_misconfig`, `cloud_metadata_exposure`, `subdomain_takeover`, `vulnerable_dependency`, `container_escape`, `serverless_misconfiguration`

Each vulnerability type is registered in the `VulnerabilityRegistry` with metadata including title, severity, CWE ID, and description.

## Challenge Tracking

Each test run creates a `VulnLabChallenge` database record with the following fields:

| Field | Description |
|-------|-------------|
| `id` | UUID primary key |
| `target_url` | Target URL tested |
| `vuln_type` | Vulnerability type tested (or `null` for CTF mode) |
| `challenge_name` | User-provided name for this challenge |
| `status` | `running`, `completed`, `failed`, `stopped` |
| `result` | `detected`, `not_detected`, or `null` (while running) |
| `findings` | JSON list of vulnerability findings |
| `logs` | JSON list of log entries from the agent |
| `notes` | User-provided notes |
| `ctf_mode` | Boolean flag for CTF pipeline runs |
| `ctf_flags` | JSON list of captured CTF flags |
| `metrics` | JSON dict of performance metrics (duration, request count, etc.) |
| `created_at` | Timestamp |
| `completed_at` | Timestamp |

## Statistics API

The statistics endpoint aggregates data across all challenges:

```
GET /api/v1/vuln-lab/stats
```

Returns:
- **Total challenges**: Count of all challenge records
- **Running count**: Currently executing tests
- **Detection rates per vuln type**: For each tested type, the number of tests run and the number where the vulnerability was detected
- **Detection rates per category**: Aggregated detection rates grouped by the 11 vulnerability categories
- **CTF flag counts**: Total flags captured across all CTF pipeline runs

## API Endpoints

### Launch a Test

```
POST /api/v1/vuln-lab/run
```

Request body (`VulnLabRunRequest`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_url` | `str` | Yes | Target URL to test |
| `vuln_type` | `str` | No | Vulnerability type key (required unless `ctf_mode` is `true`) |
| `challenge_name` | `str` | No | Name for this test |
| `auth_type` | `str` | No | Auth type: `cookie`, `bearer`, `basic`, `header` |
| `auth_value` | `str` | No | Auth credential value |
| `custom_headers` | `dict` | No | Custom HTTP headers |
| `notes` | `str` | No | Notes about this challenge |
| `ctf_mode` | `bool` | No | Enable CTF pipeline (default: `false`) |
| `ctf_flag_patterns` | `List[str]` | No | Custom flag regex patterns |
| `ctf_agent_count` | `int` | No | Number of agents for CTF pipeline (2-6) |
| `ctf_submit_url` | `str` | No | CTF platform flag submission URL |
| `ctf_platform_token` | `str` | No | Auth token for CTF platform API |

Response (`VulnLabResponse`):
```json
{
  "challenge_id": "uuid",
  "agent_id": "uuid",
  "status": "running",
  "message": "Vulnerability test started for xss_reflected"
}
```

### List Vulnerability Types

```
GET /api/v1/vuln-lab/types
```

Returns all vulnerability types grouped by category, with metadata from the VulnerabilityRegistry (title, severity, CWE ID, truncated description). Also returns `total_types` count.

### List Challenges

```
GET /api/v1/vuln-lab/challenges
```

Returns all challenge records ordered by creation time (newest first). Supports optional query filters for status and vuln_type.

### Get Challenge Details

```
GET /api/v1/vuln-lab/challenges/{challenge_id}
```

Returns the full challenge record including findings, logs, metrics, and CTF flags.

### Stop a Running Challenge

```
POST /api/v1/vuln-lab/challenges/{challenge_id}/stop
```

Cancels the running agent or CTF coordinator. Sets challenge status to `stopped`.

### Delete a Challenge

```
DELETE /api/v1/vuln-lab/challenges/{challenge_id}
```

Deletes the challenge record from the database. Running challenges must be stopped first.

### Get Statistics

```
GET /api/v1/vuln-lab/stats
```

Returns aggregated statistics across all challenges.

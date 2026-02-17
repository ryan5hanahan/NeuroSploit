# Functional Requirements

## Scanning

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-001 | System shall allow users to create scans targeting one or more URLs | Implemented | High |
| FR-002 | System shall support scan types: quick, full, custom | Implemented | High |
| FR-003 | System shall execute scans through phases: recon, testing, reporting | Implemented | High |
| FR-004 | System shall provide real-time scan progress via WebSocket (`/ws/scan/{scan_id}`) | Implemented | High |
| FR-005 | System shall allow pausing, resuming, and stopping scans | Implemented | Medium |
| FR-006 | System shall allow skipping forward to a later scan phase | Implemented | Medium |
| FR-007 | System shall auto-generate HTML reports on scan completion (`auto_generated=True`) | Implemented | High |
| FR-008 | System shall auto-generate partial reports when scans are stopped (`is_partial=True`) | Implemented | Medium |
| FR-009 | System shall support repeating (cloning + auto-starting) completed scans via `repeated_from_id` | Implemented | Medium |
| FR-010 | System shall enforce maximum concurrent scan limits (`MAX_CONCURRENT_SCANS`, default 3) returning HTTP 429 when exceeded | Implemented | Medium |
| FR-011 | System shall support scan comparison with structured vulnerability diff (new, resolved, persistent) | Implemented | Low |
| FR-012 | System shall support authenticated scanning with auth types: cookie, bearer, basic, header | Implemented | High |
| FR-013 | System shall support custom HTTP headers per scan | Implemented | Medium |
| FR-014 | System shall support tradecraft TTP association with scans via `scan_tradecraft` junction table | Implemented | Low |

## Vulnerability Detection

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-015 | System shall support 100+ vulnerability types across 11 categories via VulnerabilityRegistry | Implemented | High |
| FR-016 | System shall use LLM analysis to identify attack vectors and generate targeted test commands | Implemented | High |
| FR-017 | System shall generate and test payloads per vulnerability type via PayloadGenerator | Implemented | High |
| FR-018 | System shall verify findings with ResponseVerifier, NegativeControlEngine, and ConfidenceScorer | Implemented | High |
| FR-019 | System shall assign CVSS 3.1 scores, CVSS vectors, and CWE IDs to findings | Implemented | High |
| FR-020 | System shall support manual validation workflow with statuses: ai_confirmed, ai_rejected, validated, false_positive, pending_review | Implemented | Medium |
| FR-021 | System shall detect and adapt to Web Application Firewalls via WAFDetector and StrategyAdapter | Implemented | Medium |
| FR-022 | System shall support multi-step exploit chains via ChainEngine | Implemented | Medium |
| FR-023 | System shall learn auth patterns during scans via AccessControlLearner | Implemented | Medium |

## CTF Mode

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-024 | System shall support multi-agent CTF pipeline via CTFCoordinator with configurable agent count (2-6) | Implemented | High |
| FR-025 | System shall detect flags from 7 CTF platforms via compiled regex patterns | Implemented | High |
| FR-026 | System shall support custom flag regex patterns provided by user | Implemented | Medium |
| FR-027 | System shall auto-submit captured flags to CTF platform APIs when flag submission URL is configured | Implemented | Medium |
| FR-028 | System shall run 10 quick-win exploit probes in parallel (SQLi login, default creds, admin, files, XSS, IDOR, redirect, traversal, API disclosure, registration) | Implemented | High |
| FR-029 | System shall harvest and reuse credentials from successful logins (JWT extraction from token, access_token, authentication.token, data.token fields) | Implemented | Medium |
| FR-030 | System shall run browser-based probes for DOM XSS (5 URLs x 2 payloads) and hidden pages with SPA fallback detection | Implemented | Medium |
| FR-031 | System shall filter irrelevant vulnerability types for web CTF testing (9 cloud/container/infra types excluded) | Implemented | Low |
| FR-032 | CTF pipeline endpoint shall be `POST /api/v1/vuln-lab/run` with `ctf_mode: true` (separate from scan API) | Implemented | High |

## Vulnerability Lab

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-033 | System shall allow isolated testing of individual vulnerability types via VulnLabChallenge | Implemented | High |
| FR-034 | System shall track challenge results (detected/not_detected/error) and detection rates | Implemented | Medium |
| FR-035 | System shall provide aggregated statistics per vulnerability type and category | Implemented | Medium |
| FR-036 | System shall persist challenge logs as JSON list in vuln_lab_challenges table | Implemented | Low |

## Reporting

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-037 | System shall generate self-contained HTML reports with executive summary, findings detail, and recommendations | Implemented | High |
| FR-038 | System shall include CTF-specific sections (flags table, timeline chart, submission stats) when ctf_data is present | Implemented | Medium |
| FR-039 | System shall embed screenshots as base64 data URIs in findings, with filesystem fallback from `reports/screenshots/{finding_id}/` | Implemented | Low |
| FR-040 | System shall support dark and light report themes via ReportConfig | Implemented | Low |
| FR-041 | System shall calculate risk scores (0-100) and risk levels (HIGH/MEDIUM/LOW) in executive summary | Implemented | Medium |

## Settings and Configuration

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-042 | System shall support 6 LLM providers: Claude (Anthropic SDK), OpenAI (OpenAI SDK), Gemini (HTTP API), Bedrock (boto3), Ollama (localhost HTTP), OpenRouter (OpenAI-compatible) | Implemented | High |
| FR-043 | System shall support 8 feature toggles persisted to .env: ENABLE_MODEL_ROUTING, ENABLE_KNOWLEDGE_AUGMENTATION, ENABLE_BROWSER_VALIDATION, ENABLE_EXTENDED_THINKING, AGGRESSIVE_MODE, ENABLE_TRACING, ENABLE_PERSISTENT_MEMORY, ENABLE_BUGBOUNTY_INTEGRATION | Implemented | High |
| FR-044 | System shall provide LLM connection testing with response time measurement and result persistence to llm_test_results table | Implemented | Medium |
| FR-045 | System shall check and report installed security tools | Implemented | Low |
| FR-046 | System shall persist scan defaults (MAX_CONCURRENT_SCANS, DEFAULT_SCAN_TYPE, RECON_ENABLED_BY_DEFAULT) to .env | Implemented | Medium |

## Integration

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-047 | System shall expose 28 MCP tools across 4 categories (core: 8, sandbox: 4, ProjectDiscovery: 9, proxy: 7) for external LLM agents | Implemented | Medium |
| FR-048 | System shall support Docker sandbox for isolated security tool execution with persistent containers | Implemented | Medium |
| FR-049 | System shall support cross-scan learning via AgentMemory (AttackPatternMemory, TargetFingerprint, SuccessfulPayload) | Implemented | Medium |
| FR-050 | System shall support knowledge augmentation from bug bounty dataset (1,826 entries, 2.9MB) | Implemented | Low |

## Prompt Management

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-051 | System shall support custom and preset prompt templates stored in prompts table | Implemented | Medium |
| FR-052 | System shall support AI-extracted vulnerability type parsing from prompt content | Implemented | Low |
| FR-053 | System shall allow scans to reference prompts by ID or use inline custom_prompt | Implemented | Medium |

## Tradecraft

| ID | Requirement | Status | Priority |
|----|------------|--------|----------|
| FR-054 | System shall maintain a library of tradecraft TTPs (evasion, reconnaissance, exploitation, validation) | Implemented | Low |
| FR-055 | System shall support built-in and user-created tradecraft entries | Implemented | Low |
| FR-056 | System shall allow TTPs to be associated with individual scans via scan_tradecraft junction | Implemented | Low |

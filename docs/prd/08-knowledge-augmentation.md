# Knowledge Augmentation

## Overview

Retrieval-based knowledge augmentation from a curated bug bounty dataset. The `KnowledgeAugmentor` provides pattern recognition context to agent prompts during vulnerability testing, giving agents real-world exploitation examples and techniques relevant to the target vulnerability type.

## Dataset

- **File**: `models/bug-bounty/bugbounty_finetuning_dataset.json`
- **Size**: 1,826 entries, approximately 2.9MB
- **Content**: Real-world bug bounty report patterns including vulnerability descriptions, exploitation techniques, and remediation guidance

## How It Works

1. `KnowledgeAugmentor` lazy-loads the dataset on first use.
2. On load, it builds a keyword index mapping vulnerability types to entry indices across 19 categories:
   - `xss`, `sqli`, `ssrf`, `idor`, `rce`, `lfi`, `auth_bypass`, `csrf`, `open_redirect`, `xxe`, `ssti`, `race_condition`, `graphql`, `api`, `deserialization`, `upload`, `cors`, `subdomain_takeover`, `information_disclosure`
3. When an agent requests context for a vulnerability type, the augmentor retrieves up to `max_patterns` (default: 3) matching entries from the index.
4. Entries are formatted as reference material and injected into the agent's prompt.
5. The model is explicitly instructed to adapt patterns to the current target, not copy them verbatim.

## Configuration

- **Feature toggle**: `ENABLE_KNOWLEDGE_AUGMENTATION` environment variable.
- **`dataset_path`**: Path to the JSON dataset file. Default: `models/bug-bounty/bugbounty_finetuning_dataset.json`.
- **`max_patterns`**: Maximum patterns returned per query. Default: 3. Configured via `knowledge_augmentation.max_patterns_per_query` in `config.json`.
- **Docker**: Both `docker/Dockerfile.backend` and `docker/Dockerfile.backend.lite` include `COPY models/ ./models/` to make the dataset available in containers.

## Integration Points

| Component | Usage |
|-----------|-------|
| `BaseAgent` (CLI path) | Reads toggle from env, initializes `KnowledgeAugmentor`, wired into `_ai_analyze_context()` |
| `AutonomousAgent` (web UI scan path) | Reads toggle from env, calls `get_augmented_context(vulnerability_type=...)` for prompt enrichment |
| `config.json` | `knowledge_augmentation` key holds `dataset_path` and `max_patterns_per_query` |

### BaseAgent Integration

The `BaseAgent._ai_analyze_context()` method checks if knowledge augmentation is enabled. If so, it calls the augmentor with the current vulnerability type and prepends the returned patterns to the analysis prompt. This was previously dead code in `get_augmented_context()` that has been wired into the active code path.

### AutonomousAgent Integration

The `AutonomousAgent` calls `get_augmented_context(vulnerability_type=...)` (note: the parameter name is `vulnerability_type`, not `vuln_type`) and merges the returned context into the agent's working prompt.

## Limitations

- Dataset is static -- no automatic updates or community contribution pipeline.
- Retrieval is keyword-based only. No semantic search or vector embeddings.
- English-language patterns only.
- Some entries may reference vulnerabilities that have since been patched on their original platforms.

# sploit.ai Documentation

## Overview

sploit.ai is an AI-powered penetration testing platform that uses large language models to guide automated vulnerability discovery, testing, and reporting for web applications.

This documentation captures the current state of the system as-built and serves as a reference for contributors.

## Document Structure

### Product Requirements (docs/prd/)

Product-level documentation describing what each feature does, who uses it, and its current capabilities.

| Document | Description |
|----------|-------------|
| [00-overview.md](prd/00-overview.md) | Product vision, goals, target users |
| [01-scan-engine.md](prd/01-scan-engine.md) | Core scan pipeline: recon, analysis, testing |
| [02-ctf-mode.md](prd/02-ctf-mode.md) | CTF coordinator pipeline, flag detection and submission |
| [03-vuln-lab.md](prd/03-vuln-lab.md) | Vulnerability lab runner for isolated target testing |
| [04-reporting.md](prd/04-reporting.md) | HTML report generation and findings format |
| [05-settings-config.md](prd/05-settings-config.md) | Feature toggles, config.json, .env settings |
| [06-llm-integration.md](prd/06-llm-integration.md) | Multi-LLM support, model routing, providers |
| [07-browser-validation.md](prd/07-browser-validation.md) | Playwright-based browser probes |
| [08-knowledge-augmentation.md](prd/08-knowledge-augmentation.md) | Bug bounty dataset and vulnerability context |
| [09-mcp-server.md](prd/09-mcp-server.md) | MCP tool server for external LLM agents |
| [10-frontend.md](prd/10-frontend.md) | React UI: dashboard, scans, settings, reports |

### Technical Specification (docs/tech-spec/)

Implementation-level documentation describing how each component works.

| Document | Description |
|----------|-------------|
| [00-architecture.md](tech-spec/00-architecture.md) | System architecture, component diagram, data flow |
| [01-backend-api.md](tech-spec/01-backend-api.md) | FastAPI endpoints, request/response schemas |
| [02-scan-service.md](tech-spec/02-scan-service.md) | ScanService internals, AutonomousAgent lifecycle |
| [03-ctf-coordinator.md](tech-spec/03-ctf-coordinator.md) | CTF pipeline phases, probe methods, agent dispatch |
| [04-llm-manager.md](tech-spec/04-llm-manager.md) | LLMManager, provider abstraction, model routing |
| [05-flag-detection.md](tech-spec/05-flag-detection.md) | Flag detector patterns, submitter protocol |
| [06-report-generator.md](tech-spec/06-report-generator.md) | HTMLReportGenerator internals |
| [07-agents.md](tech-spec/07-agents.md) | Agent architecture: BaseAgent vs AutonomousAgent |
| [08-database.md](tech-spec/08-database.md) | SQLite schema, scan/finding models |
| [09-docker.md](tech-spec/09-docker.md) | Dockerfile variants, compose config |
| [10-security.md](tech-spec/10-security.md) | OPSEC proxy, credential handling |
| [11-frontend-arch.md](tech-spec/11-frontend-arch.md) | React app structure, API client |

### Requirements (docs/requirements/)

Structured requirements with unique IDs.

| Document | Description |
|----------|-------------|
| [functional.md](requirements/functional.md) | Functional requirements (FR-001 through FR-056) |
| [non-functional.md](requirements/non-functional.md) | Performance, security, reliability (NFR-001 through NFR-035) |
| [integration.md](requirements/integration.md) | External integration specs |

## Recommended Reading Order

1. **New to the project**: Start with `prd/00-overview.md`, then `tech-spec/00-architecture.md`
2. **Contributing to scanning**: `prd/01-scan-engine.md` → `tech-spec/02-scan-service.md` → `tech-spec/07-agents.md`
3. **Working on CTF mode**: `prd/02-ctf-mode.md` → `tech-spec/03-ctf-coordinator.md` → `tech-spec/05-flag-detection.md`
4. **Frontend development**: `prd/10-frontend.md` → `tech-spec/11-frontend-arch.md` → `tech-spec/01-backend-api.md`
5. **LLM integration**: `prd/06-llm-integration.md` → `tech-spec/04-llm-manager.md`
6. **Deployment**: `tech-spec/09-docker.md` → `prd/05-settings-config.md`

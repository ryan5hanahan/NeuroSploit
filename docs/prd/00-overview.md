# Product Overview

## What is NeuroSploit?

NeuroSploit v3 is an AI-powered penetration testing platform. It uses large language models to autonomously discover, test, and report web application vulnerabilities. The system combines traditional security tooling (nmap, sqlmap, nuclei, ProjectDiscovery suite) with LLM-driven analysis to guide vulnerability discovery, generate proof-of-concept payloads, verify findings, and produce professional HTML security assessment reports.

## Vision

Replace manual penetration testing workflows with AI-guided automation. Large language models analyze attack surfaces based on reconnaissance data, generate targeted payloads for discovered endpoints, verify that findings are genuine (eliminating false positives through negative control testing and confidence scoring), and produce professional reports suitable for client delivery. The platform handles the full lifecycle from target intake through report generation without requiring manual intervention, while still supporting human-in-the-loop controls (pause, resume, stop, skip phases).

## Target Users

### Penetration Testers
Augment manual testing workflows. NeuroSploit handles the initial reconnaissance, automated vulnerability scanning, and report generation, freeing pentesters to focus on complex business logic and chained exploit paths.

### CTF Competitors
Automated challenge solving via the multi-agent CTF pipeline. The system deploys multiple specialized agents in parallel to maximize flag capture rate against web-based CTF targets.

### Security Researchers
Vulnerability pattern analysis across 100+ vulnerability types. The vulnerability lab mode supports isolated testing of individual vuln types against training platforms, with detection rate tracking across categories.

### DevSecOps Teams
Continuous security testing integrated into development workflows. Scan targets via API, receive structured findings with CVSS scores, CWE IDs, and remediation guidance.

## Core Value Proposition

- **LLM-guided vulnerability discovery** with real proof-of-concept generation -- not just signature matching, but AI-analyzed attack surface assessment that generates targeted payloads for each endpoint
- **Multi-provider LLM support** -- Claude (Anthropic), GPT (OpenAI), Gemini (Google), Bedrock (AWS), OpenRouter, and Ollama for local models
- **100+ vulnerability type coverage** across 11 categories (injection, file access, authentication, authorization, client-side, infrastructure, business logic, data exposure, request forgery, advanced injection, cloud/supply chain)
- **Professional HTML reporting** with executive summaries, CVSS scoring, CWE mapping, PoC payloads, evidence screenshots, and remediation guidance

## Key Capabilities

- **Autonomous scanning with AI analysis**: Scans progress through recon, AI-driven analysis, targeted testing, and reporting phases without manual intervention
- **Multi-agent CTF pipeline**: Coordinated pipeline with recon agent, quick-win probes, credential harvesting, browser probes, LLM-prioritized vuln distribution, and parallel testing agents
- **100+ vulnerability types across 11 categories**: Injection (XSS, SQLi, command injection, SSTI, NoSQL), advanced injection (LDAP, XPath, GraphQL, CRLF), file access (LFI, RFI, XXE, file upload), request forgery (SSRF, CSRF), authentication, authorization, client-side, infrastructure, business logic, data exposure, cloud/supply chain
- **Browser-based validation via Playwright**: DOM XSS detection with dialog monitoring, hidden page discovery, screenshot capture for evidence
- **Real-time WebSocket progress**: Live scan status, phase transitions, log streaming, and finding notifications via WebSocket at `/ws/scan/{scan_id}`
- **Professional HTML reports**: Dark-themed reports with severity-based color coding, executive summaries, finding details with PoC payloads, CVSS scores, CWE references, impact analysis, and remediation guidance
- **Docker-based security tool sandbox (Kali)**: Containerized execution of nuclei, naabu, nmap, httpx, subfinder, katana, sqlmap, and 20+ additional tools with resource limits and auto-cleanup
- **MCP server for tool integration**: Model Context Protocol server exposing pentest tools (screenshots, payload delivery, DNS, port scan, tech detection, subdomain enumeration, ProjectDiscovery suite, sandbox execution, opsec profiles) for use by external LLM agents
- **Multi-LLM support**: Claude, GPT-4, Gemini Pro, AWS Bedrock Claude, OpenRouter (any model), Ollama (local models)
- **Model routing by task type**: Route reasoning tasks to Bedrock Claude, analysis/generation/validation tasks to Gemini, configurable per task type
- **Knowledge augmentation from bug bounty dataset**: 1,826-entry fine-tuning dataset providing vulnerability-specific context to improve detection accuracy
- **Tradecraft TTP library**: Reusable tactics, techniques, and procedures that can be attached to scans for targeted testing approaches
- **Scan comparison and repeat**: Clone and re-run completed scans, structured diff between any two scans showing new/resolved/persistent/changed vulnerabilities and endpoints

## Current Limitations

- **Single-target scanning only**: No batch or portfolio scanning. Each scan targets one URL (or a small list of URLs for the same application). There is no campaign management or multi-application orchestration.
- **No scheduled scan persistence across restarts**: Scans run in-memory as background asyncio tasks. If the server restarts, running scans are lost. There is no durable job queue or scan resume mechanism.
- **CTF mode optimized primarily for web challenges**: The CTF pipeline's quick-win probes, credential harvesting, and browser probes are designed for web application CTFs (particularly Juice Shop-style). Binary exploitation, cryptography, and forensics challenges are not supported.
- **Browser validation requires Playwright/Chromium**: The browser-based validation features (DOM XSS detection, hidden page discovery, screenshot capture) require Playwright and Chromium to be installed. Both Docker images include these dependencies, but local development requires separate installation.
- **No user authentication or multi-tenancy**: The platform has no user accounts, login, or access control. All data (scans, findings, reports) is accessible to anyone with network access to the server. The system is designed for single-user or trusted-team deployment.

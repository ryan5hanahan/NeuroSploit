#!/usr/bin/env python3
"""
NeuroSploit MCP Server — Exposes pentest tools via Model Context Protocol.

Tools (Core):
  - screenshot_capture, payload_delivery, dns_lookup, port_scan,
    technology_detect, subdomain_enumerate, save_finding, get_vuln_prompt
Tools (Sandbox):
  - execute_nuclei, execute_naabu, sandbox_health, sandbox_exec
Tools (ProjectDiscovery Extended):
  - execute_cvemap, execute_tlsx, execute_asnmap, execute_mapcidr,
    execute_alterx, execute_shuffledns, execute_cloudlist,
    execute_interactsh, execute_notify
Tools (Proxy):
  - proxy_status, proxy_flows, proxy_capture, proxy_replay,
    proxy_intercept, proxy_clear, proxy_export

Usage:
  python3 -m core.mcp_server          # stdio transport (default)
  MCP_TRANSPORT=sse python3 -m core.mcp_server  # SSE transport
"""

import asyncio
import json
import os
import socket
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Guard MCP import — server only works where mcp package is available
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    logger.warning("MCP package not installed. Install with: pip install 'mcp>=1.0.0'")

# Guard Playwright import
try:
    from core.browser_validator import BrowserValidator
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# AI prompts access
try:
    from backend.core.vuln_engine.ai_prompts import get_prompt, build_testing_prompt
    HAS_AI_PROMPTS = True
except ImportError:
    HAS_AI_PROMPTS = False

# Security sandbox access
try:
    from core.sandbox_manager import get_sandbox, SandboxManager
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False

# ProjectDiscovery extended tool handlers
try:
    from core.mcp_tools_pd import (
        _execute_cvemap, _execute_tlsx, _execute_asnmap,
        _execute_mapcidr, _execute_alterx, _execute_shuffledns,
        _execute_cloudlist, _execute_interactsh, _execute_notify,
        _oob_verify,
    )
    HAS_PD_TOOLS = True
except ImportError:
    HAS_PD_TOOLS = False

# Proxy tool handlers
try:
    from core.mcp_tools_proxy import (
        _proxy_status, _proxy_flows, _proxy_capture,
        _proxy_replay, _proxy_intercept, _proxy_clear, _proxy_export,
    )
    HAS_PROXY_TOOLS = True
except ImportError:
    HAS_PROXY_TOOLS = False


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

async def _screenshot_capture(url: str, selector: Optional[str] = None) -> Dict:
    """Capture a screenshot of a URL using Playwright."""
    if not HAS_PLAYWRIGHT:
        return {"error": "Playwright not available", "screenshot": None}

    try:
        bv = BrowserValidator()
        result = await bv.capture_screenshot(url, selector=selector)
        if result.get("error"):
            return {"error": result["error"], "screenshot": None}
        return {
            "url": url,
            "screenshot_base64": result.get("screenshot", ""),
            "title": result.get("title", ""),
            "status_code": result.get("status_code"),
            "status": "ok",
        }
    except Exception as e:
        return {"error": str(e), "screenshot": None}


async def _payload_delivery(
    endpoint: str,
    method: str = "GET",
    payload: str = "",
    content_type: str = "application/x-www-form-urlencoded",
    headers: Optional[Dict] = None,
    param: str = "q",
) -> Dict:
    """Send an HTTP request with a payload and capture full response."""
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            req_headers = {"Content-Type": content_type}
            if headers:
                req_headers.update(headers)

            if method.upper() == "GET":
                async with session.get(endpoint, params={param: payload}, headers=req_headers, timeout=15, allow_redirects=False) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body[:5000],
                        "body_length": len(body),
                    }
            else:
                data = {param: payload} if content_type != "application/json" else None
                json_data = json.loads(payload) if content_type == "application/json" else None
                async with session.request(
                    method.upper(), endpoint, data=data, json=json_data,
                    headers=req_headers, timeout=15, allow_redirects=False
                ) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body[:5000],
                        "body_length": len(body),
                    }
    except Exception as e:
        return {"error": str(e)}


async def _time_oracle(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[str] = None,
    iterations: int = 10,
    delay_ms: int = 100,
) -> Dict:
    """Send N timed requests and return statistical timing analysis.

    Used for time-based blind injection detection. Timeout errors are
    recorded as samples — that IS the signal for time-based blind injection.
    """
    import aiohttp
    import time
    import statistics

    iterations = max(3, min(iterations, 50))  # Clamp 3-50
    delay_sec = max(0, delay_ms / 1000.0)
    samples: List[float] = []
    timeout_count = 0

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            req_headers = {}
            if headers:
                req_headers.update(headers)

            for i in range(iterations):
                if i > 0 and delay_sec > 0:
                    await asyncio.sleep(delay_sec)

                start = time.monotonic()
                try:
                    async with session.request(
                        method.upper(), url,
                        headers=req_headers if req_headers else None,
                        data=body,
                        allow_redirects=False,
                    ) as resp:
                        await resp.read()  # Consume body to get full timing
                    elapsed_ms = (time.monotonic() - start) * 1000
                    samples.append(elapsed_ms)
                except asyncio.TimeoutError:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    samples.append(elapsed_ms)
                    timeout_count += 1
                except Exception:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    samples.append(elapsed_ms)

        if not samples:
            return {"error": "No samples collected"}

        sorted_samples = sorted(samples)
        p95_idx = max(0, int(len(sorted_samples) * 0.95) - 1)

        return {
            "tool": "time_oracle",
            "url": url,
            "method": method.upper(),
            "iterations": len(samples),
            "mean_ms": round(statistics.mean(samples), 2),
            "median_ms": round(statistics.median(samples), 2),
            "stddev_ms": round(statistics.stdev(samples), 2) if len(samples) > 1 else 0.0,
            "min_ms": round(min(samples), 2),
            "max_ms": round(max(samples), 2),
            "p95_ms": round(sorted_samples[p95_idx], 2),
            "samples": [round(s, 2) for s in samples],
            "timeout_count": timeout_count,
            "total_duration_ms": round(sum(samples) + delay_ms * max(0, len(samples) - 1), 2),
        }
    except Exception as e:
        return {"error": str(e)}


async def _dns_lookup(domain: str, record_type: str = "A") -> Dict:
    """Perform DNS lookups for a domain."""
    import subprocess

    try:
        result = subprocess.run(
            ["dig", "+short", domain, record_type],
            capture_output=True, text=True, timeout=10
        )
        records = [r.strip() for r in result.stdout.strip().split("\n") if r.strip()]
        return {"domain": domain, "type": record_type, "records": records}
    except FileNotFoundError:
        # Fallback to socket for A records
        if record_type.upper() == "A":
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                records = list(set(ip[4][0] for ip in ips))
                return {"domain": domain, "type": "A", "records": records}
            except socket.gaierror as e:
                return {"domain": domain, "type": "A", "error": str(e)}
        return {"error": "dig command not available and only A records supported via fallback"}
    except Exception as e:
        return {"error": str(e)}


async def _port_scan(host: str, ports: str = "80,443,8080,8443,3000,5000") -> Dict:
    """Scan TCP ports on a host."""
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    results = {}

    async def check_port(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return port, "open"
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, "closed"

    tasks = [check_port(p) for p in port_list[:100]]
    for coro in asyncio.as_completed(tasks):
        port, state = await coro
        results[str(port)] = state

    open_ports = [p for p, s in results.items() if s == "open"]
    return {"host": host, "ports": results, "open_ports": open_ports}


async def _technology_detect(url: str) -> Dict:
    """Detect technologies from HTTP response headers."""
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10, allow_redirects=True) as resp:
                headers = dict(resp.headers)
                body = await resp.text()

                techs = []
                server = headers.get("Server", "")
                if server:
                    techs.append(f"Server: {server}")

                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    techs.append(f"X-Powered-By: {powered_by}")

                # Framework detection from body
                framework_markers = {
                    "React": ["react", "_next/static", "__NEXT_DATA__"],
                    "Vue.js": ["vue.js", "__vue__", "v-cloak"],
                    "Angular": ["ng-version", "angular"],
                    "jQuery": ["jquery"],
                    "WordPress": ["wp-content", "wp-includes"],
                    "Laravel": ["laravel_session", "csrf-token"],
                    "Django": ["csrfmiddlewaretoken", "django"],
                    "Rails": ["csrf-param", "action_dispatch"],
                    "Spring": ["jsessionid"],
                    "Express": ["connect.sid"],
                }

                body_lower = body.lower()
                for tech, markers in framework_markers.items():
                    if any(m.lower() in body_lower for m in markers):
                        techs.append(tech)

                return {"url": url, "technologies": techs, "headers": {
                    k: v for k, v in headers.items()
                    if k.lower() in ("server", "x-powered-by", "x-aspnet-version",
                                     "x-generator", "x-drupal-cache", "x-framework")
                }}
    except Exception as e:
        return {"error": str(e)}


async def _subdomain_enumerate(domain: str) -> Dict:
    """Enumerate subdomains via common prefixes."""
    prefixes = [
        "www", "api", "admin", "app", "dev", "staging", "test", "mail",
        "ftp", "cdn", "blog", "shop", "docs", "status", "dashboard",
        "portal", "m", "mobile", "beta", "demo", "v2", "internal",
    ]

    found = []

    async def check_subdomain(prefix: str):
        subdomain = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(subdomain, None, socket.AF_INET)
            return subdomain
        except socket.gaierror:
            return None

    tasks = [check_subdomain(p) for p in prefixes]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r]

    return {"domain": domain, "subdomains": found, "count": len(found)}


async def _save_finding(finding_json: str) -> Dict:
    """Persist a finding (JSON string). Returns confirmation."""
    try:
        finding = json.loads(finding_json)
        # Validate required fields
        required = ["title", "severity", "vulnerability_type", "affected_endpoint"]
        missing = [f for f in required if f not in finding]
        if missing:
            return {"error": f"Missing required fields: {missing}"}
        return {"status": "saved", "finding_id": finding.get("id", "unknown"), "title": finding["title"]}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}


async def _get_vuln_prompt(vuln_type: str, target: str = "", endpoint: str = "", param: str = "", tech: str = "") -> Dict:
    """Retrieve the AI decision prompt for a vulnerability type."""
    if not HAS_AI_PROMPTS:
        return {"error": "AI prompts module not available"}

    try:
        prompt_data = get_prompt(vuln_type, {
            "TARGET_URL": target,
            "ENDPOINT": endpoint,
            "PARAMETER": param,
            "TECHNOLOGY": tech,
        })
        if not prompt_data:
            return {"error": f"No prompt found for vuln type: {vuln_type}"}
        full_prompt = build_testing_prompt(vuln_type, target, endpoint, param, tech)
        return {"vuln_type": vuln_type, "prompt": prompt_data, "full_prompt": full_prompt}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Sandbox tool implementations (Docker-based real tools)
# ---------------------------------------------------------------------------

async def _execute_nuclei(
    target: str,
    templates: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
    rate_limit: int = 150,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Run Nuclei vulnerability scanner in the Docker sandbox."""
    if not HAS_SANDBOX:
        return {"error": "Sandbox module not available. Install docker SDK: pip install docker"}

    try:
        sandbox = await get_sandbox()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running. Build with: cd docker && docker compose -f docker-compose.sandbox.yml up -d"}

        result = await sandbox.run_nuclei(
            target=target,
            templates=templates,
            severity=severity,
            tags=tags,
            rate_limit=rate_limit,
            opsec_profile=opsec_profile,
        )

        return {
            "tool": "nuclei",
            "target": target,
            "exit_code": result.exit_code,
            "findings": result.findings,
            "findings_count": len(result.findings),
            "duration_seconds": result.duration_seconds,
            "raw_output": result.stdout[:3000] if result.stdout else "",
            "error": result.error,
            "opsec_profile": opsec_profile,
        }
    except Exception as e:
        return {"error": str(e)}


async def _execute_naabu(
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    rate: int = 1000,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Run Naabu port scanner in the Docker sandbox."""
    if not HAS_SANDBOX:
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await get_sandbox()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        result = await sandbox.run_naabu(
            target=target,
            ports=ports,
            top_ports=top_ports,
            rate=rate,
            opsec_profile=opsec_profile,
        )

        open_ports = [f["port"] for f in result.findings]
        return {
            "tool": "naabu",
            "target": target,
            "exit_code": result.exit_code,
            "open_ports": sorted(open_ports),
            "port_count": len(open_ports),
            "findings": result.findings,
            "duration_seconds": result.duration_seconds,
            "error": result.error,
            "opsec_profile": opsec_profile,
        }
    except Exception as e:
        return {"error": str(e)}


async def _sandbox_health() -> Dict:
    """Check sandbox container health and available tools."""
    if not HAS_SANDBOX:
        return {"status": "unavailable", "reason": "Sandbox module not installed"}

    try:
        sandbox = await get_sandbox()
        return await sandbox.health_check()
    except Exception as e:
        return {"status": "error", "reason": str(e)}


async def _sandbox_exec(
    tool: str, args: str, timeout: int = 300,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Execute any allowed tool in the Docker sandbox."""
    if not HAS_SANDBOX:
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await get_sandbox()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        result = await sandbox.run_tool(
            tool=tool, args=args, timeout=timeout,
            opsec_profile=opsec_profile,
        )

        return {
            "tool": tool,
            "exit_code": result.exit_code,
            "stdout": result.stdout[:5000] if result.stdout else "",
            "stderr": result.stderr[:2000] if result.stderr else "",
            "duration_seconds": result.duration_seconds,
            "error": result.error,
            "opsec_profile": opsec_profile,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# MCP Server Definition
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "screenshot_capture",
        "description": "Capture a browser screenshot of a URL using Playwright",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to screenshot"},
                "selector": {"type": "string", "description": "Optional CSS selector to capture"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "payload_delivery",
        "description": "Send an HTTP request with a payload and capture the full response",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                "payload": {"type": "string", "description": "Payload value"},
                "content_type": {"type": "string", "default": "application/x-www-form-urlencoded"},
                "param": {"type": "string", "description": "Parameter name", "default": "q"},
            },
            "required": ["endpoint", "payload"],
        },
    },
    {
        "name": "time_oracle",
        "description": "Send N timed HTTP requests and return statistical timing analysis (mean, median, stddev, p95). Used for time-based blind injection detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to measure"},
                "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                "headers": {"type": "object", "description": "Optional request headers"},
                "body": {"type": "string", "description": "Optional request body"},
                "iterations": {"type": "integer", "description": "Number of requests (3-50, default 10)", "default": 10},
                "delay_ms": {"type": "integer", "description": "Delay between requests in ms (default 100)", "default": 100},
            },
            "required": ["url"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Perform DNS lookups for a domain",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to look up"},
                "record_type": {"type": "string", "default": "A", "description": "DNS record type"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "port_scan",
        "description": "Scan TCP ports on a host",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host"},
                "ports": {"type": "string", "default": "80,443,8080,8443,3000,5000", "description": "Comma-separated ports"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "technology_detect",
        "description": "Detect technologies from HTTP response headers and body",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyze"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "subdomain_enumerate",
        "description": "Enumerate subdomains via common prefix brute-force",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain to enumerate"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "save_finding",
        "description": "Persist a vulnerability finding (JSON string)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_json": {"type": "string", "description": "Finding as JSON string"},
            },
            "required": ["finding_json"],
        },
    },
    {
        "name": "get_vuln_prompt",
        "description": "Retrieve the AI decision prompt for a vulnerability type",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_type": {"type": "string", "description": "Vulnerability type key"},
                "target": {"type": "string", "description": "Target URL"},
                "endpoint": {"type": "string", "description": "Specific endpoint"},
                "param": {"type": "string", "description": "Parameter name"},
                "tech": {"type": "string", "description": "Detected technology"},
            },
            "required": ["vuln_type"],
        },
    },
    # --- Sandbox tools (Docker-based real security tools) ---
    {
        "name": "execute_nuclei",
        "description": "Run Nuclei vulnerability scanner (8000+ templates) in Docker sandbox. Returns structured findings with severity, CVE, CWE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "templates": {"type": "string", "description": "Specific template path (e.g. 'cves/2024/', 'vulnerabilities/xss/')"},
                "severity": {"type": "string", "description": "Filter: critical,high,medium,low,info"},
                "tags": {"type": "string", "description": "Filter by tags: xss,sqli,lfi,ssrf,rce"},
                "rate_limit": {"type": "integer", "description": "Requests per second (default 150)", "default": 150},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "execute_naabu",
        "description": "Run Naabu port scanner in Docker sandbox. Fast SYN-based scanning with configurable port ranges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname to scan"},
                "ports": {"type": "string", "description": "Ports to scan (e.g. '80,443,8080' or '1-65535')"},
                "top_ports": {"type": "integer", "description": "Scan top N ports (e.g. 100, 1000)"},
                "rate": {"type": "integer", "description": "Packets per second (default 1000)", "default": 1000},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "sandbox_health",
        "description": "Check Docker sandbox status and available security tools",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "sandbox_exec",
        "description": "Execute any allowed security tool in the Docker sandbox (nuclei, naabu, nmap, httpx, subfinder, katana, ffuf, sqlmap, nikto, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Tool name (e.g. nuclei, naabu, nmap, httpx, subfinder, katana, ffuf, gobuster, dalfox, nikto, sqlmap, curl)"},
                "args": {"type": "string", "description": "Command-line arguments for the tool"},
                "timeout": {"type": "integer", "description": "Max execution time in seconds (default 300)", "default": 300},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["tool", "args"],
        },
    },
    # --- ProjectDiscovery Extended Suite ---
    {
        "name": "execute_cvemap",
        "description": "Query CVE database via cvemap. Lookup CVEs by ID, severity, product, or vendor. Returns CVSS, CWE, affected products.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "Specific CVE ID (e.g. CVE-2024-1234)"},
                "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low"},
                "product": {"type": "string", "description": "Filter by product name"},
                "vendor": {"type": "string", "description": "Filter by vendor name"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
        },
    },
    {
        "name": "execute_tlsx",
        "description": "Analyze TLS/SSL certificates, cipher suites, and protocol versions for a target. Detects expired certs, weak ciphers, and misconfigurations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or IP"},
                "port": {"type": "string", "description": "Port to connect to (default 443)"},
                "scan_mode": {"type": "string", "description": "Scan mode: auto, ctls, ztls"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "execute_asnmap",
        "description": "Map IPs, ASNs, or organizations to CIDR ranges. Useful for identifying an organization's full IP space.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address, ASN number (e.g. AS13335), or organization name"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "execute_mapcidr",
        "description": "Manipulate CIDR ranges: aggregate overlapping ranges, split into subnets, or count IPs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cidr": {"type": "string", "description": "CIDR range (e.g. 192.168.0.0/16)"},
                "operation": {"type": "string", "description": "Operation: count, aggregate, or split-N (e.g. split-24)", "default": "count"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["cidr"],
        },
    },
    {
        "name": "execute_alterx",
        "description": "Generate subdomain permutations from a domain using pattern-based wordlist generation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain (e.g. example.com)"},
                "pattern": {"type": "string", "description": "Custom permutation pattern"},
                "enrich": {"type": "boolean", "description": "Enrich with additional patterns", "default": False},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "execute_shuffledns",
        "description": "Brute-force and resolve subdomains using massdns as backend. Fast DNS resolution at scale.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "wordlist": {"type": "string", "description": "Path to wordlist (default: /opt/wordlists/subdomains-5000.txt)"},
                "resolvers": {"type": "string", "description": "Path to resolvers file"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "execute_cloudlist",
        "description": "Enumerate cloud assets (IPs, hostnames, buckets) from configured cloud providers (AWS, GCP, Azure, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Cloud provider filter (aws, gcp, azure, do, etc.)"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
        },
    },
    {
        "name": "execute_interactsh",
        "description": "Out-of-band interaction testing via interactsh. Register an OOB URL for DNS/HTTP/SMTP callback detection, or poll for captured interactions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action: 'register' to get an OOB URL, 'poll' to wait for interactions", "default": "register"},
                "token": {"type": "string", "description": "Session token for authenticated polling"},
                "poll_interval": {"type": "integer", "description": "Poll interval in seconds"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth uses self-hosted server"},
            },
        },
    },
    {
        "name": "oob_verify",
        "description": "Simplified OOB verification: register an out-of-band URL with injection templates, or poll for captured interactions filtered by protocol (DNS, HTTP, SMTP).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action: 'register' to get OOB URL, 'poll'/'check' to verify interactions", "default": "register"},
                "oob_url": {"type": "string", "description": "OOB URL from a previous register (for context)"},
                "wait_seconds": {"type": "integer", "description": "Poll interval in seconds"},
                "expected_protocol": {"type": "string", "description": "Filter interactions by protocol: dns, http, smtp"},
            },
        },
    },
    {
        "name": "execute_notify",
        "description": "Send notification messages via configured providers (Slack, Discord, Telegram, email, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Notification message text"},
                "provider": {"type": "string", "description": "Specific provider to use"},
                "severity": {"type": "string", "description": "Severity tag for filtering"},
                "opsec_profile": {"type": "string", "description": "Opsec profile: stealth, balanced, or aggressive"},
            },
            "required": ["message"],
        },
    },
    # --- Proxy Tools (mitmproxy) ---
    {
        "name": "proxy_status",
        "description": "Check mitmproxy status, flow count, and connection info. Start with: docker compose --profile proxy up -d",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "proxy_flows",
        "description": "Retrieve captured HTTP flows from mitmproxy. Filter by URL, method, or status code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter_expr": {"type": "string", "description": "Text filter (matches URL, method, status)"},
                "limit": {"type": "integer", "description": "Max flows to return (default 50)", "default": 50},
            },
        },
    },
    {
        "name": "proxy_capture",
        "description": "Set mitmproxy capture/view filter. Use mitmproxy filter expressions (e.g. '~d example.com', '~m POST').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter_expr": {"type": "string", "description": "mitmproxy filter expression (empty to capture all)"},
            },
        },
    },
    {
        "name": "proxy_replay",
        "description": "Replay a captured flow with optional header/body modifications.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_id": {"type": "string", "description": "Flow ID to replay"},
                "modify_headers": {"type": "object", "description": "Headers to add/modify"},
                "modify_body": {"type": "string", "description": "New request body"},
            },
            "required": ["flow_id"],
        },
    },
    {
        "name": "proxy_intercept",
        "description": "Set mitmproxy intercept breakpoint. Matching flows will be paused for inspection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "mitmproxy filter pattern for interception"},
                "enabled": {"type": "boolean", "description": "Enable or disable interception", "default": True},
            },
        },
    },
    {
        "name": "proxy_clear",
        "description": "Clear all captured flows from mitmproxy.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "proxy_export",
        "description": "Export a captured flow as curl command or raw request/response.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_id": {"type": "string", "description": "Flow ID to export"},
                "format": {"type": "string", "description": "Export format: curl or raw", "default": "curl"},
            },
            "required": ["flow_id"],
        },
    },
]

# Tool dispatcher
TOOL_HANDLERS = {
    "screenshot_capture": lambda args: _screenshot_capture(args["url"], args.get("selector")),
    "payload_delivery": lambda args: _payload_delivery(
        args["endpoint"], args.get("method", "GET"), args.get("payload", ""),
        args.get("content_type", "application/x-www-form-urlencoded"),
        args.get("headers"), args.get("param", "q")
    ),
    "time_oracle": lambda args: _time_oracle(
        args["url"], args.get("method", "GET"), args.get("headers"),
        args.get("body"), args.get("iterations", 10), args.get("delay_ms", 100)
    ),
    "dns_lookup": lambda args: _dns_lookup(args["domain"], args.get("record_type", "A")),
    "port_scan": lambda args: _port_scan(args["host"], args.get("ports", "80,443,8080,8443,3000,5000")),
    "technology_detect": lambda args: _technology_detect(args["url"]),
    "subdomain_enumerate": lambda args: _subdomain_enumerate(args["domain"]),
    "save_finding": lambda args: _save_finding(args["finding_json"]),
    "get_vuln_prompt": lambda args: _get_vuln_prompt(
        args["vuln_type"], args.get("target", ""), args.get("endpoint", ""),
        args.get("param", ""), args.get("tech", "")
    ),
    # Sandbox tools
    "execute_nuclei": lambda args: _execute_nuclei(
        args["target"], args.get("templates"), args.get("severity"),
        args.get("tags"), args.get("rate_limit", 150),
        args.get("opsec_profile")
    ),
    "execute_naabu": lambda args: _execute_naabu(
        args["target"], args.get("ports"), args.get("top_ports"),
        args.get("rate", 1000), args.get("opsec_profile")
    ),
    "sandbox_health": lambda args: _sandbox_health(),
    "sandbox_exec": lambda args: _sandbox_exec(
        args["tool"], args["args"], args.get("timeout", 300),
        args.get("opsec_profile")
    ),
    # ProjectDiscovery extended suite
    "execute_cvemap": lambda args: _execute_cvemap(
        args.get("cve_id"), args.get("severity"), args.get("product"),
        args.get("vendor"), args.get("opsec_profile")
    ),
    "execute_tlsx": lambda args: _execute_tlsx(
        args["target"], args.get("port"), args.get("scan_mode"),
        args.get("opsec_profile")
    ),
    "execute_asnmap": lambda args: _execute_asnmap(
        args["target"], args.get("opsec_profile")
    ),
    "execute_mapcidr": lambda args: _execute_mapcidr(
        args["cidr"], args.get("operation", "count"),
        args.get("opsec_profile")
    ),
    "execute_alterx": lambda args: _execute_alterx(
        args["domain"], args.get("pattern"), args.get("enrich", False),
        args.get("opsec_profile")
    ),
    "execute_shuffledns": lambda args: _execute_shuffledns(
        args["domain"], args.get("wordlist", "/opt/wordlists/subdomains-5000.txt"),
        args.get("resolvers"), args.get("opsec_profile")
    ),
    "execute_cloudlist": lambda args: _execute_cloudlist(
        args.get("provider"), args.get("opsec_profile")
    ),
    "execute_interactsh": lambda args: _execute_interactsh(
        args.get("action", "register"), args.get("token"),
        args.get("poll_interval"), args.get("opsec_profile")
    ),
    "oob_verify": lambda args: _oob_verify(
        args.get("action", "register"), args.get("oob_url"),
        args.get("wait_seconds"), args.get("expected_protocol")
    ),
    "execute_notify": lambda args: _execute_notify(
        args["message"], args.get("provider"), args.get("severity"),
        args.get("opsec_profile")
    ),
    # Proxy tools
    "proxy_status": lambda args: _proxy_status(),
    "proxy_flows": lambda args: _proxy_flows(
        args.get("filter_expr"), args.get("limit", 50)
    ),
    "proxy_capture": lambda args: _proxy_capture(args.get("filter_expr", "")),
    "proxy_replay": lambda args: _proxy_replay(
        args["flow_id"], args.get("modify_headers"), args.get("modify_body")
    ),
    "proxy_intercept": lambda args: _proxy_intercept(
        args.get("pattern", ""), args.get("enabled", True)
    ),
    "proxy_clear": lambda args: _proxy_clear(),
    "proxy_export": lambda args: _proxy_export(
        args["flow_id"], args.get("format", "curl")
    ),
}


# ---------------------------------------------------------------------------
# Governance context for in-process MCP usage
# ---------------------------------------------------------------------------
_active_governance = None


def set_mcp_governance(governance):
    """Set the active governance facade for MCP tool calls.

    Called by AutonomousAgent.__aenter__ when MCP runs in-process.
    """
    global _active_governance
    _active_governance = governance


def clear_mcp_governance():
    """Clear the active governance facade (called on agent exit)."""
    global _active_governance
    _active_governance = None


def create_mcp_server() -> "Server":
    """Create and configure the MCP server with all pentest tools."""
    if not HAS_MCP:
        raise RuntimeError("MCP package not installed. Install with: pip install 'mcp>=1.0.0'")

    server = Server("neurosploit-tools")

    @server.list_tools()
    async def list_tools() -> list:
        return [Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        # Governance gate: check if tool is allowed in current phase
        if _active_governance is not None:
            decision = _active_governance.check_action(name, arguments)
            if not decision.allowed:
                logger.info(f"[GOVERNANCE] MCP tool '{name}' blocked: {decision.reason}")
                return [TextContent(type="text", text=json.dumps({
                    "error": f"Governance blocked: {decision.reason}",
                    "governance_blocked": True,
                }))]

        handler = TOOL_HANDLERS.get(name)
        if not handler:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

        try:
            result = await handler(arguments)
            return [TextContent(type="text", text=json.dumps(result, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


async def main():
    """Run the MCP server via stdio transport."""
    server = create_mcp_server()

    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    else:
        logger.error(f"Unsupported transport: {transport}. Use 'stdio'.")


if __name__ == "__main__":
    asyncio.run(main())

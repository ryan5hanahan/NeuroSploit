"""Tool definitions for the LLM-driven agent.

Each tool is defined in MCP format (name, description, inputSchema) for use
with UnifiedLLMClient.generate_with_tools(). The ToolAdapter layer handles
conversion to provider-native formats (Claude tool_use, OpenAI functions, etc.).
"""

from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Tool schema definitions (MCP format)
# ---------------------------------------------------------------------------

SHELL_EXECUTE = {
    "name": "shell_execute",
    "description": (
        "Execute a shell command inside the Docker sandbox. "
        "Pre-installed tools: nmap, curl, sqlmap, nikto, gobuster, feroxbuster, "
        "whatweb, wafw00f, dig, whois, nuclei, httpx, subfinder, naabu, katana, ffuf, python3. "
        "Use this for port scanning, web fingerprinting, directory brute-forcing, "
        "DNS enumeration, and running security tools. "
        "Output is captured and truncated to 30KB."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute (e.g., 'nmap -sV -p- target.com')",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds (default 120, max 600)",
                "default": 120,
            },
        },
        "required": ["command"],
    },
}

HTTP_REQUEST = {
    "name": "http_request",
    "description": (
        "Send an HTTP request to a URL. Supports all methods. "
        "Use this for API testing, IDOR checks, auth bypass attempts, "
        "header injection, and any direct HTTP interaction. "
        "Returns status code, headers, and response body (truncated to 30KB)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            },
            "url": {
                "type": "string",
                "description": "Full URL to request",
            },
            "headers": {
                "type": "object",
                "description": "Request headers as key-value pairs",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "string",
                "description": "Request body (for POST/PUT/PATCH)",
            },
            "follow_redirects": {
                "type": "boolean",
                "description": "Follow HTTP redirects (default true)",
                "default": True,
            },
            "credential_label": {
                "type": "string",
                "description": (
                    "Credential context to use (e.g., 'admin', 'user_a'). "
                    "Omit for default credentials."
                ),
            },
        },
        "required": ["method", "url"],
    },
}

BROWSER_NAVIGATE = {
    "name": "browser_navigate",
    "description": (
        "Navigate the headless browser to a URL. Returns page title, final URL "
        "(after redirects), and a summary of page content. Use this for pages "
        "that require JavaScript rendering, SPAs, or when you need to interact "
        "with the DOM."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "URL to navigate to",
            },
            "credential_label": {
                "type": "string",
                "description": (
                    "Credential context to use (e.g., 'admin', 'user_a'). "
                    "Omit for default credentials."
                ),
            },
        },
        "required": ["url"],
    },
}

BROWSER_EXTRACT_LINKS = {
    "name": "browser_extract_links",
    "description": (
        "Extract all links from the current browser page. Returns a list of "
        "URLs found in anchor tags, forms, and JavaScript. Useful for discovering "
        "API endpoints, admin panels, and hidden pages."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {},
    },
}

BROWSER_EXTRACT_FORMS = {
    "name": "browser_extract_forms",
    "description": (
        "Extract all forms from the current browser page. Returns form action URLs, "
        "methods, input fields (name, type, value), and hidden fields. Essential for "
        "identifying injection points, CSRF tokens, and authentication forms."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {},
    },
}

BROWSER_SUBMIT_FORM = {
    "name": "browser_submit_form",
    "description": (
        "Fill in and submit a form in the current browser page. Use this to test "
        "login forms with default/weak credentials, submit registration forms, "
        "or interact with any HTML form. Provide field names and values as key-value "
        "pairs. Hidden fields (CSRF tokens) are preserved automatically. "
        "Optionally navigate to the page first via 'url' to get fresh CSRF tokens."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "form_selector": {
                "type": "string",
                "description": (
                    "CSS selector for the form, or a numeric index "
                    "(e.g. '0' for the first form on the page)"
                ),
            },
            "field_values": {
                "type": "object",
                "description": (
                    "Mapping of form field name attributes to values "
                    "(e.g. {\"username\": \"admin\", \"password\": \"admin\"})"
                ),
                "additionalProperties": {"type": "string"},
            },
            "submit_selector": {
                "type": "string",
                "description": "Optional CSS selector for the submit button (auto-detected if omitted)",
            },
            "url": {
                "type": "string",
                "description": "Navigate to this URL first to get fresh CSRF tokens before filling the form",
            },
            "credential_label": {
                "type": "string",
                "description": "Credential context to use (e.g., 'admin', 'user_a'). Omit for default.",
            },
        },
        "required": ["form_selector", "field_values"],
    },
}

BROWSER_SCREENSHOT = {
    "name": "browser_screenshot",
    "description": (
        "Capture a full-page screenshot of the current browser state. "
        "Saves to the operation artifacts directory. Use this to document "
        "evidence of vulnerabilities, error pages, or interesting behavior."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "description": "Descriptive label for the screenshot (e.g., 'idor-user2-profile')",
            },
        },
        "required": ["label"],
    },
}

BROWSER_EXECUTE_JS = {
    "name": "browser_execute_js",
    "description": (
        "Execute JavaScript in the current browser page context. Returns the "
        "result of the expression. Use for extracting DOM data, testing XSS, "
        "reading cookies, or manipulating page state."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "script": {
                "type": "string",
                "description": "JavaScript code to execute (e.g., 'document.cookie')",
            },
        },
        "required": ["script"],
    },
}

MEMORY_STORE = {
    "name": "memory_store",
    "description": (
        "Store an observation, finding, or note in persistent memory. "
        "Use this to record important discoveries, tech stack details, "
        "credentials found, API patterns, or anything you want to remember "
        "across steps. Categories: 'recon', 'finding', 'credential', "
        "'observation', 'hypothesis', 'evidence'."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "Content to store (be specific and detailed)",
            },
            "category": {
                "type": "string",
                "description": "Category for organizing memories",
                "enum": [
                    "recon", "finding", "credential", "observation",
                    "hypothesis", "evidence",
                ],
            },
            "metadata": {
                "type": "object",
                "description": "Optional metadata (e.g., severity, endpoint, vuln_type)",
                "additionalProperties": {"type": "string"},
            },
        },
        "required": ["content", "category"],
    },
}

MEMORY_SEARCH = {
    "name": "memory_search",
    "description": (
        "Search your stored memories by keyword or semantic similarity. "
        "Use this to recall previous findings, check if you already tested "
        "something, or retrieve stored credentials and observations."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query (keywords or natural language)",
            },
            "category": {
                "type": "string",
                "description": "Optional category filter",
                "enum": [
                    "recon", "finding", "credential", "observation",
                    "hypothesis", "evidence",
                ],
            },
            "top_k": {
                "type": "integer",
                "description": "Number of results to return (default 5)",
                "default": 5,
            },
        },
        "required": ["query"],
    },
}

SAVE_ARTIFACT = {
    "name": "save_artifact",
    "description": (
        "Save evidence or data to a file in the operation artifacts directory. "
        "Use this for HTTP responses, tool outputs, exploit scripts, or any "
        "data that supports a finding. Files are preserved for the final report."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": "Filename (e.g., 'idor-response.json', 'sqli-payload.txt')",
            },
            "content": {
                "type": "string",
                "description": "File content to save",
            },
        },
        "required": ["filename", "content"],
    },
}

REPORT_FINDING = {
    "name": "report_finding",
    "description": (
        "Report a confirmed vulnerability finding. Include all evidence. "
        "This adds the finding to the operation results. Only report findings "
        "you have CONFIRMED with actual evidence — never speculate. "
        "IMPORTANT: For HIGH/CRITICAL findings, you MUST save artifact files "
        "(via save_artifact or browser_screenshot) BEFORE calling this tool, "
        "and reference the artifact paths in the evidence field."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Vulnerability title (e.g., 'BOLA on GET /api/v1/users/{id}')",
            },
            "severity": {
                "type": "string",
                "description": "Severity level",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "vuln_type": {
                "type": "string",
                "description": "Vulnerability type (e.g., 'IDOR', 'SQL Injection', 'XSS')",
            },
            "description": {
                "type": "string",
                "description": "Detailed description of the vulnerability",
            },
            "evidence": {
                "type": "string",
                "description": (
                    "Proof of exploitation: HTTP request/response, tool output, "
                    "screenshot reference, or other concrete evidence. "
                    "For HIGH/CRITICAL: include artifact file paths."
                ),
            },
            "endpoint": {
                "type": "string",
                "description": "Affected endpoint URL",
            },
            "reproduction_steps": {
                "type": "string",
                "description": "Step-by-step instructions to reproduce",
            },
            "remediation": {
                "type": "string",
                "description": "Recommended fix",
            },
            "cvss_score": {
                "type": "number",
                "description": "CVSS v3.1 base score (0.0-10.0)",
            },
            "cvss_vector": {
                "type": "string",
                "description": "CVSS v3.1 vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')",
            },
            "cwe_id": {
                "type": "string",
                "description": "CWE identifier (e.g., 'CWE-89' for SQL Injection)",
            },
            "impact": {
                "type": "string",
                "description": "Business/technical impact description",
            },
            "references": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Reference URLs (OWASP, CVE, vendor advisories)",
            },
            "poc_payload": {
                "type": "string",
                "description": "The exact payload that triggered the vulnerability",
            },
            "poc_parameter": {
                "type": "string",
                "description": "The vulnerable parameter name",
            },
            "poc_request": {
                "type": "string",
                "description": "Full HTTP request that demonstrates the vulnerability",
            },
            "poc_response": {
                "type": "string",
                "description": "HTTP response showing exploitation evidence",
            },
            "poc_code": {
                "type": "string",
                "description": "Proof-of-concept code snippet for reproducing the vulnerability",
            },
            "confidence_score": {
                "type": "number",
                "description": "Confidence in finding accuracy (0-100)",
            },
            "screenshots": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Screenshot file paths as visual evidence",
            },
            "validation_status": {
                "type": "string",
                "description": (
                    "Evidence validation status. 'verified' = artifact-backed proof exists. "
                    "'hypothesis' = needs further verification. "
                    "HIGH/CRITICAL findings MUST be 'verified' with artifacts."
                ),
                "enum": ["verified", "hypothesis"],
                "default": "verified",
            },
            "artifact_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of saved artifact/screenshot file paths supporting this finding",
            },
        },
        "required": ["title", "severity", "vuln_type", "description", "evidence", "endpoint"],
    },
}

UPDATE_PLAN = {
    "name": "update_plan",
    "description": (
        "Update your current operation plan. Use this at the start to create "
        "a plan, and at checkpoints (20%/40%/60%/80% of steps) to revise it. "
        "Include what you've done, what you learned, and what to do next."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "current_phase": {
                "type": "string",
                "description": "Current phase name (e.g., 'Discovery', 'Hypothesis', 'Validation')",
            },
            "completed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of completed objectives",
            },
            "in_progress": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of in-progress objectives",
            },
            "next_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of planned next steps",
            },
            "confidence": {
                "type": "number",
                "description": "Overall confidence in current approach (0-100)",
            },
            "key_findings_summary": {
                "type": "string",
                "description": "Brief summary of key findings so far",
            },
        },
        "required": ["current_phase", "next_steps", "confidence"],
    },
}

GET_PAYLOADS = {
    "name": "get_payloads",
    "description": (
        "Retrieve curated payloads for a specific vulnerability type from the "
        "built-in payload database (100+ vuln types, 526+ payloads including "
        "PayloadsAllTheThings/PATT). Use this to get targeted, context-aware "
        "payloads instead of crafting them from scratch. Supports WAF bypass "
        "variants, XSS context-specific payloads, and DB-specific SQL injection."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "vuln_type": {
                "type": "string",
                "description": (
                    "Vulnerability type key (e.g., 'sqli_error', 'xss_reflected', "
                    "'command_injection', 'ssti', 'ssrf', 'lfi', 'xxe', 'nosql_injection', "
                    "'jwt_manipulation', 'idor', 'cors_misconfig', etc.). "
                    "Use get_vuln_info with list_types=true to see all available types."
                ),
            },
            "context": {
                "type": "object",
                "description": "Optional context for payload selection",
                "properties": {
                    "detected_technology": {
                        "type": "string",
                        "description": "Detected backend technology (e.g., 'mysql', 'postgresql', 'nodejs', 'php')",
                    },
                    "waf_detected": {
                        "type": "boolean",
                        "description": "Whether a WAF was detected (adds encoding bypass variants)",
                    },
                    "depth": {
                        "type": "string",
                        "description": "Payload depth: 'quick' (3), 'standard' (10), 'thorough' (20), 'exhaustive' (all)",
                        "enum": ["quick", "standard", "thorough", "exhaustive"],
                    },
                },
            },
            "xss_context": {
                "type": "string",
                "description": (
                    "XSS injection context for context-specific payloads "
                    "(e.g., 'html_body', 'attribute', 'js_string', 'url', 'css')"
                ),
            },
            "filter_bypass": {
                "type": "object",
                "description": "WAF/filter bypass context for targeted bypass payloads",
                "properties": {
                    "blocked_chars": {
                        "type": "string",
                        "description": "Characters that are blocked (e.g., '<>\"')",
                    },
                    "blocked_tags": {
                        "type": "string",
                        "description": "HTML tags that are blocked (e.g., 'script,img')",
                    },
                    "blocked_events": {
                        "type": "string",
                        "description": "Event handlers that are blocked (e.g., 'onerror,onload')",
                    },
                },
            },
            "include_polyglot": {
                "type": "boolean",
                "description": (
                    "Include multi-context polyglot payloads that trigger across "
                    "multiple vulnerability types simultaneously (SQLi+XSS, SSTI+XSS, "
                    "CMDi+SQLi, etc.). Useful for initial probing. Default: false."
                ),
            },
        },
        "required": ["vuln_type"],
    },
}

GET_VULN_INFO = {
    "name": "get_vuln_info",
    "description": (
        "Get vulnerability metadata from the built-in knowledge base. Returns CWE IDs, "
        "severity ratings, descriptions, impact statements, remediation guidance, and "
        "false positive markers for 100+ vulnerability types. Use list_types=true to "
        "see all available vulnerability type keys."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "vuln_type": {
                "type": "string",
                "description": (
                    "Vulnerability type key (e.g., 'sqli_error', 'xss_reflected'). "
                    "Ignored if list_types is true."
                ),
            },
            "list_types": {
                "type": "boolean",
                "description": "If true, return all available vulnerability type keys instead of info for a specific type",
                "default": False,
            },
        },
        "required": ["vuln_type"],
    },
}

SPAWN_SUBAGENT = {
    "name": "spawn_subagent",
    "description": (
        "Spawn a lightweight sub-agent to perform a focused recon task in parallel. "
        "The sub-agent runs on the FAST tier with a limited tool set "
        "(shell_execute, http_request, browser_navigate, memory_store, save_artifact). "
        "Results are stored in shared memory and returned as text. "
        "Use this to parallelize independent discovery tasks like port scanning "
        "different targets, checking multiple endpoints, or running multiple tools. "
        "Max 3 concurrent sub-agents. Each step deducts from your budget."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "objective": {
                "type": "string",
                "description": (
                    "Clear, specific objective for the sub-agent "
                    "(e.g., 'Enumerate subdomains of target.com using subfinder')"
                ),
            },
            "max_steps": {
                "type": "integer",
                "description": "Max steps for the sub-agent (default 15, max 15)",
                "default": 15,
            },
        },
        "required": ["objective"],
    },
}

CREATE_TOOL = {
    "name": "create_tool",
    "description": (
        "Create a custom tool at runtime by providing Python code. "
        "The code must define `async def handler(args: dict, context) -> str`. "
        "Only safe imports are allowed (json, re, base64, urllib, hashlib, html, "
        "math, collections, itertools, string, binascii, hmac). "
        "System imports (os, subprocess, sys, etc.) and dangerous builtins "
        "(eval, exec, open, __import__) are blocked. "
        "Use this when you need a specialized helper that isn't covered by "
        "existing tools — e.g., a custom decoder, protocol parser, or data transformer."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "tool_name": {
                "type": "string",
                "description": "Name for the new tool (must be a valid Python identifier, not a reserved name)",
            },
            "description": {
                "type": "string",
                "description": "Description of what the tool does",
            },
            "code": {
                "type": "string",
                "description": (
                    "Python source code defining `async def handler(args: dict, context) -> str`. "
                    "Must return a string result."
                ),
            },
            "parameters": {
                "type": "object",
                "description": "JSON Schema properties for the tool's input parameters",
                "additionalProperties": True,
            },
        },
        "required": ["tool_name", "description", "code"],
    },
}

STOP = {
    "name": "stop",
    "description": (
        "Terminate the current operation. Use this when: "
        "(1) You have thoroughly tested the target and have no more productive avenues, "
        "(2) You have hit a hard blocker you cannot work around, "
        "(3) The objective has been fully achieved. "
        "Provide a clear reason for stopping."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "reason": {
                "type": "string",
                "description": "Why you are stopping the operation",
            },
            "summary": {
                "type": "string",
                "description": "Brief summary of what was accomplished",
            },
        },
        "required": ["reason", "summary"],
    },
}


def get_agent_tools() -> List[Dict[str, Any]]:
    """Return all tool definitions for the LLM-driven agent (18 tools)."""
    return [
        SHELL_EXECUTE,
        HTTP_REQUEST,
        BROWSER_NAVIGATE,
        BROWSER_EXTRACT_LINKS,
        BROWSER_EXTRACT_FORMS,
        BROWSER_SUBMIT_FORM,
        BROWSER_SCREENSHOT,
        BROWSER_EXECUTE_JS,
        MEMORY_STORE,
        MEMORY_SEARCH,
        SAVE_ARTIFACT,
        REPORT_FINDING,
        UPDATE_PLAN,
        GET_PAYLOADS,
        GET_VULN_INFO,
        SPAWN_SUBAGENT,
        CREATE_TOOL,
        STOP,
    ]

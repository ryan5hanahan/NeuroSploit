"""Meta-tool schemas for structured LLM decision-making.

These are "meta-tools" — they don't execute external actions but provide
structured schemas for the LLM to return well-typed decisions via native
tool calling (Claude tool_use / OpenAI function_calling).

Used by generate_with_tools() when the agent needs structured output
that goes beyond simple JSON extraction.
"""

from typing import Any, Dict, List


# ── Test Strategy Planning ─────────────────────────────────────────────────

TOOL_GENERATE_TEST_STRATEGY = {
    "name": "generate_test_strategy",
    "description": (
        "Generate a structured test strategy for a vulnerability type. "
        "Include specific test cases with payloads, URLs, and success indicators."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "vulnerability_type": {
                "type": "string",
                "description": "Name of the vulnerability being tested",
            },
            "cwe_id": {
                "type": "string",
                "description": "CWE identifier if applicable (e.g., CWE-89)",
            },
            "owasp_category": {
                "type": "string",
                "description": "OWASP Top 10 category if applicable",
            },
            "description": {
                "type": "string",
                "description": "Brief description of what this vulnerability is",
            },
            "severity_if_found": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "description": "Expected severity if vulnerability is confirmed",
            },
            "cvss_estimate": {
                "type": "number",
                "description": "Estimated CVSS 3.1 score (0.0-10.0)",
            },
            "test_cases": {
                "type": "array",
                "description": "List of specific test cases to execute",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "technique": {"type": "string"},
                        "url": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                        "headers": {"type": "object"},
                        "body": {"type": "string"},
                        "content_type": {"type": "string"},
                        "success_indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "failure_indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["name", "technique", "url", "method"],
                },
            },
            "payloads": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific payloads to use in testing",
            },
            "analysis_tips": {
                "type": "string",
                "description": "What patterns or behaviors indicate this vulnerability",
            },
        },
        "required": ["vulnerability_type", "test_cases", "payloads"],
    },
}


# ── Recon Tool Selection ───────────────────────────────────────────────────

TOOL_SELECT_RECON_TOOLS = {
    "name": "select_recon_tools",
    "description": (
        "Select 1-3 tools for additional reconnaissance. Return the tool name, "
        "arguments, and reason for selection."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "selections": {
                "type": "array",
                "description": "Tools selected for additional recon",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "Tool name from available list",
                        },
                        "args": {
                            "type": "string",
                            "description": "CLI arguments or JSON dict for MCP tools",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Brief reason for selecting this tool",
                        },
                    },
                    "required": ["tool", "args", "reason"],
                },
                "maxItems": 5,
            },
        },
        "required": ["selections"],
    },
}


# ── Attack Surface Analysis ────────────────────────────────────────────────

TOOL_ANALYZE_ATTACK_SURFACE = {
    "name": "analyze_attack_surface",
    "description": (
        "Analyze the target's attack surface and produce a prioritized attack plan. "
        "Use exact vulnerability type names from the available types list."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "priority_vulns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Ordered list of vulnerability types to test, highest priority first",
            },
            "high_risk_endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Endpoints that are most likely to be vulnerable",
            },
            "focus_parameters": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Parameter names to focus testing on",
            },
            "attack_vectors": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attack vectors to try",
            },
            "technology_specific_tests": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tests specific to detected technologies",
            },
        },
        "required": ["priority_vulns", "high_risk_endpoints"],
    },
}


# ── Execution Plan ─────────────────────────────────────────────────────────

TOOL_CREATE_EXECUTION_PLAN = {
    "name": "create_execution_plan",
    "description": (
        "Create a step-by-step execution plan for a penetration test. "
        "Steps should start with 'recon' and end with 'report'."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Ordered list of testing steps/actions",
            },
        },
        "required": ["steps"],
    },
}


# ── Finding Enhancement ────────────────────────────────────────────────────

TOOL_ENHANCE_FINDING = {
    "name": "enhance_finding",
    "description": (
        "Enhance a vulnerability finding with CVSS scoring, PoC code, "
        "remediation steps, and references."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "cvss_score": {
                "type": "number",
                "description": "CVSS 3.1 base score (0.0-10.0)",
            },
            "cvss_vector": {
                "type": "string",
                "description": "CVSS 3.1 vector string",
            },
            "cwe_id": {
                "type": "string",
                "description": "CWE identifier (e.g., CWE-89)",
            },
            "description": {
                "type": "string",
                "description": "Detailed vulnerability description",
            },
            "impact": {
                "type": "string",
                "description": "Real-world impact assessment",
            },
            "poc_code": {
                "type": "string",
                "description": "Python proof-of-concept script using requests library",
            },
            "remediation": {
                "type": "string",
                "description": "Specific remediation steps with code examples",
            },
            "references": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Reference URLs (OWASP, CWE, vendor docs)",
            },
        },
        "required": ["cvss_score", "cvss_vector", "description", "impact", "remediation"],
    },
}


# ── All Meta-Tools ─────────────────────────────────────────────────────────

META_TOOLS: Dict[str, Dict[str, Any]] = {
    "generate_test_strategy": TOOL_GENERATE_TEST_STRATEGY,
    "select_recon_tools": TOOL_SELECT_RECON_TOOLS,
    "analyze_attack_surface": TOOL_ANALYZE_ATTACK_SURFACE,
    "create_execution_plan": TOOL_CREATE_EXECUTION_PLAN,
    "enhance_finding": TOOL_ENHANCE_FINDING,
}


def get_meta_tools(names: List[str]) -> List[Dict[str, Any]]:
    """Get a list of meta-tool schemas by name."""
    return [META_TOOLS[n] for n in names if n in META_TOOLS]


def get_all_meta_tools() -> List[Dict[str, Any]]:
    """Get all meta-tool schemas."""
    return list(META_TOOLS.values())

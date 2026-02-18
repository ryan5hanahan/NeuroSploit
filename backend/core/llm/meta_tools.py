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


# ── Response Diff (Blind Injection Detection) ─────────────────────────────

TOOL_RESPONSE_DIFF = {
    "name": "response_diff",
    "description": (
        "Structured before/after comparison for blind injection detection. "
        "Compare a baseline response against a test (payload-injected) response "
        "to identify subtle behavioral differences that indicate blind vulnerabilities."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "baseline": {
                "type": "object",
                "description": "Baseline (clean) response measurements",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "body_length": {"type": "integer", "description": "Response body length in bytes"},
                    "body_hash": {"type": "string", "description": "SHA-256 hash of response body"},
                    "timing_ms": {"type": "number", "description": "Response time in milliseconds"},
                    "content_snippet": {"type": "string", "description": "First 500 chars of body"},
                },
                "required": ["status", "body_length", "timing_ms"],
            },
            "test": {
                "type": "object",
                "description": "Test (payload-injected) response measurements",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "body_length": {"type": "integer", "description": "Response body length in bytes"},
                    "body_hash": {"type": "string", "description": "SHA-256 hash of response body"},
                    "timing_ms": {"type": "number", "description": "Response time in milliseconds"},
                    "content_snippet": {"type": "string", "description": "First 500 chars of body"},
                },
                "required": ["status", "body_length", "timing_ms"],
            },
            "delta": {
                "type": "object",
                "description": "Computed differences between baseline and test",
                "properties": {
                    "status_changed": {"type": "boolean", "description": "Whether HTTP status changed"},
                    "length_delta": {"type": "integer", "description": "Absolute body length difference"},
                    "length_delta_pct": {"type": "number", "description": "Body length change as percentage"},
                    "timing_delta_ms": {"type": "number", "description": "Timing difference in ms"},
                    "timing_ratio": {"type": "number", "description": "test_timing / baseline_timing ratio"},
                    "content_similarity_pct": {"type": "number", "description": "Content similarity 0-100%"},
                    "new_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Patterns appearing in test but not baseline (e.g. error messages, SQL fragments)",
                    },
                    "disappeared_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Patterns present in baseline but absent from test",
                    },
                },
                "required": ["status_changed", "length_delta", "timing_delta_ms"],
            },
            "verdict": {
                "type": "string",
                "enum": [
                    "blind_confirmed",
                    "likely_blind",
                    "behavioral_diff",
                    "timing_anomaly",
                    "no_diff",
                    "inconclusive",
                ],
                "description": "Overall assessment of whether a blind vulnerability is indicated",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence in verdict (0.0-1.0)",
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of why this verdict was reached",
            },
        },
        "required": ["baseline", "test", "delta", "verdict", "confidence", "reasoning"],
    },
}


# ── Auth Context Switch (Access Control Testing) ─────────────────────────

TOOL_AUTH_CONTEXT_SWITCH = {
    "name": "auth_context_switch",
    "description": (
        "Multi-identity access control testing. Compare how an endpoint responds "
        "to requests from different user roles/identities to detect access control "
        "bypasses, privilege escalation, and IDOR vulnerabilities."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "The endpoint being tested",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "description": "HTTP method used for the test",
            },
            "identities": {
                "type": "array",
                "description": "Identities (roles) used in the comparison",
                "items": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "description": "Role label (e.g. admin, user, anonymous)"},
                        "auth_type": {
                            "type": "string",
                            "enum": ["bearer", "cookie", "basic", "api_key", "none"],
                            "description": "Authentication mechanism",
                        },
                        "credentials": {"type": "string", "description": "Credential value (token, cookie, etc.)"},
                        "description": {"type": "string", "description": "Human-readable identity description"},
                    },
                    "required": ["role", "auth_type"],
                },
                "minItems": 2,
            },
            "comparison_fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Response fields to compare (e.g. status, body_length, json_keys, records_count)",
            },
            "expected_behavior": {
                "type": "string",
                "enum": ["deny_lower_role", "different_data", "same_public_data", "role_scoped"],
                "description": "What proper access control should look like",
            },
            "verdict": {
                "type": "string",
                "enum": [
                    "access_control_bypass",
                    "proper_enforcement",
                    "partial_enforcement",
                    "inconclusive",
                ],
                "description": "Overall access control assessment",
            },
            "details": {
                "type": "array",
                "description": "Pairwise comparison results between identities",
                "items": {
                    "type": "object",
                    "properties": {
                        "identity_a": {"type": "string", "description": "First role in comparison"},
                        "identity_b": {"type": "string", "description": "Second role in comparison"},
                        "status_a": {"type": "integer"},
                        "status_b": {"type": "integer"},
                        "body_length_a": {"type": "integer"},
                        "body_length_b": {"type": "integer"},
                        "similarity_pct": {"type": "number", "description": "Response similarity 0-100%"},
                        "significant": {"type": "boolean", "description": "Whether this comparison reveals an issue"},
                        "notes": {"type": "string"},
                    },
                    "required": ["identity_a", "identity_b", "significant"],
                },
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "Severity if access control issue is found",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence in verdict (0.0-1.0)",
            },
        },
        "required": ["endpoint", "method", "identities", "verdict", "confidence"],
    },
}


# ── All Meta-Tools ─────────────────────────────────────────────────────────

META_TOOLS: Dict[str, Dict[str, Any]] = {
    "generate_test_strategy": TOOL_GENERATE_TEST_STRATEGY,
    "select_recon_tools": TOOL_SELECT_RECON_TOOLS,
    "analyze_attack_surface": TOOL_ANALYZE_ATTACK_SURFACE,
    "create_execution_plan": TOOL_CREATE_EXECUTION_PLAN,
    "enhance_finding": TOOL_ENHANCE_FINDING,
    "response_diff": TOOL_RESPONSE_DIFF,
    "auth_context_switch": TOOL_AUTH_CONTEXT_SWITCH,
}


def get_meta_tools(names: List[str]) -> List[Dict[str, Any]]:
    """Get a list of meta-tool schemas by name."""
    return [META_TOOLS[n] for n in names if n in META_TOOLS]


def get_all_meta_tools() -> List[Dict[str, Any]]:
    """Get all meta-tool schemas."""
    return list(META_TOOLS.values())

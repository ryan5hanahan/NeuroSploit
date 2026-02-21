"""Prompt composer for the LLM-driven agent.

Assembles system prompts by reading markdown templates and injecting
runtime context (target, objective, plan state, memory overview).
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


_PROMPT_DIR = Path(__file__).parent


def _read_template(name: str) -> str:
    """Read a markdown prompt template from the prompts directory."""
    path = _PROMPT_DIR / name
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def compose_agent_system_prompt(
    target: str,
    objective: str,
    operation_id: str,
    current_step: int,
    max_steps: int,
    memory_overview: str = "",
    plan_snapshot: str = "",
    auth_context: str = "",
    additional_targets: Optional[List[str]] = None,
    subdomain_discovery: bool = False,
    bugbounty_instructions: str = "",
    governance_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Compose the full system prompt for the LLM-driven agent.

    Reads the markdown templates and injects runtime variables.

    Args:
        target: Target URL or host.
        objective: Assessment objective description.
        operation_id: Unique operation identifier.
        current_step: Current step number.
        max_steps: Maximum steps allowed.
        memory_overview: Summary of stored memories (optional).
        plan_snapshot: Current plan state (optional).
        auth_context: Authentication context description (optional).
        additional_targets: Extra target URLs (optional).
        subdomain_discovery: Whether subdomain enumeration is enabled.
        governance_context: Scope/phase governance info (optional).

    Returns:
        Assembled system prompt string.
    """
    system_template = _read_template("agent_system_prompt.md")

    # Select execution prompt based on scope profile
    execution_template = _select_execution_template(governance_context)

    # Format memory overview section
    if memory_overview:
        memory_section = f"### Stored Memories\n{memory_overview}"
    else:
        memory_section = "### Stored Memories\nNo memories stored yet. Use `memory_store` to save observations."

    # Format plan section
    if plan_snapshot:
        plan_section = f"### Current Plan\n{plan_snapshot}"
    else:
        plan_section = (
            "### Current Plan\n"
            "No plan created yet. Use `update_plan` at the start to create your assessment plan."
        )

    # Budget warning
    budget_pct = (current_step / max_steps * 100) if max_steps > 0 else 0
    if budget_pct >= 80:
        budget_warning = (
            "\n\n⚠️ **BUDGET WARNING**: You have used 80%+ of your steps. "
            "Focus on documenting findings and wrapping up. "
            "Call `stop` when done."
        )
    elif budget_pct >= 60:
        budget_warning = (
            "\n\n**Budget Note**: Past 60% of steps. "
            "Focus on highest-value tests and confirming existing findings."
        )
    else:
        budget_warning = ""

    # Build multi-target display for the {target} template variable
    if additional_targets:
        target_display = target + "\n**Additional targets:**\n" + "\n".join(f"  - {t}" for t in additional_targets)
    else:
        target_display = target

    # Inject variables into system template (static mission header only)
    system_prompt = system_template.format(
        target=target_display,
        objective=objective,
        operation_id=operation_id,
        current_step=current_step,
        max_steps=max_steps,
    )

    # Build static portion: system prompt + execution guidance
    # These don't change between steps and benefit from Anthropic's prefix caching
    static_portion = f"{system_prompt}\n\n---\n\n{execution_template}"

    # --- Dynamic sections below (appended AFTER static content for cache coherence) ---

    dynamic_sections = []

    # Governance scope restrictions (HIGHEST PRIORITY — placed first)
    if governance_context:
        gov_section = _build_governance_section(governance_context)
        if gov_section:
            dynamic_sections.append(gov_section)

    # Auth context
    if auth_context:
        dynamic_sections.append(f"### Authentication\n{auth_context}")

    # Subdomain discovery
    if subdomain_discovery:
        dynamic_sections.append(
            "### Subdomain Discovery (ENABLED)\n"
            "Run `subfinder -d <domain> -silent` via shell_execute during Discovery phase. "
            "Add discovered subdomains to your target list."
        )

    # Bug bounty program rules
    if bugbounty_instructions:
        dynamic_sections.append(
            "### Bug Bounty Program Rules\n"
            "**MANDATORY**: You are testing under a bug bounty program. "
            "Follow these rules strictly — violations may result in account ban.\n\n"
            f"{bugbounty_instructions}"
        )

    # Plan snapshot (changes every step)
    dynamic_sections.append(plan_section)

    # Memory overview (changes every step)
    dynamic_sections.append(memory_section)

    # Budget warning (changes at thresholds)
    if budget_warning:
        dynamic_sections.append(budget_warning.strip())

    full_prompt = static_portion + "\n\n---\n\n" + "\n\n".join(dynamic_sections)

    return full_prompt


def compose_reflection_prompt(
    current_step: int,
    max_steps: int,
    findings_count: int,
    tools_used: Dict[str, int],
    memory_summary: str,
    plan_snapshot: str,
) -> str:
    """Compose a reflection prompt for checkpoint reviews.

    Called at 20/40/60/80% budget marks to trigger strategic reassessment.
    """
    budget_pct = (current_step / max_steps * 100) if max_steps > 0 else 0

    tool_usage = "\n".join(
        f"  - {name}: {count} calls"
        for name, count in sorted(tools_used.items(), key=lambda x: -x[1])
    )

    return (
        f"## Checkpoint Reflection ({budget_pct:.0f}% budget used)\n\n"
        f"**Steps used**: {current_step}/{max_steps}\n"
        f"**Findings reported**: {findings_count}\n\n"
        f"### Tool Usage\n{tool_usage}\n\n"
        f"### Memory Summary\n{memory_summary}\n\n"
        f"### Current Plan\n{plan_snapshot}\n\n"
        "Based on the above, update your plan using `update_plan`. Consider:\n"
        "1. Are you spending steps efficiently?\n"
        "2. Should you pivot to a different attack class?\n"
        "3. Are there untested high-value targets?\n"
        "4. Is there enough evidence for current findings?\n"
    )


# ---------------------------------------------------------------------------
# Profile → execution template mapping
# ---------------------------------------------------------------------------

_PROFILE_TEMPLATE: Dict[str, str] = {
    "bug_bounty": "execution_prompt_bug_bounty.md",
    "ctf": "execution_prompt_ctf.md",
    "pentest": "execution_prompt_pentest.md",
    "auto_pwn": "execution_prompt_auto_pwn.md",
    # Backward-compat aliases
    "full_auto": "execution_prompt_pentest.md",
    "recon_only": "execution_prompt_recon.md",
    "vuln_lab": "execution_prompt_general.md",
    "custom": "execution_prompt_general.md",
}


def _select_execution_template(governance_context: Optional[Dict[str, Any]]) -> str:
    """Select the correct execution template based on scope profile."""
    if not governance_context:
        return _read_template("execution_prompt_general.md")

    profile = governance_context.get("scope_profile", "pentest")
    template_name = _PROFILE_TEMPLATE.get(profile, "execution_prompt_general.md")
    template = _read_template(template_name)

    # Fall back to general template if profile-specific one doesn't exist
    if not template:
        template = _read_template("execution_prompt_general.md")

    return template


def _build_governance_section(governance_context: Dict[str, Any]) -> str:
    """Build the governance scope restriction section for the system prompt."""
    scope_profile = governance_context.get("scope_profile", "pentest")
    governance_mode = governance_context.get("governance_mode", "warn")
    allowed_phases = governance_context.get("allowed_phases", [])

    lines = [
        "## Scope Restrictions",
        "",
        f"**Governance Mode**: {governance_mode}",
        f"**Scope Profile**: {scope_profile}",
    ]

    if allowed_phases:
        lines.append(f"**Allowed Phases**: {', '.join(sorted(allowed_phases))}")

    # Per-profile governance guidance
    _PROFILE_GOVERNANCE_BUILDERS = {
        "bug_bounty": _bug_bounty_governance_section,
        "ctf": _ctf_governance_section,
        "pentest": _pentest_governance_section,
        "auto_pwn": _auto_pwn_governance_section,
        "recon_only": _recon_only_governance_section,
    }

    builder = _PROFILE_GOVERNANCE_BUILDERS.get(scope_profile)
    if builder:
        lines.extend(builder())

    return "\n".join(lines)


def _bug_bounty_governance_section() -> List[str]:
    """Governance section for bug bounty profile."""
    return [
        "",
        "### BUG BOUNTY — STRICT GOVERNANCE",
        "",
        "You are testing under an **authorized bug bounty program** with strict governance.",
        "",
        "**Requirements**:",
        "- Follow program scope rules exactly — out-of-scope assets are BLOCKED",
        "- Report quality matters: clear PoC, reproduction steps, impact assessment",
        "- De-duplicate findings: same root cause = one report",
        "- Respect per-asset severity caps",
        "- No denial-of-service, no accessing real user data",
        "- No post-exploitation (credential harvesting, lateral movement)",
        "",
        "All actions are monitored. Governance violations will be flagged.",
    ]


def _ctf_governance_section() -> List[str]:
    """Governance section for CTF profile."""
    return [
        "",
        "### CTF MODE — GOVERNANCE OFF",
        "",
        "You are solving a **CTF challenge**. Governance enforcement is disabled.",
        "Be creative and aggressive — your only goal is to capture the flag.",
        "Post-exploitation is enabled: credential harvesting, pivoting, and",
        "lateral movement are all permitted.",
    ]


def _pentest_governance_section() -> List[str]:
    """Governance section for pentest profile."""
    return [
        "",
        "### PENTEST — WARN MODE",
        "",
        "Professional penetration test with **warn** governance.",
        "Follow PTES/OWASP methodology. Actions that exceed the current phase",
        "will generate warnings but are not blocked. Document everything with",
        "evidence for the report.",
    ]


def _auto_pwn_governance_section() -> List[str]:
    """Governance section for auto_pwn profile."""
    return [
        "",
        "### AUTO PWN — GOVERNANCE OFF",
        "",
        "Maximum exploitation depth. Governance enforcement is disabled.",
        "Chain vulnerabilities, harvest credentials, pivot laterally,",
        "and achieve maximum impact. Post-exploitation is enabled.",
        "No checkpoints — execute autonomously.",
    ]


def _recon_only_governance_section() -> List[str]:
    """Governance section for recon_only (legacy) profile."""
    return [
        "",
        "### RECON ONLY — STRICT ENFORCEMENT",
        "",
        "You are authorized for **reconnaissance and OSINT ONLY**.",
        "",
        "**Your mission**: Gather intelligence about the target:",
        "- DNS records, zone information, MX/NS/TXT records",
        "- IP addresses, CIDR ranges, hosting provider",
        "- Geographic location and infrastructure details",
        "- Technologies, frameworks, and versions in use",
        "- Subdomains and related domains",
        "- Endpoints, API paths, and site structure",
        "- Authentication mechanisms (identify, do NOT test)",
        "- Forms and input points (map, do NOT submit)",
        "",
        "**STRICTLY FORBIDDEN** (will be BLOCKED by governance):",
        "- Login attempts or credential testing of ANY kind",
        "- Password guessing, brute force, or default credential testing",
        "- Form submission (browser_submit_form is blocked)",
        "- SQL injection, XSS, or any payload testing",
        "- Vulnerability scanners (nuclei, nikto, dalfox)",
        "- Exploitation tools (sqlmap, hydra, commix)",
        "- Any active exploitation or attack attempts",
        "- POST requests with credential data to login endpoints",
        "",
        "Any exploitation attempt **WILL BE BLOCKED** by the governance layer. "
        "Do not waste steps attempting actions that will be rejected.",
    ]

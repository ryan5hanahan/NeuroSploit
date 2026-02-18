"""Prompt composer for the LLM-driven agent.

Assembles system prompts by reading markdown templates and injecting
runtime context (target, objective, plan state, memory overview).
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional


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

    Returns:
        Assembled system prompt string.
    """
    system_template = _read_template("agent_system_prompt.md")
    execution_template = _read_template("execution_prompt_general.md")

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

    # Inject variables into system template
    system_prompt = system_template.format(
        target=target,
        objective=objective,
        operation_id=operation_id,
        current_step=current_step,
        max_steps=max_steps,
        memory_overview=memory_section,
        plan_snapshot=plan_section,
    )

    # Append execution guidance and budget warning
    full_prompt = f"{system_prompt}\n\n---\n\n{execution_template}{budget_warning}"

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

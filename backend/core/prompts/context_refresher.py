"""Dynamic context refresher for the LLM-driven agent.

Injects updated findings summary, active hypotheses, and governance
warnings into the system prompt at regular intervals.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class ContextRefresher:
    """Refreshes agent context by injecting updated state into prompts."""

    REFRESH_INTERVAL = 15  # Refresh every N steps

    def __init__(self, refresh_interval: int = 15):
        self.refresh_interval = refresh_interval
        self._last_refresh_step = 0

    def should_refresh(self, current_step: int) -> bool:
        """Check if context should be refreshed at this step."""
        if current_step == 0:
            return False
        if current_step - self._last_refresh_step >= self.refresh_interval:
            return True
        return False

    def generate_context_update(
        self,
        current_step: int,
        max_steps: int,
        findings: List[Dict[str, Any]],
        plan_snapshot: str = "",
        memory_overview: str = "",
        governance_warnings: Optional[List[str]] = None,
    ) -> str:
        """Generate a context update message to inject into conversation."""
        self._last_refresh_step = current_step

        sections = []
        sections.append(f"## Context Refresh (Step {current_step}/{max_steps})")

        # Findings summary
        if findings:
            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            findings_line = ", ".join(f"{sev}: {cnt}" for sev, cnt in sorted(severity_counts.items()))
            sections.append(f"\n### Findings So Far ({len(findings)} total)\n{findings_line}")

            # Latest 3 findings
            sections.append("\n**Recent findings:**")
            for f in findings[-3:]:
                title = f.get("title", f.get("vulnerability_type", "Unknown"))
                sections.append(f"- {title} ({f.get('severity', 'unknown')})")
        else:
            sections.append("\n### Findings So Far\nNo findings yet.")

        # Active hypotheses from plan
        if plan_snapshot:
            sections.append(f"\n### Current Plan State\n{plan_snapshot}")

        # Governance warnings
        if governance_warnings:
            sections.append("\n### Governance Warnings")
            for w in governance_warnings:
                sections.append(f"- {w}")

        # Budget status
        budget_pct = (current_step / max_steps * 100) if max_steps > 0 else 0
        budget_line = f"\n### Budget: {budget_pct:.0f}% used ({current_step}/{max_steps} steps)"
        if budget_pct >= 80:
            budget_line += "\n**WARNING: Budget is running low! Prioritize high-impact findings and wrap up.**"
        sections.append(budget_line)

        return "\n".join(sections)

    def reset(self):
        """Reset the refresher state."""
        self._last_refresh_step = 0

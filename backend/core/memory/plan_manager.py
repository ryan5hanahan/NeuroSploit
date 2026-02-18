"""Plan lifecycle management for the LLM-driven agent.

Manages structured operation plans with phases, checkpoints,
and progress tracking.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PlanPhase:
    """A single phase in an operation plan."""
    name: str
    status: str = "pending"  # pending, active, completed, skipped
    objectives: List[str] = field(default_factory=list)
    completed_objectives: List[str] = field(default_factory=list)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None


@dataclass
class OperationPlan:
    """Structured operation plan with phases and checkpoints."""
    objective: str
    phases: List[PlanPhase] = field(default_factory=list)
    current_phase_index: int = 0
    confidence: float = 50.0
    key_findings: List[str] = field(default_factory=list)
    checkpoints: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def current_phase(self) -> Optional[PlanPhase]:
        if 0 <= self.current_phase_index < len(self.phases):
            return self.phases[self.current_phase_index]
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "objective": self.objective,
            "phases": [
                {
                    "name": p.name,
                    "status": p.status,
                    "objectives": p.objectives,
                    "completed_objectives": p.completed_objectives,
                }
                for p in self.phases
            ],
            "current_phase": self.phases[self.current_phase_index].name
            if self.current_phase_index < len(self.phases)
            else "complete",
            "confidence": self.confidence,
            "key_findings": self.key_findings,
            "checkpoints_count": len(self.checkpoints),
        }

    def to_snapshot(self) -> str:
        """Generate a text snapshot for prompt injection."""
        lines = [f"**Objective**: {self.objective}"]
        lines.append(f"**Confidence**: {self.confidence:.0f}%")

        for i, phase in enumerate(self.phases):
            marker = "→" if i == self.current_phase_index else " "
            status_icon = {
                "pending": "○",
                "active": "●",
                "completed": "✓",
                "skipped": "⊘",
            }.get(phase.status, "?")
            lines.append(f"{marker} {status_icon} {phase.name}")
            for obj in phase.completed_objectives:
                lines.append(f"    ✓ {obj}")
            for obj in phase.objectives:
                if obj not in phase.completed_objectives:
                    lines.append(f"    ○ {obj}")

        if self.key_findings:
            lines.append("\n**Key Findings**:")
            for finding in self.key_findings[-5:]:
                lines.append(f"  - {finding}")

        return "\n".join(lines)


class PlanManager:
    """Manages the operation plan lifecycle.

    Creates plans, tracks phase transitions, and handles checkpoints
    at budget thresholds.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = persist_dir
        self._plan: Optional[OperationPlan] = None

        if persist_dir:
            self._load()

    @property
    def plan(self) -> Optional[OperationPlan]:
        return self._plan

    def create_plan(
        self,
        objective: str,
        phases: Optional[List[Dict[str, Any]]] = None,
    ) -> OperationPlan:
        """Create a new operation plan.

        Args:
            objective: Assessment objective.
            phases: Optional list of phase definitions.
                    Each: {"name": str, "objectives": List[str]}

        Returns:
            The created OperationPlan.
        """
        if phases:
            plan_phases = [
                PlanPhase(name=p["name"], objectives=p.get("objectives", []))
                for p in phases
            ]
        else:
            # Default 4-phase structure
            plan_phases = [
                PlanPhase(name="Discovery", objectives=[
                    "Port scan and service detection",
                    "Technology fingerprinting",
                    "Endpoint enumeration",
                    "Authentication mapping",
                ]),
                PlanPhase(name="Hypothesis", objectives=[
                    "Identify high-value attack targets",
                    "Form vulnerability hypotheses",
                    "Prioritize by likelihood and impact",
                ]),
                PlanPhase(name="Validation", objectives=[
                    "Test hypotheses with crafted requests",
                    "Collect exploitation evidence",
                    "Verify findings with negative controls",
                ]),
                PlanPhase(name="Reporting", objectives=[
                    "Document all confirmed findings",
                    "Save evidence artifacts",
                    "Generate final summary",
                ]),
            ]

        plan_phases[0].status = "active"
        plan_phases[0].started_at = time.time()

        self._plan = OperationPlan(
            objective=objective,
            phases=plan_phases,
        )

        self._save()
        return self._plan

    def update_from_agent(
        self,
        current_phase: str,
        completed: List[str],
        in_progress: List[str],
        next_steps: List[str],
        confidence: float,
        key_findings_summary: str = "",
        current_step: int = 0,
        max_steps: int = 100,
    ) -> Optional[OperationPlan]:
        """Update plan from agent's update_plan tool call."""
        if not self._plan:
            # Create plan from first update
            self._plan = OperationPlan(
                objective=key_findings_summary or "Security assessment",
                phases=[
                    PlanPhase(name="Discovery"),
                    PlanPhase(name="Hypothesis"),
                    PlanPhase(name="Validation"),
                    PlanPhase(name="Reporting"),
                ],
            )

        # Update confidence
        self._plan.confidence = confidence
        self._plan.updated_at = time.time()

        # Update key findings
        if key_findings_summary:
            if key_findings_summary not in self._plan.key_findings:
                self._plan.key_findings.append(key_findings_summary)

        # Match and update phase
        for i, phase in enumerate(self._plan.phases):
            if phase.name.lower() == current_phase.lower():
                phase.status = "active"
                self._plan.current_phase_index = i
                # Mark completed objectives
                for item in completed:
                    if item not in phase.completed_objectives:
                        phase.completed_objectives.append(item)
                # Update objectives from next_steps
                for step in next_steps:
                    if step not in phase.objectives:
                        phase.objectives.append(step)
                break

        # Mark earlier phases as completed
        for i in range(self._plan.current_phase_index):
            if self._plan.phases[i].status != "skipped":
                self._plan.phases[i].status = "completed"
                if not self._plan.phases[i].completed_at:
                    self._plan.phases[i].completed_at = time.time()

        self._save()
        return self._plan

    def add_checkpoint(
        self,
        step: int,
        max_steps: int,
        findings_count: int,
        notes: str = "",
    ) -> None:
        """Record a checkpoint at a budget threshold."""
        if not self._plan:
            return

        checkpoint = {
            "step": step,
            "budget_pct": (step / max_steps * 100) if max_steps > 0 else 0,
            "findings_count": findings_count,
            "confidence": self._plan.confidence,
            "current_phase": self._plan.current_phase.name if self._plan.current_phase else "unknown",
            "notes": notes,
            "timestamp": time.time(),
        }
        self._plan.checkpoints.append(checkpoint)
        self._save()

    def should_checkpoint(self, current_step: int, max_steps: int) -> bool:
        """Check if we should trigger a checkpoint at this step."""
        if max_steps <= 0:
            return False

        budget_pct = current_step / max_steps * 100
        thresholds = [20, 40, 60, 80]

        # Find the nearest threshold we haven't checkpointed yet
        existing_pcts = {
            round(cp["budget_pct"]) for cp in (self._plan.checkpoints if self._plan else [])
        }

        for threshold in thresholds:
            if threshold not in existing_pcts:
                # Allow +-2% tolerance
                if abs(budget_pct - threshold) < 2.5:
                    return True

        return False

    def get_snapshot(self) -> str:
        """Get plan snapshot text for prompt injection."""
        if not self._plan:
            return "No plan created yet."
        return self._plan.to_snapshot()

    def _save(self) -> None:
        """Persist plan to disk."""
        if not self.persist_dir or not self._plan:
            return

        os.makedirs(self.persist_dir, exist_ok=True)
        filepath = os.path.join(self.persist_dir, "plan.json")
        with open(filepath, "w") as f:
            json.dump(self._plan.to_dict(), f, indent=2)

    def _load(self) -> None:
        """Load plan from disk."""
        if not self.persist_dir:
            return

        filepath = os.path.join(self.persist_dir, "plan.json")
        if not os.path.exists(filepath):
            return

        try:
            with open(filepath) as f:
                data = json.load(f)

            phases = [
                PlanPhase(
                    name=p["name"],
                    status=p.get("status", "pending"),
                    objectives=p.get("objectives", []),
                    completed_objectives=p.get("completed_objectives", []),
                )
                for p in data.get("phases", [])
            ]

            self._plan = OperationPlan(
                objective=data.get("objective", ""),
                phases=phases,
                confidence=data.get("confidence", 50.0),
                key_findings=data.get("key_findings", []),
            )
            logger.info(f"Loaded plan from {filepath}")
        except Exception as e:
            logger.warning(f"Failed to load plan: {e}")

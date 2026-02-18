"""Operation-level observability for the LLM-driven agent.

Tracks metrics across an entire operation: token usage, cost,
tool effectiveness, timing, and findings.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolMetrics:
    """Metrics for a single tool type."""
    call_count: int = 0
    error_count: int = 0
    total_duration_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.call_count == 0:
            return 0.0
        return (self.call_count - self.error_count) / self.call_count

    @property
    def avg_duration_ms(self) -> float:
        if self.call_count == 0:
            return 0.0
        return self.total_duration_ms / self.call_count


@dataclass
class PhaseMetrics:
    """Metrics for a single operation phase."""
    name: str
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    steps_used: int = 0
    findings_during: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0


@dataclass
class OperationTracker:
    """Tracks comprehensive metrics for an LLM-driven agent operation.

    Aggregates data from tool executions, LLM calls (via CostTracker),
    and findings to produce an operation-level metrics report.
    """
    operation_id: str
    target: str
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    # Token tracking
    total_input_tokens: int = 0
    total_output_tokens: int = 0

    # Cost tracking
    total_cost_usd: float = 0.0
    cost_by_tier: Dict[str, float] = field(default_factory=dict)

    # Tool tracking
    tool_metrics: Dict[str, ToolMetrics] = field(default_factory=dict)

    # Finding tracking
    findings_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })

    # Phase tracking
    phases: List[PhaseMetrics] = field(default_factory=list)
    current_phase: Optional[str] = None

    # Step tracking
    steps_used: int = 0
    max_steps: int = 0

    def record_tool_execution(
        self,
        tool_name: str,
        duration_ms: float,
        is_error: bool,
    ) -> None:
        """Record a tool execution."""
        if tool_name not in self.tool_metrics:
            self.tool_metrics[tool_name] = ToolMetrics()

        metrics = self.tool_metrics[tool_name]
        metrics.call_count += 1
        metrics.total_duration_ms += duration_ms
        if is_error:
            metrics.error_count += 1

        self.steps_used += 1

    def record_llm_call(
        self,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        tier: str,
    ) -> None:
        """Record an LLM API call."""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost_usd
        self.cost_by_tier[tier] = self.cost_by_tier.get(tier, 0.0) + cost_usd

    def record_finding(self, severity: str) -> None:
        """Record a vulnerability finding."""
        severity = severity.lower()
        if severity in self.findings_by_severity:
            self.findings_by_severity[severity] += 1

    def start_phase(self, phase_name: str) -> None:
        """Start a new operation phase."""
        # Complete current phase
        if self.phases and not self.phases[-1].completed_at:
            self.phases[-1].completed_at = time.time()

        self.current_phase = phase_name
        self.phases.append(PhaseMetrics(
            name=phase_name,
            started_at=time.time(),
        ))

    def complete(self) -> None:
        """Mark the operation as complete."""
        self.completed_at = time.time()
        if self.phases and not self.phases[-1].completed_at:
            self.phases[-1].completed_at = time.time()

    @property
    def duration_seconds(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def total_findings(self) -> int:
        return sum(self.findings_by_severity.values())

    @property
    def efficiency_score(self) -> float:
        """Findings per step — higher is better."""
        if self.steps_used == 0:
            return 0.0
        return self.total_findings / self.steps_used

    def report(self) -> Dict[str, Any]:
        """Generate a comprehensive metrics report."""
        return {
            "operation_id": self.operation_id,
            "target": self.target,
            "duration_seconds": round(self.duration_seconds, 1),
            "steps": {
                "used": self.steps_used,
                "max": self.max_steps,
                "utilization_pct": round(
                    (self.steps_used / self.max_steps * 100) if self.max_steps > 0 else 0, 1
                ),
            },
            "tokens": {
                "input": self.total_input_tokens,
                "output": self.total_output_tokens,
                "total": self.total_tokens,
            },
            "cost": {
                "total_usd": round(self.total_cost_usd, 4),
                "by_tier": {k: round(v, 4) for k, v in self.cost_by_tier.items()},
            },
            "findings": {
                "total": self.total_findings,
                "by_severity": self.findings_by_severity,
                "efficiency": round(self.efficiency_score, 4),
            },
            "tools": {
                name: {
                    "calls": m.call_count,
                    "errors": m.error_count,
                    "success_rate": round(m.success_rate, 2),
                    "avg_duration_ms": round(m.avg_duration_ms, 1),
                }
                for name, m in sorted(
                    self.tool_metrics.items(),
                    key=lambda x: -x[1].call_count,
                )
            },
            "phases": [
                {
                    "name": p.name,
                    "duration_seconds": round(p.duration_seconds, 1),
                    "steps_used": p.steps_used,
                }
                for p in self.phases
            ],
        }

    def save(self, directory: str) -> str:
        """Save metrics report to a JSON file."""
        os.makedirs(directory, exist_ok=True)
        filepath = os.path.join(directory, "operation_metrics.json")
        with open(filepath, "w") as f:
            json.dump(self.report(), f, indent=2)
        return filepath

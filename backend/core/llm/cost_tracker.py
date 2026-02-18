"""Per-tier token and cost tracking with budget enforcement."""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .providers.base import LLMResponse, ModelTier


# Cost per 1M tokens (USD), approximate as of Feb 2026
COST_PER_1M_TOKENS: Dict[str, Dict[str, float]] = {
    # Anthropic
    "claude-haiku-4-5-20250929": {"input": 0.80, "output": 4.00},
    "claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00},
    "claude-opus-4-5-20250929": {"input": 15.00, "output": 75.00},
    # OpenAI
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    # Gemini
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
    "gemini-2.0-pro": {"input": 1.25, "output": 5.00},
    # Bedrock (same as Anthropic for Claude models)
    "us.anthropic.claude-haiku-4-5-20250929-v1:0": {"input": 0.80, "output": 4.00},
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0": {"input": 3.00, "output": 15.00},
    "us.anthropic.claude-opus-4-5-20250929-v1:0": {"input": 15.00, "output": 75.00},
}


@dataclass
class CallRecord:
    """Record of a single LLM call."""
    timestamp: float
    task_type: str
    tier: ModelTier
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: float = 0.0


@dataclass
class CostTracker:
    """Tracks LLM token usage and costs per scan session."""

    budget_usd: float = 5.00
    warn_at_pct: float = 80.0
    enabled: bool = True
    calls: List[CallRecord] = field(default_factory=list)
    _warned: bool = field(default=False, repr=False)

    def record(
        self,
        response: LLMResponse,
        task_type: str,
        tier: ModelTier,
        duration_ms: float = 0.0,
    ) -> CallRecord:
        """Record a completed LLM call and return the record."""
        cost = self._estimate_cost(
            response.model, response.input_tokens, response.output_tokens
        )

        record = CallRecord(
            timestamp=time.time(),
            task_type=task_type,
            tier=tier,
            model=response.model,
            provider=response.provider,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=cost,
            duration_ms=duration_ms,
        )
        self.calls.append(record)
        return record

    def _estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD for a call."""
        rates = COST_PER_1M_TOKENS.get(model)
        if not rates:
            return 0.0
        input_cost = (input_tokens / 1_000_000) * rates["input"]
        output_cost = (output_tokens / 1_000_000) * rates["output"]
        return input_cost + output_cost

    @property
    def total_cost(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def total_input_tokens(self) -> int:
        return sum(c.input_tokens for c in self.calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.budget_usd - self.total_cost)

    @property
    def budget_pct_used(self) -> float:
        if self.budget_usd <= 0:
            return 0.0
        return (self.total_cost / self.budget_usd) * 100

    @property
    def over_budget(self) -> bool:
        return self.total_cost >= self.budget_usd

    @property
    def should_warn(self) -> bool:
        """True if budget warning threshold exceeded (fires once)."""
        if self._warned:
            return False
        if self.budget_pct_used >= self.warn_at_pct:
            self._warned = True
            return True
        return False

    def tier_summary(self) -> Dict[str, Dict[str, Any]]:
        """Per-tier usage summary."""
        summary: Dict[str, Dict[str, Any]] = {}
        for tier in ModelTier:
            tier_calls = [c for c in self.calls if c.tier == tier]
            summary[tier.value] = {
                "calls": len(tier_calls),
                "input_tokens": sum(c.input_tokens for c in tier_calls),
                "output_tokens": sum(c.output_tokens for c in tier_calls),
                "cost_usd": round(sum(c.cost_usd for c in tier_calls), 4),
            }
        return summary

    def report(self) -> Dict[str, Any]:
        """Full cost report for the scan session."""
        return {
            "total_calls": len(self.calls),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost, 4),
            "budget_usd": self.budget_usd,
            "budget_remaining_usd": round(self.budget_remaining, 4),
            "budget_pct_used": round(self.budget_pct_used, 1),
            "tiers": self.tier_summary(),
        }

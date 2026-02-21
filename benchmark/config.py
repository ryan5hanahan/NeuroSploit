"""Benchmark configuration."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BenchmarkConfig:
    """Configuration for a single benchmark run.

    Fields mirror the agent constructor parameters so the runner can forward
    them without translation.
    """

    # Required target fields
    target_name: str = "juice_shop"
    target_url: str = "http://juice-shop:3000"

    # Agent budget controls
    max_steps: int = 50
    budget_usd: float = 2.0
    timeout_seconds: int = 600  # 10 minutes

    # Scoring
    ground_truth_path: str = "benchmark/ground_truth/juice_shop.yaml"

    # Results persistence
    results_dir: str = "benchmark/results"

    # Optional LLM overrides
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None

    # Tagging/metadata for multi-run comparisons
    tags: List[str] = field(default_factory=list)

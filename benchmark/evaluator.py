"""
Agent Evaluation Framework — Compare and analyze benchmark results.

Provides precision/recall/F1 scoring, cost efficiency metrics,
and A/B comparison between benchmark runs.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EvalResult:
    """Evaluation result for a single benchmark run."""
    target_name: str
    timestamp: str
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    cost_usd: float = 0.0
    cost_per_finding: float = 0.0
    steps_used: int = 0
    duration_seconds: float = 0.0
    findings_per_minute: float = 0.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComparisonReport:
    """A/B comparison between two benchmark runs."""
    baseline: EvalResult
    candidate: EvalResult
    precision_delta: float = 0.0
    recall_delta: float = 0.0
    f1_delta: float = 0.0
    cost_delta: float = 0.0
    speed_delta: float = 0.0
    recommendation: str = ""


class AgentEvaluator:
    """Evaluates agent performance against ground truth and compares runs."""

    async def evaluate_run(
        self,
        result: Dict[str, Any],
        ground_truth: List[Dict[str, Any]],
    ) -> EvalResult:
        """Evaluate a single benchmark run against ground truth.

        Args:
            result: Benchmark run result dict (from BenchmarkRunner).
            ground_truth: List of ground truth vulnerability entries.

        Returns:
            EvalResult with computed metrics.
        """
        scores = result.get("scores", {})
        config = result.get("config", {})

        total_findings = scores.get("total_findings", 0)
        matched = scores.get("matched_findings", 0)
        ground_truth_count = scores.get("ground_truth_count", len(ground_truth))
        false_positives = total_findings - matched
        false_negatives = ground_truth_count - matched

        precision = scores.get("precision", 0.0)
        recall = scores.get("recall", 0.0)
        f1 = scores.get("f1_score", 0.0)

        cost_usd = scores.get("cost_usd", 0.0)
        steps_used = scores.get("steps_used", 0)
        duration = scores.get("duration_seconds", 0.0)

        cost_per_finding = cost_usd / matched if matched > 0 else 0.0
        findings_per_min = (matched / (duration / 60.0)) if duration > 0 else 0.0

        return EvalResult(
            target_name=config.get("target_name", "unknown"),
            timestamp=result.get("timestamp", datetime.utcnow().isoformat()),
            total_findings=total_findings,
            true_positives=matched,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1,
            cost_usd=cost_usd,
            cost_per_finding=round(cost_per_finding, 4),
            steps_used=steps_used,
            duration_seconds=duration,
            findings_per_minute=round(findings_per_min, 2),
            tags=config.get("tags", []),
            metadata=result.get("metadata", {}),
        )

    async def evaluate_suite(
        self, results: List[Dict[str, Any]], ground_truths: Dict[str, List[Dict]]
    ) -> List[EvalResult]:
        """Evaluate a suite of benchmark runs.

        Args:
            results: List of benchmark result dicts.
            ground_truths: Map of target_name -> ground truth list.

        Returns:
            List of EvalResult for each run.
        """
        eval_results = []
        for result in results:
            target = result.get("config", {}).get("target_name", "unknown")
            gt = ground_truths.get(target, [])
            eval_result = await self.evaluate_run(result, gt)
            eval_results.append(eval_result)
        return eval_results

    def compare_runs(
        self, baseline: EvalResult, candidate: EvalResult
    ) -> ComparisonReport:
        """Compare two benchmark runs (A/B comparison).

        Args:
            baseline: The baseline (control) run.
            candidate: The candidate (experimental) run.

        Returns:
            ComparisonReport with deltas and recommendation.
        """
        precision_delta = candidate.precision - baseline.precision
        recall_delta = candidate.recall - baseline.recall
        f1_delta = candidate.f1_score - baseline.f1_score
        cost_delta = candidate.cost_usd - baseline.cost_usd
        speed_delta = candidate.findings_per_minute - baseline.findings_per_minute

        # Generate recommendation
        improvements = []
        regressions = []

        if f1_delta > 0.05:
            improvements.append(f"F1 improved by {f1_delta:+.3f}")
        elif f1_delta < -0.05:
            regressions.append(f"F1 regressed by {f1_delta:+.3f}")

        if precision_delta > 0.05:
            improvements.append(f"Precision improved by {precision_delta:+.3f}")
        elif precision_delta < -0.05:
            regressions.append(f"Precision regressed by {precision_delta:+.3f}")

        if recall_delta > 0.05:
            improvements.append(f"Recall improved by {recall_delta:+.3f}")
        elif recall_delta < -0.05:
            regressions.append(f"Recall regressed by {recall_delta:+.3f}")

        if cost_delta < -0.1:
            improvements.append(f"Cost reduced by ${abs(cost_delta):.2f}")
        elif cost_delta > 0.1:
            regressions.append(f"Cost increased by ${cost_delta:.2f}")

        if improvements and not regressions:
            recommendation = "ACCEPT: " + "; ".join(improvements)
        elif regressions and not improvements:
            recommendation = "REJECT: " + "; ".join(regressions)
        elif improvements and regressions:
            recommendation = "REVIEW: " + "; ".join(improvements + regressions)
        else:
            recommendation = "NEUTRAL: No significant changes detected"

        return ComparisonReport(
            baseline=baseline,
            candidate=candidate,
            precision_delta=round(precision_delta, 4),
            recall_delta=round(recall_delta, 4),
            f1_delta=round(f1_delta, 4),
            cost_delta=round(cost_delta, 4),
            speed_delta=round(speed_delta, 4),
            recommendation=recommendation,
        )

    def generate_comparison_markdown(self, report: ComparisonReport) -> str:
        """Generate a markdown comparison report."""
        lines = [
            "# Benchmark Comparison Report",
            "",
            f"**Generated**: {datetime.utcnow().isoformat()}Z",
            "",
            "## Metrics Comparison",
            "",
            "| Metric | Baseline | Candidate | Delta |",
            "|--------|----------|-----------|-------|",
            f"| Precision | {report.baseline.precision:.3f} | {report.candidate.precision:.3f} | {report.precision_delta:+.3f} |",
            f"| Recall | {report.baseline.recall:.3f} | {report.candidate.recall:.3f} | {report.recall_delta:+.3f} |",
            f"| F1 Score | {report.baseline.f1_score:.3f} | {report.candidate.f1_score:.3f} | {report.f1_delta:+.3f} |",
            f"| Cost (USD) | ${report.baseline.cost_usd:.2f} | ${report.candidate.cost_usd:.2f} | {report.cost_delta:+.2f} |",
            f"| Findings/min | {report.baseline.findings_per_minute:.1f} | {report.candidate.findings_per_minute:.1f} | {report.speed_delta:+.1f} |",
            f"| Steps | {report.baseline.steps_used} | {report.candidate.steps_used} | {report.candidate.steps_used - report.baseline.steps_used:+d} |",
            "",
            "## Recommendation",
            "",
            f"**{report.recommendation}**",
            "",
        ]
        return "\n".join(lines)

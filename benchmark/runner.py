"""Benchmark Runner — orchestrate target healthcheck, agent run, scoring, and report.

Usage:
    python -m benchmark.runner --target juice_shop
    python benchmark/runner.py --target juice_shop --max-steps 50 --budget 2.0
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict

# Ensure project root on sys.path so both `benchmark.*` and `backend.*` resolve
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from benchmark.config import BenchmarkConfig
from benchmark.report import BenchmarkReportGenerator
from benchmark.scorer import Scorer
from benchmark.targets.juice_shop import JuiceShopTarget

logger = logging.getLogger(__name__)

# Registry: target_name -> target class
TARGET_REGISTRY = {
    "juice_shop": JuiceShopTarget,
}


class BenchmarkRunner:
    """Run the LLM agent against a benchmark target and produce scored results.

    Follows the scan_service.py pattern for instantiating LLMDrivenAgent:
        agent = LLMDrivenAgent(target=url, objective=..., max_steps=...)
        result = await agent.run()

    The runner is responsible for:
    1. Resolving the target class from the config.
    2. Polling the healthcheck URL until the container is ready.
    3. Instantiating and running LLMDrivenAgent.
    4. Collecting findings from AgentResult.
    5. Scoring them against the ground truth.
    6. Persisting results to disk and returning a results dict.
    """

    def __init__(self, config: BenchmarkConfig):
        self.config = config

    async def run(self) -> Dict[str, Any]:
        """Execute a full benchmark run.

        Returns:
            Dict containing:
                target       (str)
                timestamp    (str, ISO format)
                config       (dict — serialised BenchmarkConfig)
                agent_status (str — AgentResult.status)
                scores       (dict — Scorer.score_findings() output)
                agent_meta   (dict — steps, duration, tool_usage, artifacts_dir)
        """
        # Resolve target
        target_cls = TARGET_REGISTRY.get(self.config.target_name)
        if not target_cls:
            raise ValueError(
                f"Unknown benchmark target: '{self.config.target_name}'. "
                f"Available: {list(TARGET_REGISTRY.keys())}"
            )

        target = target_cls()
        logger.info(
            f"[BenchmarkRunner] Starting run: target={target.name} "
            f"url={self.config.target_url} max_steps={self.config.max_steps}"
        )

        # Wait for target to be accepting connections
        await self._wait_for_target(
            target.get_healthcheck_url(),
            timeout=min(self.config.timeout_seconds // 3, 120),
        )

        # Run agent
        wall_start = time.monotonic()
        agent_result = await self._run_agent(target)
        duration = time.monotonic() - wall_start

        # Collect cost
        cost_usd = 0.0
        if agent_result.cost_report:
            cost_usd = agent_result.cost_report.get("total_cost_usd", 0.0)

        # Load ground truth and score
        ground_truth = Scorer._load_ground_truth_from_yaml(target.get_ground_truth_path())
        scorer = Scorer(ground_truth)
        scores = scorer.score_findings(
            findings=agent_result.findings,
            cost_usd=cost_usd,
            steps_used=agent_result.steps_used,
            duration_seconds=duration,
        )

        # Build full results dict
        results = {
            "target": target.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "config": {
                "target_name": self.config.target_name,
                "target_url": self.config.target_url,
                "max_steps": self.config.max_steps,
                "budget_usd": self.config.budget_usd,
                "timeout_seconds": self.config.timeout_seconds,
                "ground_truth_path": self.config.ground_truth_path,
                "tags": self.config.tags,
            },
            "agent_status": agent_result.status,
            "scores": scores,
            "agent_meta": {
                "operation_id": agent_result.operation_id,
                "steps_used": agent_result.steps_used,
                "max_steps": agent_result.max_steps,
                "duration_seconds": round(duration, 2),
                "cost_usd": round(cost_usd, 4),
                "cost_report": agent_result.cost_report,
                "stop_reason": agent_result.stop_reason,
                "stop_summary": agent_result.stop_summary,
                "tool_usage": agent_result.tool_usage,
                "artifacts_dir": agent_result.artifacts_dir,
                "error": agent_result.error,
            },
        }

        # Persist results
        self._save_results(results)

        return results

    async def _run_agent(self, target):
        """Instantiate and run LLMDrivenAgent (mirrors scan_service.py pattern)."""
        from backend.core.llm import UnifiedLLMClient
        from backend.core.llm_agent import LLMDrivenAgent

        llm_client = UnifiedLLMClient()

        agent = LLMDrivenAgent(
            target=self.config.target_url,
            objective=target.get_objective(),
            max_steps=self.config.max_steps,
            llm_client=llm_client,
            data_dir=self.config.results_dir,
        )

        try:
            return await asyncio.wait_for(
                agent.run(),
                timeout=self.config.timeout_seconds,
            )
        except asyncio.TimeoutError:
            agent.cancel()
            logger.warning(
                f"[BenchmarkRunner] Agent timed out after {self.config.timeout_seconds}s"
            )
            raise

    async def _wait_for_target(self, url: str, timeout: int = 120) -> None:
        """Poll the healthcheck URL until it responds or the timeout expires."""
        import aiohttp

        deadline = time.monotonic() + timeout
        logger.info(f"[BenchmarkRunner] Waiting for target at {url} (timeout={timeout}s)...")

        while time.monotonic() < deadline:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5), ssl=False
                    ) as resp:
                        if resp.status < 500:
                            logger.info(
                                f"[BenchmarkRunner] Target ready: {url} (HTTP {resp.status})"
                            )
                            return
            except Exception:
                pass
            await asyncio.sleep(3)

        raise TimeoutError(
            f"[BenchmarkRunner] Target {url} not ready after {timeout}s. "
            "Is the Docker container running?"
        )

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Persist results to JSON and generate markdown report."""
        os.makedirs(self.config.results_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = f"benchmark_{self.config.target_name}_{ts}"

        # JSON
        json_path = os.path.join(self.config.results_dir, f"{base}.json")
        with open(json_path, "w") as fh:
            json.dump(results, fh, indent=2, default=str)
        logger.info(f"[BenchmarkRunner] JSON results saved: {json_path}")

        # Markdown
        reporter = BenchmarkReportGenerator()
        md_path = os.path.join(self.config.results_dir, f"{base}.md")
        with open(md_path, "w") as fh:
            fh.write(reporter.generate_markdown(results))
        logger.info(f"[BenchmarkRunner] Markdown report saved: {md_path}")


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="sploit.ai Phase 1 Benchmark Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default="juice_shop",
        choices=list(TARGET_REGISTRY.keys()),
        help="Benchmark target to run against",
    )
    parser.add_argument("--target-url", default="", help="Override target URL")
    parser.add_argument("--max-steps", type=int, default=50, help="Agent step budget")
    parser.add_argument("--budget", type=float, default=2.0, help="LLM cost budget (USD)")
    parser.add_argument("--timeout", type=int, default=600, help="Overall timeout (seconds)")
    parser.add_argument("--results-dir", default="benchmark/results", help="Output directory")
    args = parser.parse_args()

    # Build config — resolve target URL if not explicitly overridden
    target_url = args.target_url
    if not target_url:
        target_cls = TARGET_REGISTRY[args.target]
        target_url = target_cls().get_healthcheck_url()

    config = BenchmarkConfig(
        target_name=args.target,
        target_url=target_url,
        max_steps=args.max_steps,
        budget_usd=args.budget,
        timeout_seconds=args.timeout,
        results_dir=args.results_dir,
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    results = asyncio.run(BenchmarkRunner(config).run())
    scores = results.get("scores", {})

    print(f"\n{'='*60}")
    print(f"Benchmark Results: {config.target_name}")
    print(f"{'='*60}")
    print(f"Precision:        {scores.get('precision', 0):.2%}")
    print(f"Recall:           {scores.get('recall', 0):.2%}")
    print(f"F1 Score:         {scores.get('f1', 0):.2%}")
    print(
        f"TP: {scores.get('true_positives', 0)} | "
        f"FP: {scores.get('false_positives', 0)} | "
        f"FN: {scores.get('false_negatives', 0)}"
    )
    print(
        f"Cost: ${scores.get('cost_usd', 0):.4f} | "
        f"Cost/finding: ${scores.get('cost_per_finding', 0):.4f}"
    )
    meta = results.get("agent_meta", {})
    print(f"Steps: {meta.get('steps_used', 0)} | Duration: {meta.get('duration_seconds', 0):.1f}s")
    print(f"Agent status: {results.get('agent_status', 'unknown')}")


if __name__ == "__main__":
    main()

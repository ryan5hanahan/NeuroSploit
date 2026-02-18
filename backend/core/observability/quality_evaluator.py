"""Post-operation quality evaluation for the LLM-driven agent.

Evaluates operation quality based on coverage, efficiency,
evidence quality, and methodology adherence.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    """Result of a quality evaluation."""
    overall_score: float  # 0-100
    dimensions: Dict[str, float]  # Dimension name → score (0-100)
    notes: List[str] = field(default_factory=list)


class QualityEvaluator:
    """Evaluates the quality of an LLM-driven agent operation.

    Scores the operation across multiple dimensions:
    - Coverage: How thoroughly was the target explored?
    - Efficiency: How well were steps utilized?
    - Evidence: How strong is the evidence for findings?
    - Methodology: Did the agent follow proper methodology?
    - Reporting: Are findings well-documented?
    """

    def evaluate(
        self,
        findings: List[Dict[str, Any]],
        steps_used: int,
        max_steps: int,
        tool_usage: Dict[str, int],
        plan_phases: List[Dict[str, Any]],
        duration_seconds: float,
    ) -> EvaluationResult:
        """Evaluate an operation's quality.

        Args:
            findings: List of reported findings.
            steps_used: Total steps used.
            max_steps: Maximum steps allowed.
            tool_usage: Dict of tool_name → call_count.
            plan_phases: List of plan phase dicts.
            duration_seconds: Total operation duration.

        Returns:
            EvaluationResult with scores and notes.
        """
        dimensions = {}
        notes = []

        # 1. Coverage (0-100): Tool diversity and target exploration
        dimensions["coverage"] = self._score_coverage(tool_usage, findings, notes)

        # 2. Efficiency (0-100): Step utilization and finding rate
        dimensions["efficiency"] = self._score_efficiency(
            findings, steps_used, max_steps, notes
        )

        # 3. Evidence Quality (0-100): Strength of finding evidence
        dimensions["evidence_quality"] = self._score_evidence(findings, notes)

        # 4. Methodology (0-100): Adherence to testing methodology
        dimensions["methodology"] = self._score_methodology(
            tool_usage, plan_phases, notes
        )

        # 5. Reporting (0-100): Completeness of finding documentation
        dimensions["reporting"] = self._score_reporting(findings, notes)

        # Overall score (weighted average)
        weights = {
            "coverage": 0.20,
            "efficiency": 0.15,
            "evidence_quality": 0.30,
            "methodology": 0.15,
            "reporting": 0.20,
        }
        overall = sum(
            dimensions[dim] * weights.get(dim, 0.2)
            for dim in dimensions
        )

        return EvaluationResult(
            overall_score=round(overall, 1),
            dimensions={k: round(v, 1) for k, v in dimensions.items()},
            notes=notes,
        )

    def _score_coverage(
        self,
        tool_usage: Dict[str, int],
        findings: List[Dict],
        notes: List[str],
    ) -> float:
        """Score target exploration coverage."""
        score = 0.0

        # Tool diversity (max 40 points)
        tool_categories = {
            "recon": ["shell_execute"],
            "http": ["http_request"],
            "browser": [
                "browser_navigate", "browser_extract_links",
                "browser_extract_forms", "browser_execute_js",
            ],
            "memory": ["memory_store", "memory_search"],
            "evidence": ["browser_screenshot", "save_artifact"],
            "reporting": ["report_finding"],
        }

        categories_used = 0
        for cat, tools in tool_categories.items():
            if any(tool_usage.get(t, 0) > 0 for t in tools):
                categories_used += 1

        score += min(categories_used / len(tool_categories) * 40, 40)

        # Finding diversity by vuln type (max 30 points)
        vuln_types = {f.get("vuln_type", "unknown") for f in findings}
        type_score = min(len(vuln_types) * 10, 30)
        score += type_score

        # Recon depth (max 30 points)
        shell_calls = tool_usage.get("shell_execute", 0)
        http_calls = tool_usage.get("http_request", 0)
        browser_calls = sum(
            tool_usage.get(t, 0) for t in ["browser_navigate", "browser_extract_links"]
        )
        recon_score = min((shell_calls + http_calls + browser_calls) / 10 * 30, 30)
        score += recon_score

        if categories_used <= 2:
            notes.append("Low tool diversity — only used tools from 1-2 categories")

        return min(score, 100)

    def _score_efficiency(
        self,
        findings: List[Dict],
        steps_used: int,
        max_steps: int,
        notes: List[str],
    ) -> float:
        """Score step utilization efficiency."""
        if steps_used == 0:
            return 0.0

        score = 0.0

        # Finding rate (max 50 points)
        rate = len(findings) / steps_used if steps_used > 0 else 0
        score += min(rate * 500, 50)  # 0.1 findings/step = 50 points

        # Budget utilization (max 30 points) — using 50-90% is ideal
        utilization = steps_used / max_steps if max_steps > 0 else 0
        if 0.5 <= utilization <= 0.9:
            score += 30
        elif 0.3 <= utilization <= 0.95:
            score += 20
        else:
            score += 10

        # High-severity finding bonus (max 20 points)
        high_sev = sum(
            1 for f in findings
            if f.get("severity") in ("critical", "high")
        )
        score += min(high_sev * 10, 20)

        if rate < 0.02:
            notes.append(
                "Low finding rate — consider more targeted testing"
            )

        return min(score, 100)

    def _score_evidence(
        self,
        findings: List[Dict],
        notes: List[str],
    ) -> float:
        """Score evidence quality across all findings."""
        if not findings:
            return 0.0

        total_score = 0.0
        for finding in findings:
            finding_score = 0.0

            evidence = finding.get("evidence", "")
            # Has substantial evidence (max 40 points)
            if len(evidence) > 100:
                finding_score += 40
            elif len(evidence) > 20:
                finding_score += 20

            # Has reproduction steps (max 30 points)
            repro = finding.get("reproduction_steps", "")
            if len(repro) > 50:
                finding_score += 30
            elif repro:
                finding_score += 15

            # Has HTTP details in evidence (max 30 points)
            evidence_lower = evidence.lower()
            if any(kw in evidence_lower for kw in [
                "http", "status", "response", "request", "header",
                "cookie", "token", "200", "401", "403", "500",
            ]):
                finding_score += 30

            total_score += finding_score

        avg_score = total_score / len(findings)

        weak_findings = sum(
            1 for f in findings if len(f.get("evidence", "")) < 50
        )
        if weak_findings > 0:
            notes.append(
                f"{weak_findings} finding(s) have weak evidence (<50 chars)"
            )

        return min(avg_score, 100)

    def _score_methodology(
        self,
        tool_usage: Dict[str, int],
        plan_phases: List[Dict[str, Any]],
        notes: List[str],
    ) -> float:
        """Score methodology adherence."""
        score = 0.0

        # Used planning tool (max 25 points)
        plan_updates = tool_usage.get("update_plan", 0)
        if plan_updates >= 3:
            score += 25
        elif plan_updates >= 1:
            score += 15
        else:
            notes.append("No plan created — agent should use update_plan")

        # Used memory system (max 25 points)
        memory_stores = tool_usage.get("memory_store", 0)
        memory_searches = tool_usage.get("memory_search", 0)
        if memory_stores >= 3 and memory_searches >= 1:
            score += 25
        elif memory_stores >= 1:
            score += 15

        # Started with recon (max 25 points)
        if tool_usage.get("shell_execute", 0) > 0 or tool_usage.get("browser_navigate", 0) > 0:
            score += 25

        # Used evidence capture (max 25 points)
        screenshots = tool_usage.get("browser_screenshot", 0)
        artifacts = tool_usage.get("save_artifact", 0)
        if screenshots + artifacts >= 2:
            score += 25
        elif screenshots + artifacts >= 1:
            score += 15

        return min(score, 100)

    def _score_reporting(
        self,
        findings: List[Dict],
        notes: List[str],
    ) -> float:
        """Score finding documentation quality."""
        if not findings:
            return 50.0  # Neutral if no findings (could mean target is secure)

        total_score = 0.0
        for finding in findings:
            finding_score = 0.0

            # Has title (20 points)
            if finding.get("title"):
                finding_score += 20

            # Has severity (20 points)
            if finding.get("severity"):
                finding_score += 20

            # Has description (20 points)
            desc = finding.get("description", "")
            if len(desc) > 50:
                finding_score += 20
            elif desc:
                finding_score += 10

            # Has endpoint (20 points)
            if finding.get("endpoint"):
                finding_score += 20

            # Has remediation (20 points)
            if finding.get("remediation"):
                finding_score += 20

            total_score += finding_score

        avg = total_score / len(findings)

        incomplete = sum(
            1 for f in findings
            if not f.get("remediation")
        )
        if incomplete > 0:
            notes.append(
                f"{incomplete} finding(s) missing remediation guidance"
            )

        return min(avg, 100)

    def save_report(
        self,
        result: EvaluationResult,
        directory: str,
    ) -> str:
        """Save evaluation report to file."""
        os.makedirs(directory, exist_ok=True)
        filepath = os.path.join(directory, "quality_evaluation.json")
        with open(filepath, "w") as f:
            json.dump({
                "overall_score": result.overall_score,
                "dimensions": result.dimensions,
                "notes": result.notes,
            }, f, indent=2)
        return filepath

"""Benchmark report generation — markdown and JSON output.

The BenchmarkReportGenerator class is the primary interface.  It accepts the
results dict returned by BenchmarkRunner.run() and renders it in two formats:
  - Markdown: human-readable report with scores table, finding breakdown, and
              recommendations (for sharing in PRs or tracking progress over runs).
  - JSON:     machine-readable copy of the full results dict (indented).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List


class BenchmarkReportGenerator:
    """Generate benchmark reports in markdown and JSON formats.

    Usage:
        reporter = BenchmarkReportGenerator()
        md_text   = reporter.generate_markdown(results)
        json_text = reporter.generate_json(results)
    """

    def generate_markdown(self, results: Dict[str, Any]) -> str:
        """Render results as a markdown report string.

        Sections:
        1. Header with target name, timestamp, and config summary
        2. Scores table (precision, recall, F1, TP/FP/FN, cost)
        3. Per-finding breakdown (matched TPs with score, unmatched FPs, missed FNs)
        4. Recommendations based on recall/precision/cost gaps

        Args:
            results: Dict as returned by BenchmarkRunner.run().

        Returns:
            Multi-line markdown string.
        """
        target = results.get("target", "unknown")
        timestamp = results.get("timestamp", datetime.now(timezone.utc).isoformat())
        cfg = results.get("config", {})
        scores = results.get("scores", {})
        meta = results.get("agent_meta", {})
        agent_status = results.get("agent_status", "unknown")

        lines: List[str] = []

        # ---- Header ----
        lines += [
            f"# Benchmark Report: {target}",
            "",
            f"**Date**: {timestamp}",
            f"**Target**: {target}",
            f"**Agent status**: {agent_status}",
            "",
            "## Configuration",
            "",
            "| Parameter | Value |",
            "|-----------|-------|",
            f"| Max steps | {cfg.get('max_steps', '-')} |",
            f"| Budget (USD) | ${cfg.get('budget_usd', 0):.2f} |",
            f"| Timeout (s) | {cfg.get('timeout_seconds', '-')} |",
            f"| Target URL | {cfg.get('target_url', '-')} |",
            f"| Ground truth | {cfg.get('ground_truth_path', '-')} |",
            "",
        ]

        # ---- Scores table ----
        tp = scores.get("true_positives", 0)
        fp = scores.get("false_positives", 0)
        fn = scores.get("false_negatives", 0)
        precision = scores.get("precision", 0.0)
        recall = scores.get("recall", 0.0)
        f1 = scores.get("f1", 0.0)
        cost_usd = scores.get("cost_usd", 0.0)
        cost_per_finding = scores.get("cost_per_finding", 0.0)

        lines += [
            "## Scores",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Precision | {precision:.2%} |",
            f"| Recall | {recall:.2%} |",
            f"| F1 Score | **{f1:.2%}** |",
            f"| True Positives | {tp} |",
            f"| False Positives | {fp} |",
            f"| False Negatives | {fn} |",
            f"| Cost (USD) | ${cost_usd:.4f} |",
            f"| Cost per Finding | ${cost_per_finding:.4f} |",
            f"| Steps Used | {meta.get('steps_used', '-')} |",
            f"| Duration (s) | {meta.get('duration_seconds', 0):.1f} |",
            "",
        ]

        # ---- Matched findings (True Positives) ----
        matched_pairs: List[Dict[str, Any]] = scores.get("matched_pairs", [])
        if matched_pairs:
            lines += ["## Detected Vulnerabilities (True Positives)", ""]
            lines += [
                "| # | Ground Truth ID | Vuln Type | Severity | Match Score |",
                "|---|----------------|-----------|----------|-------------|",
            ]
            for i, pair in enumerate(matched_pairs, 1):
                truth = pair.get("truth", {})
                match_score = pair.get("score", 0.0)
                lines.append(
                    f"| {i} | {truth.get('id', '?')} "
                    f"| {truth.get('vuln_type', '?')} "
                    f"| {truth.get('severity', '?')} "
                    f"| {match_score:.2f} |"
                )
            lines.append("")

        # ---- Missed vulnerabilities (False Negatives) ----
        unmatched_truths: List[Dict[str, Any]] = scores.get("unmatched_truths", [])
        if unmatched_truths:
            lines += ["## Missed Vulnerabilities (False Negatives)", ""]
            lines += [
                "| Ground Truth ID | Vuln Type | Severity | Endpoint |",
                "|----------------|-----------|----------|----------|",
            ]
            for truth in unmatched_truths:
                lines.append(
                    f"| {truth.get('id', '?')} "
                    f"| {truth.get('vuln_type', '?')} "
                    f"| {truth.get('severity', '?')} "
                    f"| `{truth.get('endpoint', '?')}` |"
                )
            lines.append("")

        # ---- False positives ----
        unmatched_findings: List[Dict[str, Any]] = scores.get("unmatched_findings", [])
        if unmatched_findings:
            lines += ["## False Positives (Unmatched Agent Findings)", ""]
            for finding in unmatched_findings:
                title = finding.get("title") or finding.get("description", "Unknown")
                vuln_type = (
                    finding.get("vulnerability_type")
                    or finding.get("vuln_type")
                    or finding.get("type", "?")
                )
                lines.append(f"- **{title}** ({vuln_type})")
            lines.append("")

        # ---- Recommendations ----
        lines += ["## Recommendations", ""]
        recommendations: List[str] = []

        if recall < 0.5:
            recommendations.append(
                "**Low recall (<50%)**: The agent missed more than half the known "
                "vulnerabilities. Consider increasing `max_steps` or tuning the agent "
                "system prompt to prioritise comprehensive coverage over depth."
            )
        if precision < 0.5 and fp > 0:
            recommendations.append(
                "**Low precision (<50%)**: The agent produced many false positives. "
                "Review the `_match_finding` threshold or tighten ground truth "
                "`match_keywords` to reduce noise."
            )
        if cost_per_finding > 0.50 and tp > 0:
            recommendations.append(
                f"**High cost per finding (${cost_per_finding:.2f})**: "
                "Consider using a faster/cheaper LLM tier for reconnaissance "
                "and reserving deep-tier calls for hypothesis validation."
            )
        if fn > 0:
            missed_types = sorted({t.get("vuln_type", "?") for t in unmatched_truths})
            recommendations.append(
                f"**Missed vulnerability types**: {', '.join(missed_types)}. "
                "Add explicit objectives targeting these classes to the agent prompt."
            )
        if not recommendations:
            recommendations.append(
                "Agent performed well. Continue iterating on step budget and "
                "prompt engineering to push F1 above 0.80."
            )

        for rec in recommendations:
            lines.append(f"- {rec}")
        lines.append("")

        return "\n".join(lines)

    def generate_json(self, results: Dict[str, Any]) -> str:
        """Serialise results dict to indented JSON string.

        Args:
            results: Dict as returned by BenchmarkRunner.run().

        Returns:
            JSON string (indented, with non-serialisable values stringified).
        """
        return json.dumps(results, indent=2, default=str)

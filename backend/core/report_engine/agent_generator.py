"""Report generator for LLM-driven agent operations.

Generates standalone HTML and JSON reports from agent operation data
(dict-based, not ORM). Reuses CSS/styling patterns from the scan
report generator but adds agent-specific sections: plan timeline,
cost breakdown, quality assessment, and tool usage.
"""

import base64
import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AgentReportGenerator:
    """Generates HTML/JSON reports from agent operation data.

    Unlike the scan ReportGenerator which depends on Scan/Vulnerability
    ORM models, this operates on plain dicts — matching the in-memory
    structure of _agent_results and AgentResult.

    Usage:
        gen = AgentReportGenerator(reports_dir="data/reports")
        path, summary = gen.generate(operation_data, format="html")
    """

    def __init__(self, reports_dir: str = "data/reports"):
        self.reports_dir = Path(reports_dir)

    def generate(
        self,
        data: Dict[str, Any],
        format: str = "html",
        title: Optional[str] = None,
    ) -> Tuple[Path, str]:
        """Generate a report from operation data.

        Args:
            data: Operation result dict (from _agent_results or results.json).
            format: "html" or "json".
            title: Optional report title override.

        Returns:
            Tuple of (file_path, executive_summary_text).
        """
        op_id = data.get("operation_id", data.get("id", "unknown"))
        target = data.get("target", "unknown")
        title = title or f"Agent Assessment Report — {target}"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Build executive summary
        summary = self._build_executive_summary(data)

        # Generate content
        if format == "json":
            content = self._generate_json(data, title, summary)
            filename = f"agent_report_{timestamp}.json"
        else:
            content = self._generate_html(data, title, summary)
            filename = f"agent_report_{timestamp}.html"

        # Write to disk
        report_dir = self.reports_dir / f"agent_report_{op_id[:8]}_{timestamp}"
        report_dir.mkdir(parents=True, exist_ok=True)
        file_path = report_dir / filename
        file_path.write_text(content, encoding="utf-8")

        return file_path, summary

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _build_executive_summary(self, data: Dict[str, Any]) -> str:
        findings = data.get("findings", [])
        total = len(findings)
        sev_counts = self._severity_counts(findings)
        steps = data.get("steps_used", 0)
        max_steps = data.get("max_steps", 0)
        duration = data.get("duration_seconds", 0) or 0
        cost = (data.get("cost_report") or {}).get("total_cost_usd", 0)

        risk = (
            "Critical" if sev_counts["critical"] > 0
            else "High" if sev_counts["high"] > 0
            else "Medium" if sev_counts["medium"] > 0
            else "Low" if sev_counts["low"] > 0
            else "Informational"
        )

        return (
            f"An autonomous LLM-driven security assessment was performed against "
            f"{data.get('target', 'the target')}.\n\n"
            f"The agent completed {steps}/{max_steps} steps in "
            f"{self._fmt_duration(duration)} at a cost of ${cost:.4f}.\n\n"
            f"Total findings: {total} "
            f"(Critical: {sev_counts['critical']}, High: {sev_counts['high']}, "
            f"Medium: {sev_counts['medium']}, Low: {sev_counts['low']}, "
            f"Info: {sev_counts['info']})\n\n"
            f"Overall Risk Level: {risk}"
        )

    # ------------------------------------------------------------------
    # JSON format
    # ------------------------------------------------------------------

    def _generate_json(self, data: Dict, title: str, summary: str) -> str:
        report = {
            "title": title,
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": summary,
            "operation": {
                "operation_id": data.get("operation_id", data.get("id")),
                "target": data.get("target"),
                "objective": data.get("objective"),
                "status": data.get("status"),
                "steps_used": data.get("steps_used"),
                "max_steps": data.get("max_steps"),
                "duration_seconds": data.get("duration_seconds"),
                "stop_reason": data.get("stop_reason"),
            },
            "findings": data.get("findings", []),
            "cost_report": data.get("cost_report"),
            "tool_usage": data.get("tool_usage"),
            "plan_phases": data.get("plan_phases"),
            "quality_evaluation": data.get("quality_evaluation"),
        }
        return json.dumps(report, indent=2, default=str)

    # ------------------------------------------------------------------
    # HTML format
    # ------------------------------------------------------------------

    def _generate_html(self, data: Dict, title: str, summary: str) -> str:
        findings = data.get("findings", [])
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5),
        )
        sev_counts = self._severity_counts(findings)

        findings_html = self._render_finding_cards(sorted_findings, data)
        plan_html = self._render_plan_timeline(data.get("plan_phases"))
        cost_html = self._render_cost_breakdown(data.get("cost_report"))
        quality_html = self._render_quality_assessment(data.get("quality_evaluation"))
        tools_html = self._render_tool_usage(data.get("tool_usage"))
        screenshots_html = self._render_screenshots(data.get("artifacts_dir"))
        total_cost = (data.get("cost_report") or {}).get("total_cost_usd", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)}</title>
{self._css()}
</head>
<body>
<div class="container">

<header>
    <h1>{_esc(title)}</h1>
    <div class="meta">
        <span>Target: <strong>{_esc(data.get('target', ''))}</strong></span>
        <span>Status: <strong>{_esc(data.get('status', ''))}</strong></span>
        <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
    </div>
</header>

<section class="summary-section">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="stat-card">
            <div class="stat-value">{len(findings)}</div>
            <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card critical">
            <div class="stat-value">{sev_counts['critical']}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="stat-value">{sev_counts['high']}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card medium">
            <div class="stat-value">{sev_counts['medium']}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card low">
            <div class="stat-value">{sev_counts['low']}</div>
            <div class="stat-label">Low</div>
        </div>
    </div>
    <div class="metrics-row">
        <span>Steps: {data.get('steps_used', 0)}/{data.get('max_steps', 0)}</span>
        <span>Duration: {self._fmt_duration(data.get('duration_seconds', 0) or 0)}</span>
        <span>Cost: ${total_cost:.4f}</span>
    </div>
    <p class="summary-text">{_esc(summary)}</p>
</section>

<section>
    <h2>Findings</h2>
    {findings_html if findings_html else '<p class="empty">No findings reported.</p>'}
</section>

{plan_html}
{cost_html}
{quality_html}
{tools_html}
{screenshots_html}

<footer>
    <p>Generated by NeuroSploit LLM Agent &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</footer>

</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # HTML section renderers
    # ------------------------------------------------------------------

    def _render_finding_cards(self, findings: List[Dict], data: Dict) -> str:
        if not findings:
            return ""
        cards = []
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info")
            color = SEVERITY_COLORS.get(sev, "#6c757d")
            status = f.get("validation_status", "")
            status_badge = ""
            if status == "verified":
                status_badge = '<span class="badge verified">Verified</span>'
            elif status == "hypothesis":
                status_badge = '<span class="badge hypothesis">Hypothesis</span>'

            evidence_html = ""
            if f.get("evidence"):
                evidence_html = f'<div class="field"><h4>Evidence</h4><pre>{_esc(f["evidence"])}</pre></div>'

            repro_html = ""
            if f.get("reproduction_steps"):
                repro_html = f'<div class="field"><h4>Reproduction Steps</h4><p>{_esc(f["reproduction_steps"])}</p></div>'

            remediation_html = ""
            if f.get("remediation"):
                remediation_html = f'<div class="field remediation"><h4>Remediation</h4><p>{_esc(f["remediation"])}</p></div>'

            cards.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{color};">{sev.upper()}</span>
                    <h3>#{i} {_esc(f.get('title', 'Untitled'))}</h3>
                    {status_badge}
                </div>
                <div class="finding-meta">
                    <span><strong>Type:</strong> {_esc(f.get('vuln_type', 'N/A'))}</span>
                    <span><strong>Endpoint:</strong> {_esc(f.get('endpoint', 'N/A'))}</span>
                </div>
                <div class="field"><h4>Description</h4><p>{_esc(f.get('description', ''))}</p></div>
                {evidence_html}
                {repro_html}
                {remediation_html}
            </div>""")
        return "\n".join(cards)

    def _render_plan_timeline(self, plan_phases: Optional[List]) -> str:
        if not plan_phases:
            return ""
        items = []
        for phase in plan_phases:
            name = phase.get("name", "Unknown")
            status = phase.get("status", "pending")
            objectives = phase.get("objectives", [])
            completed = phase.get("completed_objectives", [])
            icon = "&#9679;" if status == "completed" else "&#9675;"
            obj_html = "".join(
                f"<li class='{'done' if o in completed else ''}'>{_esc(o)}</li>"
                for o in objectives
            )
            items.append(f"""
            <div class="timeline-item {status}">
                <span class="timeline-icon">{icon}</span>
                <div>
                    <strong>{_esc(name)}</strong> — <em>{status}</em>
                    <ul>{obj_html}</ul>
                </div>
            </div>""")
        return f"""
        <section>
            <h2>Plan Timeline</h2>
            <div class="timeline">{''.join(items)}</div>
        </section>"""

    def _render_cost_breakdown(self, cost: Optional[Dict]) -> str:
        if not cost:
            return ""
        tiers = cost.get("tiers", {})
        rows = []
        for tier_name, tier_data in tiers.items():
            rows.append(f"""
            <tr>
                <td>{_esc(tier_name)}</td>
                <td>{tier_data.get('calls', 0)}</td>
                <td>{tier_data.get('input_tokens', 0):,}</td>
                <td>{tier_data.get('output_tokens', 0):,}</td>
                <td>${tier_data.get('cost_usd', 0):.4f}</td>
            </tr>""")
        return f"""
        <section>
            <h2>Cost Breakdown</h2>
            <table>
                <thead><tr><th>Tier</th><th>Calls</th><th>Input Tokens</th><th>Output Tokens</th><th>Cost</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
                <tfoot><tr><td colspan="4"><strong>Total</strong></td><td><strong>${cost.get('total_cost_usd', 0):.4f}</strong></td></tr></tfoot>
            </table>
        </section>"""

    def _render_quality_assessment(self, quality: Optional[Dict]) -> str:
        if not quality:
            return ""
        dims = quality.get("dimensions", {})
        notes = quality.get("notes", [])
        dim_rows = "".join(
            f"<tr><td>{_esc(k.replace('_', ' ').title())}</td><td>{self._score_bar(v)}</td><td>{v}/100</td></tr>"
            for k, v in dims.items()
        )
        notes_html = "".join(f"<li>{_esc(n)}</li>" for n in notes) if notes else ""
        return f"""
        <section>
            <h2>Quality Assessment</h2>
            <div class="quality-overall">Overall Score: <strong>{quality.get('overall_score', 0)}/100</strong></div>
            <table>
                <thead><tr><th>Dimension</th><th>Score</th><th>Value</th></tr></thead>
                <tbody>{dim_rows}</tbody>
            </table>
            {'<ul class="quality-notes">' + notes_html + '</ul>' if notes_html else ''}
        </section>"""

    def _render_tool_usage(self, tool_usage: Optional[Dict]) -> str:
        if not tool_usage:
            return ""
        sorted_tools = sorted(tool_usage.items(), key=lambda x: -x[1])
        rows = "".join(
            f"<tr><td>{_esc(name)}</td><td>{count}</td></tr>"
            for name, count in sorted_tools
        )
        return f"""
        <section>
            <h2>Tool Usage</h2>
            <table>
                <thead><tr><th>Tool</th><th>Calls</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </section>"""

    def _render_screenshots(self, artifacts_dir: Optional[str]) -> str:
        if not artifacts_dir:
            return ""
        screenshots_dir = os.path.join(artifacts_dir, "screenshots")
        if not os.path.isdir(screenshots_dir):
            return ""
        images = []
        for fname in sorted(os.listdir(screenshots_dir)):
            if not fname.lower().endswith(".png"):
                continue
            fpath = os.path.join(screenshots_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                images.append(f"""
                <div class="screenshot">
                    <p>{_esc(fname)}</p>
                    <img src="data:image/png;base64,{b64}" alt="{_esc(fname)}" />
                </div>""")
            except Exception:
                continue
        if not images:
            return ""
        return f"""
        <section>
            <h2>Screenshots</h2>
            <div class="screenshots-grid">{''.join(images)}</div>
        </section>"""

    # ------------------------------------------------------------------
    # CSS
    # ------------------------------------------------------------------

    def _css(self) -> str:
        return """<style>
:root { --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a; --text: #e0e0e0; --muted: #888; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }
.container { max-width: 1000px; margin: 0 auto; padding: 40px 24px; }
header { margin-bottom: 32px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }
header h1 { font-size: 1.75rem; margin-bottom: 8px; }
.meta { display: flex; gap: 24px; color: var(--muted); font-size: 0.875rem; flex-wrap: wrap; }
section { margin-bottom: 40px; }
h2 { font-size: 1.35rem; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 16px; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
.stat-value { font-size: 2rem; font-weight: 700; }
.stat-label { font-size: 0.8rem; color: var(--muted); }
.stat-card.critical .stat-value { color: #dc3545; }
.stat-card.high .stat-value { color: #fd7e14; }
.stat-card.medium .stat-value { color: #ffc107; }
.stat-card.low .stat-value { color: #17a2b8; }
.metrics-row { display: flex; gap: 24px; color: var(--muted); font-size: 0.9rem; margin-bottom: 12px; }
.summary-text { white-space: pre-wrap; color: var(--muted); }
.finding-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }
.finding-header h3 { font-size: 1.1rem; }
.severity-badge { color: #fff; padding: 2px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
.badge { font-size: 0.7rem; padding: 2px 8px; border-radius: 12px; }
.badge.verified { background: rgba(40,167,69,0.2); color: #28a745; border: 1px solid rgba(40,167,69,0.3); }
.badge.hypothesis { background: rgba(255,193,7,0.15); color: #ffc107; border: 1px solid rgba(255,193,7,0.3); }
.finding-meta { display: flex; gap: 20px; font-size: 0.85rem; color: var(--muted); margin-bottom: 12px; }
.field { margin-top: 12px; }
.field h4 { font-size: 0.85rem; color: var(--muted); margin-bottom: 4px; }
.field p { font-size: 0.9rem; white-space: pre-wrap; }
.field pre { background: var(--bg); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.8rem; max-height: 300px; white-space: pre-wrap; }
.field.remediation h4 { color: #28a745; }
table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
th { background: var(--bg); font-weight: 600; }
tfoot td { border-top: 2px solid var(--border); }
.timeline { padding-left: 16px; }
.timeline-item { display: flex; gap: 12px; margin-bottom: 12px; }
.timeline-icon { font-size: 1rem; margin-top: 2px; }
.timeline-item.completed .timeline-icon { color: #28a745; }
.timeline-item ul { margin-top: 4px; padding-left: 20px; font-size: 0.85rem; color: var(--muted); }
.timeline-item li.done { text-decoration: line-through; color: #555; }
.quality-overall { font-size: 1.2rem; margin-bottom: 12px; }
.score-bar { display: inline-block; width: 100px; height: 8px; background: var(--bg); border-radius: 4px; overflow: hidden; vertical-align: middle; }
.score-fill { height: 100%; border-radius: 4px; }
.quality-notes { padding-left: 20px; color: var(--muted); font-size: 0.85rem; margin-top: 8px; }
.screenshots-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }
.screenshot { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }
.screenshot img { width: 100%; border-radius: 4px; }
.screenshot p { font-size: 0.8rem; color: var(--muted); margin-bottom: 8px; font-family: monospace; }
.empty { color: var(--muted); text-align: center; padding: 24px; }
footer { text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); }
@media print { body { background: #fff; color: #000; } .container { max-width: 100%; } }
</style>"""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
        return f"{seconds / 3600:.0f}h {(seconds % 3600) / 60:.0f}m"

    @staticmethod
    def _score_bar(value: int) -> str:
        color = "#28a745" if value >= 70 else "#ffc107" if value >= 40 else "#dc3545"
        return f'<div class="score-bar"><div class="score-fill" style="width:{value}%;background:{color};"></div></div>'


def _esc(text: Any) -> str:
    """HTML-escape a value, handling None gracefully."""
    if text is None:
        return ""
    return html.escape(str(text))

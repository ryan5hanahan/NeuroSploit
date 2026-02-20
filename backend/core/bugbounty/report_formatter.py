"""
HackerOne Report Formatter — Generate H1-ready draft reports from vulnerability findings.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class H1ReportFormatter:
    """Formats vulnerability findings into HackerOne report drafts."""

    # Map internal severity to H1 severity_rating
    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "none",
    }

    @classmethod
    def format_draft(cls, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Map a Vulnerability dict to an H1-style draft report.

        Returns a dict with fields matching HackerOne's POST /reports schema:
        title, vulnerability_information, impact, severity_rating, weakness_id
        """
        severity = cls.SEVERITY_MAP.get(
            (vuln.get("severity") or "info").lower(), "none"
        )

        # Assemble vulnerability_information from available fields
        sections = []

        desc = vuln.get("description") or ""
        if desc:
            sections.append(f"## Description\n{desc}")

        endpoint = vuln.get("affected_endpoint") or vuln.get("url") or ""
        if endpoint:
            sections.append(f"## Affected Endpoint\n`{endpoint}`")

        # PoC details
        poc_parts = []
        if vuln.get("poc_request"):
            poc_parts.append(f"**Request:**\n```\n{vuln['poc_request']}\n```")
        if vuln.get("poc_response"):
            resp_preview = vuln["poc_response"][:2000]
            poc_parts.append(f"**Response (truncated):**\n```\n{resp_preview}\n```")
        if vuln.get("poc_payload"):
            poc_parts.append(f"**Payload:** `{vuln['poc_payload']}`")
        if vuln.get("poc_code"):
            poc_parts.append(f"**PoC Code:**\n```\n{vuln['poc_code']}\n```")
        if poc_parts:
            sections.append("## Proof of Concept\n" + "\n\n".join(poc_parts))

        remediation = vuln.get("remediation") or ""
        if remediation:
            sections.append(f"## Remediation\n{remediation}")

        vulnerability_information = "\n\n".join(sections) if sections else desc

        impact = vuln.get("impact") or ""
        if not impact:
            impact = f"An attacker could exploit this {vuln.get('vulnerability_type', 'vulnerability')} to compromise the target application."

        return {
            "title": vuln.get("title") or f"{vuln.get('vulnerability_type', 'Vulnerability')} — {endpoint}",
            "vulnerability_information": vulnerability_information,
            "impact": impact,
            "severity_rating": severity,
            "weakness_id": vuln.get("cwe_id") or "",
        }

    @classmethod
    def format_preview_markdown(cls, draft: Dict[str, Any]) -> str:
        """Render a draft report as readable markdown for preview."""
        lines = [
            f"# {draft.get('title', 'Untitled')}",
            "",
            f"**Severity:** {draft.get('severity_rating', 'none')}",
        ]
        if draft.get("weakness_id"):
            lines.append(f"**Weakness:** {draft['weakness_id']}")

        lines.append("")
        lines.append(draft.get("vulnerability_information", ""))
        lines.append("")

        impact = draft.get("impact", "")
        if impact:
            lines.append("## Impact")
            lines.append(impact)

        return "\n".join(lines)

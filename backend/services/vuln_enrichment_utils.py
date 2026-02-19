"""
Vulnerability metadata backfill utility.

Uses VulnerabilityRegistry to fill missing CWE, impact, and remediation fields
on Vulnerability model instances before they are persisted.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# Lazy singleton — avoids import-time side effects
_registry = None


def _get_registry():
    global _registry
    if _registry is None:
        from backend.core.vuln_engine.registry import VulnerabilityRegistry
        _registry = VulnerabilityRegistry()
    return _registry


def backfill_vulnerability_metadata(vuln: "Vulnerability") -> None:
    """Fill missing CWE, impact, and remediation from VulnerabilityRegistry.

    Mutates the Vulnerability in-place *before* flush so the DB row is complete.
    Safe to call multiple times (idempotent — only fills blanks).
    """
    registry = _get_registry()
    vtype = vuln.vulnerability_type
    if not vtype:
        return

    if not vuln.cwe_id:
        cwe = registry.get_cwe_id(vtype)
        if cwe:
            vuln.cwe_id = cwe

    if not vuln.impact:
        impact = registry.get_impact(vtype)
        if impact:
            vuln.impact = impact

    if not vuln.remediation:
        remediation = registry.get_remediation(vtype)
        if remediation:
            vuln.remediation = remediation

    if not vuln.description:
        desc = registry.get_description(vtype)
        if desc:
            vuln.description = desc

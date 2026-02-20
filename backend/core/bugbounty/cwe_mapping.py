"""CWE-to-vuln_type reverse mapping.

Built from VulnerabilityRegistry.VULNERABILITY_INFO (100 entries).
Used by governance_bridge to derive allowed_vuln_types from a bug bounty
program's weakness list (CWE IDs).
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def build_cwe_to_vuln_types() -> Dict[str, List[str]]:
    """Build reverse mapping: CWE-ID string -> list of vuln_type keys.

    Example: "CWE-79" -> ["xss_reflected", "xss_stored", "xss_dom", ...]
    """
    from backend.core.vuln_engine.registry import VulnerabilityRegistry

    mapping: Dict[str, List[str]] = {}
    for vuln_type, info in VulnerabilityRegistry.VULNERABILITY_INFO.items():
        cwe = info.get("cwe_id", "")
        if cwe:
            mapping.setdefault(cwe, []).append(vuln_type)
    return mapping


# Lazy-loaded singleton (avoids import-time circular deps)
_cwe_to_vuln_types: Dict[str, List[str]] | None = None


def get_cwe_to_vuln_types() -> Dict[str, List[str]]:
    """Return the CWE-to-vuln_types mapping (lazy-loaded singleton)."""
    global _cwe_to_vuln_types
    if _cwe_to_vuln_types is None:
        _cwe_to_vuln_types = build_cwe_to_vuln_types()
        logger.info(f"CWE mapping built: {len(_cwe_to_vuln_types)} CWE IDs -> vuln types")
    return _cwe_to_vuln_types

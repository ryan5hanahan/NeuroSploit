"""Context-aware filtering for techniques.

Provides advanced filtering based on technology stack, WAF presence,
depth configuration, and technique tags.
"""
import logging
from typing import Any, Dict, List, Optional

from techniques.schema import Technique

logger = logging.getLogger(__name__)


def filter_by_context(
    techniques: List[Technique],
    technology_stack: Optional[List[str]] = None,
    waf_detected: bool = False,
    waf_type: Optional[str] = None,
    depth: str = "standard",
    tags: Optional[List[str]] = None,
    exclude_tags: Optional[List[str]] = None,
) -> List[Technique]:
    """Filter techniques based on full execution context.

    Args:
        techniques: List of techniques to filter
        technology_stack: Detected technologies (e.g., ["php", "mysql", "apache"])
        waf_detected: Whether a WAF was detected
        waf_type: Specific WAF type if known (e.g., "cloudflare", "mod_security")
        depth: Testing depth ("quick", "standard", "thorough")
        tags: Include only techniques with these tags
        exclude_tags: Exclude techniques with these tags
    """
    depth_order = {"quick": 0, "standard": 1, "thorough": 2}
    max_depth = depth_order.get(depth, 1)

    filtered = []
    for t in techniques:
        # Depth filter
        technique_depth = depth_order.get(t.depth, 1)
        if technique_depth > max_depth:
            continue

        # Technology filter
        if technology_stack and t.technology:
            tech_match = any(
                any(detected.lower() in req.lower() for detected in technology_stack)
                for req in t.technology
            )
            if not tech_match:
                continue

        # WAF filter - include WAF bypass only when WAF detected
        if t.waf_bypass and not waf_detected:
            continue

        # Tag inclusion filter
        if tags:
            if not any(tag in t.tags for tag in tags):
                continue

        # Tag exclusion filter
        if exclude_tags:
            if any(tag in t.tags for tag in exclude_tags):
                continue

        filtered.append(t)

    return filtered


def rank_techniques(
    techniques: List[Technique],
    priority_vuln_types: Optional[List[str]] = None,
) -> List[Technique]:
    """Rank techniques by relevance and severity."""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def score(t: Technique) -> int:
        s = severity_order.get(t.severity, 2) * 10
        if priority_vuln_types and t.vuln_type in priority_vuln_types:
            s += 50
        s += len(t.payloads)  # More payloads = more coverage
        return s

    return sorted(techniques, key=score, reverse=True)

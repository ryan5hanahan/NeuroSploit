"""Governance bridge — converts bug bounty program data into governance ScanScope.

Platform-agnostic: works with any BugBountyProvider's normalized dataclasses.
No HackerOne-specific code here.
"""

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from backend.core.bugbounty.provider import ProgramInfo, ProgramScope, ScopeAsset

logger = logging.getLogger(__name__)

# Severity ranking for max_severity enforcement
SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
    "": 5,  # No limit
}


@dataclass
class BugBountyContext:
    """Bug bounty metadata passed alongside ScanScope to the agent.

    Carries per-asset severity limits, testing instructions, and
    platform-specific info that doesn't fit in the frozen ScanScope.
    """
    platform: str = ""
    program_handle: str = ""
    program_name: str = ""
    safe_harbor: str = ""
    open_scope: bool = False
    asset_severity_limits: dict[str, str] = field(default_factory=dict)  # pattern -> max_severity
    asset_instructions: dict[str, str] = field(default_factory=dict)  # pattern -> instruction
    testing_instructions: str = ""  # Aggregated markdown for agent prompt
    program_weaknesses: list[str] = field(default_factory=list)  # CWE IDs


def _extract_domain_from_identifier(identifier: str) -> str:
    """Extract a hostname from a scope asset identifier."""
    if "://" in identifier:
        parsed = urlparse(identifier)
        return parsed.hostname or identifier
    # Strip wildcard prefix
    if identifier.startswith("*."):
        return identifier[2:]
    return identifier


def _asset_to_domain_pattern(asset: ScopeAsset) -> Optional[str]:
    """Convert a scope asset to a domain/pattern string for governance.

    Returns the pattern string or None if the asset type is not domain-like.
    """
    asset_type = asset.asset_type.upper()
    if asset_type in ("URL", "DOMAIN", "WILDCARD"):
        return _extract_domain_from_identifier(asset.identifier)
    return None


def _asset_matches_hostname(pattern: str, hostname: str) -> bool:
    """Check if a hostname matches an asset pattern (exact or wildcard subdomain)."""
    if pattern == hostname:
        return True
    if hostname.endswith(f".{pattern}"):
        return True
    return False


def build_scan_scope_from_program(
    program: ProgramInfo,
    scope: ProgramScope,
    target_url: str,
) -> tuple:
    """Build a ScanScope + BugBountyContext from bug bounty program data.

    Args:
        program: Normalized program info.
        scope: Normalized program scope (in-scope + out-of-scope).
        target_url: The primary target URL (for fallback domain scoping).

    Returns:
        (ScanScope, BugBountyContext) tuple.
    """
    from backend.core.governance import ScanScope, ScopeProfile

    # Collect allowed domains from in-scope URL/DOMAIN/WILDCARD assets
    allowed_domains: set[str] = set()
    allowed_cidrs: set[str] = set()

    for asset in scope.in_scope:
        asset_type = asset.asset_type.upper()
        if asset_type in ("URL", "DOMAIN", "WILDCARD"):
            domain = _extract_domain_from_identifier(asset.identifier)
            if domain:
                allowed_domains.add(domain)
        elif asset_type == "CIDR":
            allowed_cidrs.add(asset.identifier)

    # Fallback: if no domains extracted, use the target_url domain
    if not allowed_domains and not allowed_cidrs:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        if parsed.hostname:
            allowed_domains.add(parsed.hostname)

    # Derive allowed_vuln_types from program weaknesses via CWE mapping
    allowed_vuln_types: set[str] = set()
    if program.program_weaknesses:
        from backend.core.bugbounty.cwe_mapping import get_cwe_to_vuln_types
        cwe_map = get_cwe_to_vuln_types()
        for cwe_id in program.program_weaknesses:
            vuln_types = cwe_map.get(cwe_id, [])
            allowed_vuln_types.update(vuln_types)
    # Empty set = all types allowed (no restriction)

    # Build per-asset severity limits and instructions
    asset_severity_limits: dict[str, str] = {}
    asset_instructions: dict[str, str] = {}

    for asset in scope.in_scope:
        domain = _asset_to_domain_pattern(asset)
        if not domain:
            domain = asset.identifier
        if asset.max_severity:
            asset_severity_limits[domain] = asset.max_severity
        if asset.instruction:
            asset_instructions[domain] = asset.instruction

    # Build testing instructions markdown for the agent prompt
    testing_instructions = _build_testing_instructions(
        program, scope, asset_severity_limits, asset_instructions,
    )

    # Build BugBountyContext
    context = BugBountyContext(
        platform=program.platform,
        program_handle=program.handle,
        program_name=program.name,
        safe_harbor=program.safe_harbor,
        open_scope=program.open_scope,
        asset_severity_limits=asset_severity_limits,
        asset_instructions=asset_instructions,
        testing_instructions=testing_instructions,
        program_weaknesses=program.program_weaknesses,
    )

    # Build ScanScope
    scan_scope = ScanScope(
        profile=ScopeProfile.BUG_BOUNTY,
        allowed_domains=frozenset(allowed_domains),
        allowed_vuln_types=frozenset(allowed_vuln_types),
        allowed_phases=frozenset(),  # all phases allowed
        skip_subdomain_enum=False,
        skip_port_scan=False,
        max_recon_depth="full",
        nuclei_template_tags=None,
        include_subdomains=True,
        allowed_cidrs=frozenset(allowed_cidrs),
        bugbounty_context=context,
    )

    logger.info(
        f"Built bug bounty scope for {program.handle}: "
        f"{len(allowed_domains)} domains, {len(allowed_cidrs)} CIDRs, "
        f"{len(allowed_vuln_types) or 'all'} vuln types, "
        f"{len(asset_severity_limits)} severity limits"
    )

    return scan_scope, context


def _build_testing_instructions(
    program: ProgramInfo,
    scope: ProgramScope,
    severity_limits: dict[str, str],
    instructions: dict[str, str],
) -> str:
    """Build markdown testing instructions for the agent system prompt."""
    lines = [
        f"**Program**: {program.name} ({program.platform})",
    ]

    if program.safe_harbor:
        harbor_display = {
            "full": "Full Safe Harbor",
            "partial": "Partial Safe Harbor",
            "none": "No Safe Harbor",
        }.get(program.safe_harbor, program.safe_harbor)
        lines.append(f"**Safe Harbor**: {harbor_display}")

    if program.open_scope:
        lines.append("**Open Scope**: Yes — assets not listed may still be eligible")

    # Out-of-scope warnings
    if scope.out_of_scope:
        lines.append("")
        lines.append("**Out-of-Scope Assets** (DO NOT TEST):")
        for asset in scope.out_of_scope[:20]:
            lines.append(f"- `{asset.identifier}` ({asset.asset_type})")

    # Per-asset instructions
    if instructions:
        lines.append("")
        lines.append("**Per-Asset Testing Instructions**:")
        for pattern, instr in instructions.items():
            lines.append(f"- `{pattern}`: {instr}")

    # Per-asset severity limits
    if severity_limits:
        lines.append("")
        lines.append("**Per-Asset Maximum Severity** (findings above this will be capped):")
        for pattern, max_sev in severity_limits.items():
            lines.append(f"- `{pattern}`: max **{max_sev}**")

    # Program weaknesses
    if program.program_weaknesses:
        lines.append("")
        lines.append(f"**Program Weaknesses** (focus areas): {', '.join(program.program_weaknesses)}")

    return "\n".join(lines)


def check_severity_against_limit(
    severity: str,
    target_url: str,
    asset_severity_limits: dict[str, str],
) -> tuple[bool, str]:
    """Check if a finding severity is within the per-asset max_severity limit.

    Args:
        severity: The finding's severity (e.g. "critical").
        target_url: The finding's target URL/endpoint.
        asset_severity_limits: Pattern -> max_severity mapping.

    Returns:
        (within_limit, effective_severity):
        - within_limit=True, effective_severity=severity if OK
        - within_limit=False, effective_severity=capped severity if exceeded
    """
    if not asset_severity_limits:
        return True, severity

    # Extract hostname from target URL
    try:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        hostname = parsed.hostname or target_url
    except Exception:
        hostname = target_url

    # Find matching asset limit
    max_sev = ""
    for pattern, limit in asset_severity_limits.items():
        if _asset_matches_hostname(pattern, hostname):
            max_sev = limit
            break

    if not max_sev:
        return True, severity  # No limit for this asset

    sev_rank = SEVERITY_RANK.get(severity.lower(), 2)
    max_rank = SEVERITY_RANK.get(max_sev.lower(), 5)

    if max_rank >= 5:
        return True, severity  # No effective limit

    if sev_rank <= max_rank:
        return True, severity  # Within limit

    # Exceeded: cap to the max severity
    return False, max_sev

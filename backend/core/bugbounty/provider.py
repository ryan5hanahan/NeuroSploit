"""Bug bounty platform provider abstraction.

Normalized dataclasses and Protocol interface for platform-agnostic
bug bounty program data. New platforms (Bugcrowd, Intigriti, Synack)
implement BugBountyProvider — no governance code changes needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

import aiohttp


@dataclass
class ProgramInfo:
    """Normalized program metadata from any bug bounty platform."""
    handle: str
    name: str
    platform: str  # "hackerone", "bugcrowd", etc.
    url: str = ""
    offers_bounties: bool = False
    submission_state: str = ""
    safe_harbor: str = ""  # "full", "partial", "none"
    open_scope: bool = False
    policy: str = ""
    program_weaknesses: list[str] = field(default_factory=list)  # CWE IDs


@dataclass
class ScopeAsset:
    """Normalized scope asset from any bug bounty platform."""
    identifier: str  # Domain, URL, IP, etc.
    asset_type: str  # "URL", "DOMAIN", "WILDCARD", "CIDR", etc.
    in_scope: bool = True
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = True
    max_severity: str = ""  # "critical", "high", "medium", "low", "none"
    instruction: str = ""
    confidentiality_requirement: str = ""
    integrity_requirement: str = ""
    availability_requirement: str = ""


@dataclass
class ProgramScope:
    """Normalized program scope — in-scope and out-of-scope assets."""
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[ScopeAsset] = field(default_factory=list)


@dataclass
class ExistingReport:
    """Normalized existing report for duplicate detection."""
    id: str
    title: str
    state: str = ""
    severity_rating: str = ""
    weakness: str = ""
    created_at: str = ""
    description_preview: str = ""


@runtime_checkable
class BugBountyProvider(Protocol):
    """Protocol for bug bounty platform providers.

    Implement this to add a new platform. Register via PlatformRegistry.
    """
    platform_name: str

    @property
    def enabled(self) -> bool:
        """Whether the provider has valid credentials configured."""
        ...

    async def test_connection(self, session: aiohttp.ClientSession) -> dict:
        """Verify credentials with a lightweight API call."""
        ...

    async def list_programs(self, session: aiohttp.ClientSession) -> list[ProgramInfo]:
        """List programs the authenticated user has access to."""
        ...

    async def get_program(self, handle: str, session: aiohttp.ClientSession) -> Optional[ProgramInfo]:
        """Get detailed program info by handle."""
        ...

    async def get_scope(self, handle: str, session: aiohttp.ClientSession) -> ProgramScope:
        """Get structured program scope (in-scope + out-of-scope assets)."""
        ...

    async def get_reports(self, handle: str, session: aiohttp.ClientSession, limit: int = 50) -> list[ExistingReport]:
        """Get existing reports for duplicate detection."""
        ...

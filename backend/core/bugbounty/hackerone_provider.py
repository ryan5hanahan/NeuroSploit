"""HackerOne provider — adapts HackerOneClient to the BugBountyProvider protocol."""

import logging
import os
from typing import Optional

import aiohttp

from backend.core.bugbounty.hackerone_client import HackerOneClient
from backend.core.bugbounty.provider import (
    BugBountyProvider,
    ExistingReport,
    ProgramInfo,
    ProgramScope,
    ScopeAsset,
)

logger = logging.getLogger(__name__)


class HackerOneProvider:
    """BugBountyProvider implementation for HackerOne.

    Wraps HackerOneClient (raw API calls) and normalizes data into
    platform-agnostic dataclasses.
    """

    platform_name = "hackerone"

    def __init__(self):
        self._client = self._build_client()

    def _build_client(self) -> HackerOneClient:
        """Build a HackerOneClient from settings + env vars."""
        try:
            from backend.api.v1.settings import _settings
            token = _settings.get("hackerone_api_token") or os.getenv("HACKERONE_API_TOKEN", "")
            username = _settings.get("hackerone_username") or os.getenv("HACKERONE_USERNAME", "")
        except Exception:
            token = os.getenv("HACKERONE_API_TOKEN", "")
            username = os.getenv("HACKERONE_USERNAME", "")
        return HackerOneClient(api_token=token, username=username)

    @property
    def enabled(self) -> bool:
        # Rebuild client to pick up credential changes
        self._client = self._build_client()
        return self._client.enabled

    async def test_connection(self, session: aiohttp.ClientSession) -> dict:
        self._client = self._build_client()
        return await self._client.test_connection(session)

    async def list_programs(self, session: aiohttp.ClientSession) -> list[ProgramInfo]:
        self._client = self._build_client()
        raw_programs = await self._client.list_programs(session)
        return [
            ProgramInfo(
                handle=p.get("handle", ""),
                name=p.get("name", ""),
                platform="hackerone",
                url=p.get("url", ""),
                offers_bounties=p.get("offers_bounties", False),
                submission_state=p.get("submission_state", ""),
            )
            for p in raw_programs
        ]

    async def get_program(self, handle: str, session: aiohttp.ClientSession) -> Optional[ProgramInfo]:
        self._client = self._build_client()
        raw = await self._client.get_program(handle, session)
        if not raw:
            return None
        return ProgramInfo(
            handle=handle,
            name=raw.get("name", ""),
            platform="hackerone",
            url=raw.get("url", ""),
            offers_bounties=raw.get("offers_bounties", False),
            submission_state=raw.get("submission_state", ""),
            safe_harbor=raw.get("safe_harbor", ""),
            open_scope=raw.get("open_scope", False),
            policy=raw.get("policy", ""),
            program_weaknesses=raw.get("program_weaknesses", []),
        )

    async def get_scope(self, handle: str, session: aiohttp.ClientSession) -> ProgramScope:
        self._client = self._build_client()
        raw = await self._client.get_scope(handle, session)
        return ProgramScope(
            in_scope=[
                ScopeAsset(
                    identifier=a.get("asset_identifier", ""),
                    asset_type=a.get("asset_type", ""),
                    in_scope=True,
                    eligible_for_bounty=a.get("eligible_for_bounty", False),
                    eligible_for_submission=a.get("eligible_for_submission", True),
                    max_severity=a.get("max_severity", ""),
                    instruction=a.get("instruction", ""),
                    confidentiality_requirement=a.get("confidentiality_requirement", ""),
                    integrity_requirement=a.get("integrity_requirement", ""),
                    availability_requirement=a.get("availability_requirement", ""),
                )
                for a in raw.get("in_scope", [])
            ],
            out_of_scope=[
                ScopeAsset(
                    identifier=a.get("asset_identifier", ""),
                    asset_type=a.get("asset_type", ""),
                    in_scope=False,
                    eligible_for_bounty=False,
                    eligible_for_submission=False,
                    max_severity=a.get("max_severity", ""),
                    instruction=a.get("instruction", ""),
                )
                for a in raw.get("out_of_scope", [])
            ],
        )

    async def get_reports(
        self, handle: str, session: aiohttp.ClientSession, limit: int = 50
    ) -> list[ExistingReport]:
        self._client = self._build_client()
        raw_reports = await self._client.get_reports(handle, session, limit=limit)
        return [
            ExistingReport(
                id=r.get("id", ""),
                title=r.get("title", ""),
                state=r.get("state", ""),
                severity_rating=r.get("severity_rating", ""),
                weakness=r.get("weakness", ""),
                created_at=r.get("created_at", ""),
                description_preview=r.get("vulnerability_information", "")[:500],
            )
            for r in raw_reports
        ]

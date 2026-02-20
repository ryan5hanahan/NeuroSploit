"""
HackerOne API Client — Read-only program info, scope, existing reports.

No auto-submission. This is for scope awareness and duplicate detection only.
"""

import base64
import logging
import os
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class HackerOneClient:
    """Read-only HackerOne API v1 client."""

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(
        self,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
    ):
        self.api_token = api_token or os.getenv("HACKERONE_API_TOKEN", "")
        self.username = username or os.getenv("HACKERONE_USERNAME", "")
        self._auth_header = ""
        if self.api_token and self.username:
            creds = base64.b64encode(
                f"{self.username}:{self.api_token}".encode()
            ).decode()
            self._auth_header = f"Basic {creds}"

    @property
    def enabled(self) -> bool:
        return bool(self.api_token and self.username)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": self._auth_header,
            "Accept": "application/json",
        }

    async def _get(
        self, path: str, session: aiohttp.ClientSession, params: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Make an authenticated GET request to HackerOne API."""
        try:
            async with session.get(
                f"{self.BASE_URL}{path}",
                headers=self._headers(),
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                logger.warning(f"HackerOne API {resp.status} for {path}")
                return None
        except Exception as e:
            logger.warning(f"HackerOne API error: {e}")
            return None

    async def test_connection(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Lightweight connectivity check — fetches one program to verify credentials."""
        if not self.enabled:
            return {"success": False, "error": "HackerOne credentials not configured"}
        try:
            data = await self._get(
                "/hackers/programs",
                session,
                params={"page[size]": 1},
            )
            if data is not None:
                return {"success": True, "message": "HackerOne connection verified"}
            return {"success": False, "error": "Authentication failed or API unreachable"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_programs(self, session: aiohttp.ClientSession) -> List[Dict]:
        """List programs the authenticated user has access to."""
        data = await self._get(
            "/hackers/programs",
            session,
            params={"page[size]": 100},
        )
        if not data:
            return []

        programs = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            programs.append({
                "handle": attrs.get("handle", ""),
                "name": attrs.get("name", ""),
                "offers_bounties": attrs.get("offers_bounties", False),
                "submission_state": attrs.get("submission_state", ""),
                "url": attrs.get("url", ""),
            })
        return programs

    async def get_program(self, handle: str, session: aiohttp.ClientSession) -> Optional[Dict]:
        """Get program info by handle (e.g., 'security')."""
        data = await self._get(f"/hackers/programs/{handle}", session)
        if not data:
            return None

        attrs = data.get("data", {}).get("attributes", {})
        return {
            "handle": handle,
            "name": attrs.get("name"),
            "url": attrs.get("url"),
            "policy": attrs.get("policy"),
            "submission_state": attrs.get("submission_state"),
            "started_accepting_at": attrs.get("started_accepting_at"),
            "offers_bounties": attrs.get("offers_bounties"),
        }

    async def get_scope(self, handle: str, session: aiohttp.ClientSession) -> Dict[str, List]:
        """Get program scope (in-scope and out-of-scope assets)."""
        data = await self._get(
            f"/hackers/programs/{handle}/structured_scopes",
            session,
            params={"page[size]": 100},
        )
        if not data:
            return {"in_scope": [], "out_of_scope": []}

        in_scope = []
        out_of_scope = []

        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            asset = {
                "asset_identifier": attrs.get("asset_identifier", ""),
                "asset_type": attrs.get("asset_type", ""),
                "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                "eligible_for_submission": attrs.get("eligible_for_submission", True),
                "instruction": attrs.get("instruction", ""),
                "max_severity": attrs.get("max_severity", ""),
            }

            if attrs.get("eligible_for_submission", True):
                in_scope.append(asset)
            else:
                out_of_scope.append(asset)

        logger.info(f"HackerOne scope for {handle}: {len(in_scope)} in, {len(out_of_scope)} out")
        return {"in_scope": in_scope, "out_of_scope": out_of_scope}

    async def get_reports(
        self, handle: str, session: aiohttp.ClientSession, limit: int = 50
    ) -> List[Dict]:
        """Get existing reports for duplicate detection."""
        data = await self._get(
            "/hackers/me/reports",
            session,
            params={
                "filter[program][]": handle,
                "page[size]": min(limit, 100),
            },
        )
        if not data:
            return []

        reports = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            reports.append({
                "id": item.get("id"),
                "title": attrs.get("title", ""),
                "state": attrs.get("state", ""),
                "substate": attrs.get("substate", ""),
                "severity_rating": attrs.get("severity_rating"),
                "weakness": attrs.get("weakness", {}).get("name", ""),
                "created_at": attrs.get("created_at"),
                "vulnerability_information": (attrs.get("vulnerability_information", "") or "")[:500],
            })

        return reports

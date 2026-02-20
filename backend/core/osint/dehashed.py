"""
Dehashed OSINT Client — Breach data, exposed credentials.
"""

import base64
import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class DehashedClient(OSINTClient):
    SERVICE_NAME = "dehashed"
    RATE_LIMIT_PER_SECOND = 1.0
    BASE_URL = "https://api.dehashed.com"

    def __init__(self, email: str, api_key: str):
        super().__init__(api_key=api_key)
        self.email = email
        self._auth_header = base64.b64encode(
            f"{email}:{api_key}".encode()
        ).decode()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.email)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Basic {self._auth_header}",
            "Accept": "application/json",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search Dehashed for breach data related to the domain."""
        cache_key = f"dehashed:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "dehashed"}

        data = await self._fetch_json(
            f"{self.BASE_URL}/search",
            session,
            headers=self._headers(),
            params={"query": f"domain:{domain}", "size": 100},
        )
        if not data:
            result["error"] = "No results"
            return result

        entries = data.get("entries", []) or []
        breaches = []
        credential_count = 0

        for entry in entries[:100]:
            breach_entry = {
                "email": entry.get("email", ""),
                "database_name": entry.get("database_name", ""),
                "has_password": bool(entry.get("password") or entry.get("hashed_password")),
            }
            breaches.append(breach_entry)
            if breach_entry["has_password"]:
                credential_count += 1

        result["breaches"] = breaches
        result["total_entries"] = data.get("total", len(entries))
        result["credential_count"] = credential_count

        self._cache_set(cache_key, result)
        logger.info(
            f"Dehashed search for {domain}: {len(breaches)} breach entries, "
            f"{credential_count} with credentials"
        )
        return result

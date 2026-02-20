"""
PublicWWW OSINT Client — Sites using specific code/libraries.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class PublicWWWClient(OSINTClient):
    SERVICE_NAME = "publicwww"
    RATE_LIMIT_PER_SECOND = 0.5
    BASE_URL = "https://publicwww.com/websites"

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search PublicWWW for sites referencing the domain (linked code, scripts)."""
        cache_key = f"publicwww:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "publicwww"}

        # PublicWWW API returns JSON with key parameter
        data = await self._fetch_json(
            f"{self.BASE_URL}/{domain}/",
            session,
            params={"key": self.api_key, "export": "json"},
        )

        sites = []
        if data and isinstance(data, list):
            for entry in data[:50]:
                if isinstance(entry, dict):
                    sites.append({
                        "url": entry.get("url", entry.get("site", "")),
                        "rank": entry.get("rank", 0),
                    })
                elif isinstance(entry, str):
                    sites.append({"url": entry, "rank": 0})

        result["referencing_sites"] = sites
        result["total_sites"] = len(sites)

        self._cache_set(cache_key, result)
        logger.info(f"PublicWWW search for {domain}: {len(sites)} referencing sites")
        return result

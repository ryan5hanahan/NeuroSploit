"""Vulners API Client — vulnerability intelligence and exploit search.

Follows the OSINTClient pattern with rate limiting, TTL cache, and standard interface.
"""
import logging
from typing import Any, Dict, List, Optional
import aiohttp
from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)

class VulnersClient(OSINTClient):
    """Vulners.com API client for vulnerability intelligence."""

    SERVICE_NAME = "vulners"
    RATE_LIMIT_PER_SECOND = 2.0
    CACHE_TTL_SECONDS = 3600

    BASE_URL = "https://vulners.com/api/v3"

    def __init__(self, api_key: str):
        super().__init__(api_key)

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Enrich target with vulnerability intelligence from Vulners."""
        if not self.enabled:
            return {"source": self.SERVICE_NAME, "enabled": False}

        cache_key = f"vulners:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = {
            "source": self.SERVICE_NAME,
            "exploits": [],
            "vulns": [],
            "software": [],
        }

        # Search for vulnerabilities related to the domain/software
        exploits = await self.search_exploits(domain, session)
        result["exploits"] = exploits
        result["vulns"] = [
            {
                "id": e.get("id", ""),
                "title": e.get("title", ""),
                "cvss_score": e.get("cvss", {}).get("score", 0),
                "type": e.get("type", ""),
            }
            for e in exploits[:20]
        ]

        self._cache_set(cache_key, result)
        return result

    async def search_exploits(
        self, query: str, session: aiohttp.ClientSession, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Search for exploits matching a query."""
        cache_key = f"vulners:exploits:{query}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        data = await self._fetch_json(
            f"{self.BASE_URL}/search/lucene/",
            session,
            headers={"Content-Type": "application/json"},
            params={
                "query": query,
                "apiKey": self.api_key,
                "size": limit,
                "fields": ["id", "title", "description", "type", "cvss", "href"],
            },
        )

        if not data or data.get("result") != "OK":
            return []

        exploits = []
        for item in data.get("data", {}).get("search", []):
            source = item.get("_source", {})
            exploits.append({
                "id": source.get("id", ""),
                "title": source.get("title", ""),
                "description": (source.get("description", "") or "")[:500],
                "type": source.get("type", ""),
                "cvss": source.get("cvss", {}),
                "href": source.get("href", ""),
            })

        self._cache_set(cache_key, exploits)
        return exploits

    async def search_by_cve(
        self, cve_id: str, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Search for exploits by CVE ID."""
        return await self.search_exploits(cve_id, session)

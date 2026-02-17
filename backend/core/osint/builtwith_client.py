"""
BuiltWith OSINT Client — Technology profiling.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class BuiltWithClient(OSINTClient):
    SERVICE_NAME = "builtwith"
    RATE_LIMIT_PER_SECOND = 0.5
    BASE_URL = "https://api.builtwith.com"

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Get technology profile for a domain."""
        cache_key = f"bw:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "builtwith"}

        # Free tier uses v21
        data = await self._fetch_json(
            f"{self.BASE_URL}/free1/api.json",
            session,
            params={"KEY": self.api_key, "LOOKUP": domain},
        )
        if not data:
            # Try v21 endpoint
            data = await self._fetch_json(
                f"{self.BASE_URL}/v21/api.json",
                session,
                params={"KEY": self.api_key, "LOOKUP": domain},
            )

        if not data:
            result["error"] = "No data available"
            return result

        # Parse technology groups
        technologies = []
        for group in data.get("groups", data.get("Results", [{}])):
            # Handle both free and paid API formats
            if isinstance(group, dict):
                paths = group.get("Result", {}).get("Paths", [])
                if not paths:
                    paths = [group]
                for path in paths:
                    for tech in path.get("Technologies", []):
                        technologies.append({
                            "name": tech.get("Name", ""),
                            "tag": tech.get("Tag", ""),
                            "categories": [
                                cat.get("Name", "")
                                for cat in tech.get("Categories", [])
                            ],
                        })

        result["technologies"] = technologies
        result["tech_count"] = len(technologies)

        self._cache_set(cache_key, result)
        logger.info(f"BuiltWith enrichment for {domain}: {len(technologies)} technologies")
        return result

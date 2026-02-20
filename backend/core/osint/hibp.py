"""
Have I Been Pwned OSINT Client — Breach history, paste appearances.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class HIBPClient(OSINTClient):
    SERVICE_NAME = "hibp"
    RATE_LIMIT_PER_SECOND = 0.1  # HIBP rate limit: 1 req/10s on free tier
    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def _headers(self) -> Dict[str, str]:
        return {
            "hibp-api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "sploitai-osint",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search HIBP for breaches affecting the domain."""
        cache_key = f"hibp:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "hibp"}

        # Search breaches by domain
        data = await self._fetch_json(
            f"{self.BASE_URL}/breaches",
            session,
            headers=self._headers(),
            params={"domain": domain},
        )

        breaches = []
        if data and isinstance(data, list):
            for breach in data:
                breaches.append({
                    "name": breach.get("Name", ""),
                    "title": breach.get("Title", ""),
                    "breach_date": breach.get("BreachDate", ""),
                    "pwn_count": breach.get("PwnCount", 0),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified", False),
                    "is_sensitive": breach.get("IsSensitive", False),
                })

        result["breaches"] = breaches
        result["total_breaches"] = len(breaches)
        result["total_pwned_accounts"] = sum(b.get("pwn_count", 0) for b in breaches)

        self._cache_set(cache_key, result)
        logger.info(
            f"HIBP search for {domain}: {len(breaches)} breaches, "
            f"{result['total_pwned_accounts']} total accounts"
        )
        return result

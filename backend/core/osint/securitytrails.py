"""
SecurityTrails OSINT Client — Subdomains, DNS history, associated domains.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class SecurityTrailsClient(OSINTClient):
    SERVICE_NAME = "securitytrails"
    RATE_LIMIT_PER_SECOND = 2.0
    BASE_URL = "https://api.securitytrails.com/v1"

    def _headers(self) -> Dict[str, str]:
        return {
            "APIKEY": self.api_key,
            "Accept": "application/json",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Get subdomains, DNS history, and associated domains."""
        cache_key = f"securitytrails:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "securitytrails"}

        # Subdomains
        sub_data = await self._fetch_json(
            f"{self.BASE_URL}/domain/{domain}/subdomains",
            session,
            headers=self._headers(),
        )
        if sub_data:
            subs = sub_data.get("subdomains", [])
            result["subdomains"] = [f"{s}.{domain}" for s in subs[:100]]

        # DNS history (A records)
        dns_data = await self._fetch_json(
            f"{self.BASE_URL}/history/{domain}/dns/a",
            session,
            headers=self._headers(),
        )
        if dns_data:
            records = dns_data.get("records", [])
            result["dns_history"] = [
                {
                    "ip": r.get("values", [{}])[0].get("ip", "") if r.get("values") else "",
                    "first_seen": r.get("first_seen"),
                    "last_seen": r.get("last_seen"),
                    "type": r.get("type", "a"),
                }
                for r in records[:50]
            ]

        # Associated domains
        assoc_data = await self._fetch_json(
            f"{self.BASE_URL}/domain/{domain}/associated",
            session,
            headers=self._headers(),
        )
        if assoc_data:
            result["associated_domains"] = [
                r.get("hostname", "") for r in assoc_data.get("records", [])[:50]
            ]

        self._cache_set(cache_key, result)
        logger.info(
            f"SecurityTrails enrichment for {domain}: "
            f"{len(result.get('subdomains', []))} subdomains, "
            f"{len(result.get('dns_history', []))} DNS records"
        )
        return result

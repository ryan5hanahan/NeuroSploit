"""
VirusTotal OSINT Client — URL/domain scan, reputation.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class VirusTotalClient(OSINTClient):
    SERVICE_NAME = "virustotal"
    RATE_LIMIT_PER_SECOND = 0.25  # Free tier: 4 req/min
    BASE_URL = "https://www.virustotal.com/api/v3"

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Get VirusTotal domain report."""
        cache_key = f"vt:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "virustotal"}

        data = await self._fetch_json(
            f"{self.BASE_URL}/domains/{domain}",
            session,
            headers=self._headers(),
        )
        if not data:
            result["error"] = "No data available"
            return result

        attrs = data.get("data", {}).get("attributes", {})

        # Reputation and analysis stats
        result["reputation"] = attrs.get("reputation", 0)
        result["last_analysis_stats"] = attrs.get("last_analysis_stats", {})
        result["categories"] = attrs.get("categories", {})

        # DNS records
        result["last_dns_records"] = [
            {"type": r.get("type"), "value": r.get("value")}
            for r in attrs.get("last_dns_records", [])[:20]
        ]

        # WHOIS
        result["whois"] = (attrs.get("whois", "") or "")[:500]

        # Subdomains (from relationships)
        subdomains = await self._get_subdomains(domain, session)
        if subdomains:
            result["subdomains"] = subdomains

        self._cache_set(cache_key, result)
        malicious = result.get("last_analysis_stats", {}).get("malicious", 0)
        logger.info(f"VirusTotal enrichment for {domain}: reputation={result['reputation']}, malicious={malicious}")
        return result

    async def _get_subdomains(self, domain: str, session: aiohttp.ClientSession) -> list:
        """Get subdomains from VirusTotal."""
        data = await self._fetch_json(
            f"{self.BASE_URL}/domains/{domain}/subdomains",
            session,
            headers=self._headers(),
            params={"limit": 40},
        )
        if not data:
            return []
        return [
            item.get("id", "")
            for item in data.get("data", [])
            if item.get("id")
        ]

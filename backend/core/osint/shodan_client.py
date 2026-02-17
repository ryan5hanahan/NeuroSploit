"""
Shodan OSINT Client — Host info, open ports, services, known vulns.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class ShodanClient(OSINTClient):
    SERVICE_NAME = "shodan"
    RATE_LIMIT_PER_SECOND = 1.0  # Free tier: 1 req/s
    BASE_URL = "https://api.shodan.io"

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Get Shodan host info for a domain."""
        cache_key = f"shodan:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "shodan"}

        # Resolve domain to IP first
        dns_data = await self._fetch_json(
            f"{self.BASE_URL}/dns/resolve",
            session,
            params={"hostnames": domain, "key": self.api_key},
        )
        if not dns_data or domain not in dns_data:
            result["error"] = "Could not resolve domain"
            return result

        ip = dns_data[domain]
        result["ip"] = ip

        # Get host info
        host_data = await self._fetch_json(
            f"{self.BASE_URL}/shodan/host/{ip}",
            session,
            params={"key": self.api_key},
        )
        if not host_data:
            result["error"] = "No host data available"
            self._cache_set(cache_key, result)
            return result

        result["ports"] = host_data.get("ports", [])
        result["hostnames"] = host_data.get("hostnames", [])
        result["os"] = host_data.get("os")
        result["org"] = host_data.get("org")
        result["isp"] = host_data.get("isp")
        result["vulns"] = host_data.get("vulns", [])

        # Extract services
        services = []
        for svc in host_data.get("data", []):
            services.append({
                "port": svc.get("port"),
                "transport": svc.get("transport"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "banner": (svc.get("data", "") or "")[:200],
            })
        result["services"] = services

        self._cache_set(cache_key, result)
        logger.info(f"Shodan enrichment for {domain}: {len(result['ports'])} ports, {len(result['vulns'])} vulns")
        return result

    async def search_exploits(self, query: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search Shodan exploit database."""
        data = await self._fetch_json(
            f"{self.BASE_URL}/api-info",
            session,
            params={"key": self.api_key},
        )
        # Exploit search requires paid tier; return API info on free tier
        exploit_data = await self._fetch_json(
            "https://exploits.shodan.io/api/search",
            session,
            params={"query": query, "key": self.api_key},
        )
        if exploit_data:
            return {
                "source": "shodan_exploits",
                "total": exploit_data.get("total", 0),
                "matches": [
                    {
                        "description": m.get("description", "")[:200],
                        "source": m.get("source"),
                        "id": m.get("_id"),
                    }
                    for m in exploit_data.get("matches", [])[:10]
                ],
            }
        return {"source": "shodan_exploits", "total": 0, "matches": []}

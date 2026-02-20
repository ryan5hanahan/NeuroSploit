"""
ZoomEye OSINT Client — Open ports, banners, OS fingerprints.
"""

import logging
from typing import Any, Dict, Optional

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class ZoomEyeClient(OSINTClient):
    SERVICE_NAME = "zoomeye"
    RATE_LIMIT_PER_SECOND = 1.0
    BASE_URL = "https://api.zoomeye.hk"

    def _headers(self) -> Dict[str, str]:
        return {
            "API-KEY": self.api_key,
            "Accept": "application/json",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search ZoomEye for host data."""
        cache_key = f"zoomeye:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "zoomeye"}

        data = await self._fetch_json(
            f"{self.BASE_URL}/host/search",
            session,
            headers=self._headers(),
            params={"query": f"hostname:{domain}", "page": 1},
        )
        if not data or not data.get("matches"):
            result["error"] = "No results"
            return result

        ports = set()
        banners = []
        os_fingerprints = set()

        for match in data.get("matches", []):
            portinfo = match.get("portinfo", {})
            port = portinfo.get("port")
            if port:
                ports.add(port)
            banner_text = portinfo.get("banner", "")
            if banner_text:
                banners.append({
                    "port": port,
                    "service": portinfo.get("service", ""),
                    "product": portinfo.get("product", ""),
                    "version": portinfo.get("version", ""),
                    "banner": banner_text[:200],
                })
            os_info = match.get("geoinfo", {}).get("os", "")
            if os_info:
                os_fingerprints.add(os_info)

        result["ports"] = sorted(ports)
        result["banners"] = banners[:30]
        result["os_fingerprints"] = sorted(os_fingerprints)

        self._cache_set(cache_key, result)
        logger.info(
            f"ZoomEye enrichment for {domain}: {len(ports)} ports, "
            f"{len(banners)} banners, {len(os_fingerprints)} OS fingerprints"
        )
        return result

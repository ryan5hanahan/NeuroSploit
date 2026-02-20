"""
FOFA OSINT Client — Open ports, services, technologies.
"""

import base64
import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class FOFAClient(OSINTClient):
    SERVICE_NAME = "fofa"
    RATE_LIMIT_PER_SECOND = 1.0
    BASE_URL = "https://fofa.info/api/v1"

    def __init__(self, email: str, api_key: str):
        super().__init__(api_key=api_key)
        self.email = email

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.email)

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search FOFA for host information."""
        cache_key = f"fofa:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "fofa"}

        query = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        data = await self._fetch_json(
            f"{self.BASE_URL}/search/all",
            session,
            params={
                "email": self.email,
                "key": self.api_key,
                "qbase64": query,
                "size": 100,
                "fields": "ip,port,protocol,title,server,banner",
            },
        )
        if not data or not data.get("results"):
            result["error"] = "No results"
            return result

        ports = set()
        services = []
        technologies = []

        for row in data.get("results", []):
            if len(row) >= 6:
                ip, port, protocol, title, server, banner = row[:6]
                if port:
                    ports.add(int(port) if str(port).isdigit() else port)
                services.append({
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "title": (title or "")[:200],
                    "server": server or "",
                })
                if server and server not in technologies:
                    technologies.append(server)

        result["ports"] = sorted(p for p in ports if isinstance(p, int))
        result["services"] = services[:50]
        result["technologies"] = technologies[:20]

        self._cache_set(cache_key, result)
        logger.info(f"FOFA enrichment for {domain}: {len(ports)} ports, {len(services)} services")
        return result

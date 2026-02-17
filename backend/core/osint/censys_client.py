"""
Censys OSINT Client — Hosts, certificates, search.
"""

import base64
import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class CensysClient(OSINTClient):
    SERVICE_NAME = "censys"
    RATE_LIMIT_PER_SECOND = 0.4  # Free tier: ~2 req/5s
    BASE_URL = "https://search.censys.io/api"

    def __init__(self, api_id: str, api_secret: str):
        # Censys uses basic auth (id:secret)
        super().__init__(api_key=api_id)
        self.api_secret = api_secret
        self._auth_header = base64.b64encode(
            f"{api_id}:{api_secret}".encode()
        ).decode()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.api_secret)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Basic {self._auth_header}",
            "Accept": "application/json",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search Censys for host and certificate data."""
        cache_key = f"censys:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "censys"}

        # Search hosts
        host_data = await self._search_hosts(domain, session)
        if host_data:
            result["hosts"] = host_data

        # Search certificates
        cert_data = await self._search_certs(domain, session)
        if cert_data:
            result["certificates"] = cert_data

        self._cache_set(cache_key, result)
        return result

    async def _search_hosts(self, domain: str, session: aiohttp.ClientSession) -> list:
        """Search Censys hosts API."""
        data = await self._fetch_json(
            f"{self.BASE_URL}/v2/hosts/search",
            session,
            headers=self._headers(),
            params={"q": domain, "per_page": 25},
        )
        if not data:
            return []

        hosts = []
        for hit in data.get("result", {}).get("hits", []):
            hosts.append({
                "ip": hit.get("ip"),
                "services": [
                    {
                        "port": svc.get("port"),
                        "service_name": svc.get("service_name"),
                        "transport_protocol": svc.get("transport_protocol"),
                    }
                    for svc in hit.get("services", [])
                ],
                "location": hit.get("location", {}).get("country"),
                "autonomous_system": hit.get("autonomous_system", {}).get("name"),
            })
        logger.info(f"Censys host search for {domain}: {len(hosts)} hosts")
        return hosts

    async def _search_certs(self, domain: str, session: aiohttp.ClientSession) -> list:
        """Search Censys certificates API."""
        data = await self._fetch_json(
            f"{self.BASE_URL}/v2/certificates/search",
            session,
            headers=self._headers(),
            params={"q": domain, "per_page": 10},
        )
        if not data:
            return []

        certs = []
        for hit in data.get("result", {}).get("hits", []):
            certs.append({
                "fingerprint": hit.get("fingerprint_sha256", "")[:16] + "...",
                "names": hit.get("names", []),
                "issuer": hit.get("parsed", {}).get("issuer_dn", ""),
                "not_after": hit.get("parsed", {}).get("validity", {}).get("end"),
            })
        return certs

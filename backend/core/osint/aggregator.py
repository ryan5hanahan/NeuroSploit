"""
OSINT Aggregator — Auto-discovers enabled clients, runs all in parallel, merges results.
"""

import asyncio
import logging
import os
from typing import Any, Dict, List

import aiohttp

from backend.core.osint.base_client import OSINTClient
from backend.core.osint.shodan_client import ShodanClient
from backend.core.osint.censys_client import CensysClient
from backend.core.osint.virustotal_client import VirusTotalClient
from backend.core.osint.builtwith_client import BuiltWithClient

logger = logging.getLogger(__name__)


class OSINTAggregator:
    """Aggregates OSINT data from all configured API clients."""

    def __init__(self):
        self.clients: List[OSINTClient] = []
        self._init_clients()

    def _init_clients(self):
        """Auto-discover clients based on which API keys are configured."""
        shodan_key = os.getenv("SHODAN_API_KEY", "")
        if shodan_key:
            self.clients.append(ShodanClient(shodan_key))

        censys_id = os.getenv("CENSYS_API_ID", "")
        censys_secret = os.getenv("CENSYS_API_SECRET", "")
        if censys_id and censys_secret:
            self.clients.append(CensysClient(censys_id, censys_secret))

        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if vt_key:
            self.clients.append(VirusTotalClient(vt_key))

        bw_key = os.getenv("BUILTWITH_API_KEY", "")
        if bw_key:
            self.clients.append(BuiltWithClient(bw_key))

        if self.clients:
            names = [c.SERVICE_NAME for c in self.clients]
            logger.info(f"OSINT aggregator initialized with {len(self.clients)} clients: {names}")
        else:
            logger.debug("OSINT aggregator: no API keys configured, all clients disabled")

    @property
    def enabled(self) -> bool:
        return len(self.clients) > 0

    @property
    def client_names(self) -> List[str]:
        return [c.SERVICE_NAME for c in self.clients]

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Run all enabled OSINT clients in parallel and merge results.

        Returns a dict keyed by service name, plus a merged summary.
        """
        if not self.clients:
            return {"enabled": False, "clients": []}

        # Strip scheme for API lookups
        clean_domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

        tasks = [
            self._safe_enrich(client, clean_domain, session)
            for client in self.clients
        ]
        results = await asyncio.gather(*tasks)

        merged: Dict[str, Any] = {
            "enabled": True,
            "clients": self.client_names,
        }

        # Merge per-client results
        all_ports = set()
        all_technologies = []
        all_vulns = []
        all_subdomains = set()

        for client, result in zip(self.clients, results):
            merged[client.SERVICE_NAME] = result

            # Aggregate cross-client data
            if "ports" in result:
                all_ports.update(result["ports"])
            if "technologies" in result:
                all_technologies.extend(result["technologies"])
            if "vulns" in result:
                all_vulns.extend(result["vulns"])
            if "subdomains" in result:
                all_subdomains.update(result["subdomains"])
            if "hosts" in result:
                for host in result["hosts"]:
                    for svc in host.get("services", []):
                        if svc.get("port"):
                            all_ports.add(svc["port"])

        merged["summary"] = {
            "ports": sorted(all_ports),
            "technologies": all_technologies,
            "known_vulns": all_vulns[:50],
            "subdomains": sorted(all_subdomains),
        }

        logger.info(
            f"OSINT aggregation for {clean_domain}: "
            f"{len(all_ports)} ports, {len(all_technologies)} techs, "
            f"{len(all_vulns)} vulns, {len(all_subdomains)} subdomains"
        )
        return merged

    async def _safe_enrich(
        self, client: OSINTClient, domain: str, session: aiohttp.ClientSession
    ) -> Dict[str, Any]:
        """Wrap client.enrich_target with error handling."""
        try:
            return await asyncio.wait_for(
                client.enrich_target(domain, session), timeout=60
            )
        except asyncio.TimeoutError:
            logger.warning(f"{client.SERVICE_NAME} timed out for {domain}")
            return {"source": client.SERVICE_NAME, "error": "timeout"}
        except Exception as e:
            logger.warning(f"{client.SERVICE_NAME} error for {domain}: {e}")
            return {"source": client.SERVICE_NAME, "error": str(e)}

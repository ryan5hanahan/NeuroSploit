"""
NVD (National Vulnerability Database) OSINT Client.

Queries NVD API v2.0 for CVEs by CWE ID and/or keyword.
Supports optional API key for higher rate limits.
"""

import logging
from typing import Any, Dict, List, Optional

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient(OSINTClient):
    SERVICE_NAME = "nvd"
    CACHE_TTL_SECONDS = 86400  # 24 hours
    # Free tier: 5 requests per 30 seconds ≈ 0.16/s
    # With API key: ~50 requests per 30 seconds ≈ 1.5/s
    RATE_LIMIT_PER_SECOND = 0.16

    def __init__(self, api_key: str = ""):
        super().__init__(api_key)
        if self.api_key:
            self.RATE_LIMIT_PER_SECOND = 1.5

    @property
    def enabled(self) -> bool:
        # NVD works without an API key (just slower)
        return True

    # ------------------------------------------------------------------
    # Public search methods
    # ------------------------------------------------------------------

    async def search_by_cwe(
        self,
        cwe_id: str,
        keyword: str,
        session: aiohttp.ClientSession,
        max_results: int = 5,
    ) -> List[Dict[str, Any]]:
        """Search NVD by CWE ID + keyword.  Returns simplified CVE dicts."""
        cache_key = f"nvd:cwe:{cwe_id}:{keyword}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        params: Dict[str, str] = {
            "resultsPerPage": str(max_results),
        }
        # NVD expects bare CWE ID like "CWE-79"
        if cwe_id:
            params["cweId"] = cwe_id
        if keyword:
            params["keywordSearch"] = keyword

        results = await self._query_nvd(params, session)
        self._cache_set(cache_key, results)
        return results

    async def search_by_keyword(
        self,
        keyword: str,
        session: aiohttp.ClientSession,
        max_results: int = 5,
    ) -> List[Dict[str, Any]]:
        """Fallback search by keyword only (no CWE filter)."""
        cache_key = f"nvd:kw:{keyword}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(max_results),
        }
        results = await self._query_nvd(params, session)
        self._cache_set(cache_key, results)
        return results

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Not used for NVD — satisfies ABC."""
        return {"source": "nvd"}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _query_nvd(
        self,
        params: Dict[str, str],
        session: aiohttp.ClientSession,
    ) -> List[Dict[str, Any]]:
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        data = await self._fetch_json(NVD_API_BASE, session, headers=headers, params=params)
        if not data:
            return []

        return self._parse_cves(data)

    @staticmethod
    def _parse_cves(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract simplified CVE records from NVD API v2.0 response."""
        results: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Description (English preferred)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS — try v3.1 first, then v3.0, then v2
            cvss_score = None
            cvss_vector = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            # Published date
            published = cve.get("published", "")

            # References
            refs = [
                r.get("url", "")
                for r in cve.get("references", [])
                if r.get("url")
            ][:5]

            results.append({
                "cve_id": cve_id,
                "description": desc[:500],
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "published": published,
                "references": refs,
            })

        return results

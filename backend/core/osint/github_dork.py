"""
GitHub Code Search OSINT Client — Leaked secrets, config files, API keys in repos.
"""

import logging
from typing import Any, Dict, List

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)

# Dork queries to search for leaked secrets related to a domain
_DORK_PATTERNS: List[Dict[str, str]] = [
    {"query": '"{domain}" password', "category": "credentials"},
    {"query": '"{domain}" api_key', "category": "api_keys"},
    {"query": '"{domain}" apikey', "category": "api_keys"},
    {"query": '"{domain}" secret_key', "category": "api_keys"},
    {"query": '"{domain}" access_token', "category": "tokens"},
    {"query": '"{domain}" authorization bearer', "category": "tokens"},
    {"query": '"{domain}" filename:.env', "category": "config_files"},
    {"query": '"{domain}" filename:.yml password', "category": "config_files"},
    {"query": '"{domain}" filename:config.json', "category": "config_files"},
    {"query": '"{domain}" filename:credentials', "category": "credentials"},
    {"query": '"{domain}" AWS_SECRET_ACCESS_KEY', "category": "cloud_keys"},
    {"query": '"{domain}" PRIVATE KEY', "category": "private_keys"},
]


class GitHubDorkClient(OSINTClient):
    SERVICE_NAME = "github_dork"
    RATE_LIMIT_PER_SECOND = 0.5  # GitHub search rate limit: 30 req/min
    BASE_URL = "https://api.github.com"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"token {self.api_key}",
            "Accept": "application/vnd.github.v3+json",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search GitHub for leaked secrets related to the domain."""
        cache_key = f"github_dork:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "github_dork", "code_leaks": []}

        for dork in _DORK_PATTERNS:
            query = dork["query"].replace("{domain}", domain)
            data = await self._fetch_json(
                f"{self.BASE_URL}/search/code",
                session,
                headers=self._headers(),
                params={"q": query, "per_page": 5},
            )
            if not data:
                continue

            for item in data.get("items", [])[:3]:
                result["code_leaks"].append({
                    "category": dork["category"],
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "score": item.get("score", 0),
                })

        result["total_leaks"] = len(result["code_leaks"])

        self._cache_set(cache_key, result)
        logger.info(f"GitHub dork search for {domain}: {result['total_leaks']} potential leaks")
        return result

"""Google Dorking Client — automated Google dork generation and search.

Generates targeted Google dorks from domain and technology stack,
uses Google Custom Search API when available.
"""
import logging
import urllib.parse
from typing import Any, Dict, List, Optional
import aiohttp
from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)

# 20+ dork templates organized by category
DORK_TEMPLATES = {
    "sensitive_files": [
        'site:{domain} filetype:env',
        'site:{domain} filetype:log',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:bak',
        'site:{domain} filetype:conf',
        'site:{domain} filetype:cfg',
        'site:{domain} filetype:xml inurl:config',
    ],
    "exposed_panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} intitle:"index of"',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:phpinfo',
    ],
    "information_disclosure": [
        'site:{domain} ext:txt "password"',
        'site:{domain} inurl:".git"',
        'site:{domain} inurl:".svn"',
        'site:{domain} "index of /" "parent directory"',
        'site:{domain} filetype:pdf "confidential"',
    ],
    "api_endpoints": [
        'site:{domain} inurl:api',
        'site:{domain} inurl:graphql',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:v1 OR inurl:v2',
    ],
    "error_messages": [
        'site:{domain} "SQL syntax" OR "mysql_fetch"',
        'site:{domain} "stack trace" OR "traceback"',
        'site:{domain} "PHP Warning" OR "PHP Error"',
    ],
}


class GoogleDorkClient(OSINTClient):
    """Google dorking client for passive OSINT via search queries."""

    SERVICE_NAME = "google_dorking"
    RATE_LIMIT_PER_SECOND = 1.0
    CACHE_TTL_SECONDS = 7200  # 2 hours

    def __init__(self, api_key: str, cse_cx: str = ""):
        super().__init__(api_key)
        self.cse_cx = cse_cx
        self._has_cse = bool(api_key and cse_cx)

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Generate dorks and optionally execute via Google CSE API."""
        cache_key = f"gdork:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        # Always generate dork queries
        dorks = self.generate_dorks(domain)

        result = {
            "source": self.SERVICE_NAME,
            "dorks_generated": len(dorks),
            "dorks": dorks,
            "results": [],
            "shell_commands": self.generate_shell_commands(domain),
        }

        # If CSE API available, execute top dorks
        if self._has_cse:
            for category, queries in list(DORK_TEMPLATES.items())[:3]:
                for query_template in queries[:2]:  # Limit API calls
                    query = query_template.format(domain=domain)
                    search_results = await self._cse_search(query, session)
                    if search_results:
                        result["results"].extend(search_results)

        self._cache_set(cache_key, result)
        return result

    def generate_dorks(self, domain: str, technology: str = "") -> List[Dict[str, str]]:
        """Generate Google dork queries for a target domain."""
        dorks = []
        for category, templates in DORK_TEMPLATES.items():
            for template in templates:
                query = template.format(domain=domain)
                dorks.append({
                    "category": category,
                    "query": query,
                    "search_url": f"https://www.google.com/search?q={urllib.parse.quote(query)}",
                })

        # Add technology-specific dorks if known
        if technology:
            tech_dorks = self._get_tech_specific_dorks(domain, technology)
            dorks.extend(tech_dorks)

        return dorks

    def generate_shell_commands(self, domain: str) -> List[str]:
        """Generate shell commands for manual dorking via tools."""
        commands = []
        for category, templates in list(DORK_TEMPLATES.items())[:3]:
            query = templates[0].format(domain=domain)
            commands.append(
                f'# {category}\ncurl -s "https://www.google.com/search?q={urllib.parse.quote(query)}" '
                f'-H "User-Agent: Mozilla/5.0" | grep -oP \'href="[^"]*\''
            )
        return commands

    async def _cse_search(
        self, query: str, session: aiohttp.ClientSession
    ) -> List[Dict[str, str]]:
        """Execute a search via Google Custom Search Engine API."""
        if not self._has_cse:
            return []

        data = await self._fetch_json(
            "https://www.googleapis.com/customsearch/v1",
            session,
            params={
                "key": self.api_key,
                "cx": self.cse_cx,
                "q": query,
                "num": 10,
            },
        )

        if not data:
            return []

        results = []
        for item in data.get("items", []):
            results.append({
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "query": query,
            })
        return results

    def _get_tech_specific_dorks(self, domain: str, technology: str) -> List[Dict[str, str]]:
        """Generate technology-specific dork queries."""
        tech_dorks = {
            "wordpress": [
                'site:{domain} inurl:wp-content',
                'site:{domain} inurl:wp-includes',
                'site:{domain} filetype:txt "wp-config"',
            ],
            "django": [
                'site:{domain} inurl:admin',
                'site:{domain} "Django" "DEBUG = True"',
            ],
            "laravel": [
                'site:{domain} inurl:.env "APP_KEY"',
                'site:{domain} "Laravel" "debug"',
            ],
            "nodejs": [
                'site:{domain} filetype:json "dependencies"',
                'site:{domain} inurl:package.json',
            ],
        }

        dorks = []
        tech_lower = technology.lower()
        for tech_key, templates in tech_dorks.items():
            if tech_key in tech_lower:
                for template in templates:
                    query = template.format(domain=domain)
                    dorks.append({
                        "category": f"tech_{tech_key}",
                        "query": query,
                        "search_url": f"https://www.google.com/search?q={urllib.parse.quote(query)}",
                    })
        return dorks

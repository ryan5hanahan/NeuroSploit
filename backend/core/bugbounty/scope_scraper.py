"""Bug Bounty Scope Scraper — Scrape program scope from HackerOne and Bugcrowd.

Parses scope tables from platform pages into structured format for ScopeParser.
"""
import logging
import re
from typing import Any, Dict, List, Optional
import aiohttp

logger = logging.getLogger(__name__)


class ScopeScraper:
    """Scrapes bug bounty program scope from platform pages."""

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self._session = session

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session

    async def scrape_hackerone_page(self, program_handle: str) -> Dict[str, Any]:
        """Scrape scope from a HackerOne program's public page.

        Uses the HackerOne API when credentials are available,
        falls back to parsing the public program page.
        """
        session = await self._ensure_session()

        # Try public API first (no auth needed for public programs)
        url = f"https://api.hackerone.com/v1/hackers/programs/{program_handle}/structured_scopes"
        try:
            async with session.get(
                url,
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_h1_api_response(data, program_handle)
        except Exception as e:
            logger.warning(f"H1 API scope fetch failed for {program_handle}: {e}")

        # Fallback: scrape the public page
        page_url = f"https://hackerone.com/{program_handle}"
        try:
            async with session.get(
                page_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    return self._parse_h1_html(html, program_handle)
        except Exception as e:
            logger.warning(f"H1 page scrape failed for {program_handle}: {e}")

        return {"program": program_handle, "in_scope": [], "out_of_scope": [], "source": "failed"}

    async def scrape_bugcrowd_page(self, program_slug: str) -> Dict[str, Any]:
        """Scrape scope from a Bugcrowd program's public page."""
        session = await self._ensure_session()

        url = f"https://bugcrowd.com/{program_slug}"
        try:
            async with session.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    return self._parse_bugcrowd_html(html, program_slug)
        except Exception as e:
            logger.warning(f"Bugcrowd scrape failed for {program_slug}: {e}")

        return {"program": program_slug, "in_scope": [], "out_of_scope": [], "source": "failed"}

    def _parse_h1_api_response(self, data: Dict, program_handle: str) -> Dict[str, Any]:
        """Parse HackerOne structured scopes API response."""
        in_scope = []
        out_of_scope = []

        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            asset = {
                "asset_identifier": attrs.get("asset_identifier", ""),
                "asset_type": attrs.get("asset_type", ""),
                "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                "eligible_for_submission": attrs.get("eligible_for_submission", True),
                "instruction": attrs.get("instruction", ""),
                "max_severity": attrs.get("max_severity", ""),
            }

            if attrs.get("eligible_for_submission", True):
                in_scope.append(asset)
            else:
                out_of_scope.append(asset)

        return {
            "program": program_handle,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "source": "h1_api",
        }

    def _parse_h1_html(self, html: str, program_handle: str) -> Dict[str, Any]:
        """Parse scope from HackerOne public program page HTML."""
        domains = []

        # Extract domains from common patterns in H1 pages
        domain_pattern = re.compile(
            r'(?:asset_identifier|scope-target)["\s:>]*([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})',
            re.IGNORECASE,
        )
        for match in domain_pattern.finditer(html):
            domain = match.group(1).strip()
            if domain and "." in domain:
                domains.append(domain)

        # Also look for wildcard patterns
        wildcard_pattern = re.compile(r'\*\.([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})')
        for match in wildcard_pattern.finditer(html):
            domains.append(f"*.{match.group(1)}")

        # Deduplicate
        seen = set()
        in_scope = []
        for domain in domains:
            if domain not in seen:
                seen.add(domain)
                in_scope.append({
                    "asset_identifier": domain,
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                })

        return {
            "program": program_handle,
            "in_scope": in_scope,
            "out_of_scope": [],
            "source": "h1_html",
        }

    def _parse_bugcrowd_html(self, html: str, program_slug: str) -> Dict[str, Any]:
        """Parse scope from Bugcrowd public program page HTML."""
        domains = []

        # Extract domains from Bugcrowd scope tables
        domain_pattern = re.compile(
            r'(?:target|scope)["\s:>]*([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})',
            re.IGNORECASE,
        )
        for match in domain_pattern.finditer(html):
            domain = match.group(1).strip()
            if domain and "." in domain:
                domains.append(domain)

        seen = set()
        in_scope = []
        for domain in domains:
            if domain not in seen:
                seen.add(domain)
                in_scope.append({
                    "asset_identifier": domain,
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                })

        return {
            "program": program_slug,
            "in_scope": in_scope,
            "out_of_scope": [],
            "source": "bugcrowd_html",
        }

    async def close(self):
        """Close the HTTP session if we created it."""
        if self._session:
            await self._session.close()
            self._session = None

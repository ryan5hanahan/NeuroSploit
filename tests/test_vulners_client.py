"""
Phase 2 Tests — VulnersClient

Tests Vulners.com API client for vulnerability intelligence and exploit search,
following the OSINTClient pattern with caching and rate limiting.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.osint.base_client import OSINTClient
from backend.core.osint.vulners_client import VulnersClient


@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    return AsyncMock()


def _patch_fetch(client, responses):
    """Patch _fetch_json to return responses in order."""
    call_count = {"n": 0}

    async def _mock_fetch(*args, **kwargs):
        idx = call_count["n"]
        call_count["n"] += 1
        if idx < len(responses):
            return responses[idx]
        return None

    client._fetch_json = _mock_fetch


# ---------------------------------------------------------------------------
# Inheritance and basic properties
# ---------------------------------------------------------------------------


class TestVulnersClientBasic:
    def test_inherits_osint_client(self):
        client = VulnersClient("test-key")
        assert isinstance(client, OSINTClient)

    def test_service_name(self):
        client = VulnersClient("test-key")
        assert client.SERVICE_NAME == "vulners"

    def test_rate_limit(self):
        client = VulnersClient("test-key")
        assert client.RATE_LIMIT_PER_SECOND == 2.0

    def test_cache_ttl(self):
        client = VulnersClient("test-key")
        assert client.CACHE_TTL_SECONDS == 3600

    def test_enabled_with_key(self):
        client = VulnersClient("test-key")
        assert client.enabled is True

    def test_disabled_without_key(self):
        client = VulnersClient("")
        assert client.enabled is False

    def test_base_url(self):
        client = VulnersClient("test-key")
        assert client.BASE_URL == "https://vulners.com/api/v3"


# ---------------------------------------------------------------------------
# enrich_target
# ---------------------------------------------------------------------------


class TestVulnersClientEnrichTarget:
    @pytest.mark.asyncio
    async def test_enrich_target_disabled_returns_early(self, mock_session):
        client = VulnersClient("")
        result = await client.enrich_target("example.com", mock_session)
        assert result["source"] == "vulners"
        assert result["enabled"] is False

    @pytest.mark.asyncio
    async def test_enrich_target_with_exploits(self, mock_session):
        client = VulnersClient("test-key")
        vuln_response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2021-44228",
                            "title": "Log4Shell RCE",
                            "description": "Apache Log4j remote code execution",
                            "type": "cve",
                            "cvss": {"score": 10.0},
                            "href": "https://vulners.com/cve/CVE-2021-44228",
                        }
                    },
                    {
                        "_source": {
                            "id": "EXPLOIT-DB-50592",
                            "title": "Log4Shell PoC",
                            "description": "Proof of concept exploit",
                            "type": "exploitdb",
                            "cvss": {"score": 10.0},
                            "href": "https://vulners.com/exploitdb/EXPLOIT-DB-50592",
                        }
                    },
                ]
            },
        }
        _patch_fetch(client, [vuln_response])
        result = await client.enrich_target("example.com", mock_session)

        assert result["source"] == "vulners"
        assert len(result["exploits"]) == 2
        assert len(result["vulns"]) == 2
        assert result["vulns"][0]["id"] == "CVE-2021-44228"
        assert result["vulns"][0]["title"] == "Log4Shell RCE"
        assert result["vulns"][0]["cvss_score"] == 10.0
        assert result["vulns"][0]["type"] == "cve"

    @pytest.mark.asyncio
    async def test_enrich_target_empty_result_when_api_fails(self, mock_session):
        client = VulnersClient("test-key")
        _patch_fetch(client, [None])
        result = await client.enrich_target("example.com", mock_session)
        assert result["exploits"] == []
        assert result["vulns"] == []

    @pytest.mark.asyncio
    async def test_enrich_target_with_error_result(self, mock_session):
        client = VulnersClient("test-key")
        _patch_fetch(client, [{"result": "error", "data": {}}])
        result = await client.enrich_target("example.com", mock_session)
        assert result["exploits"] == []
        assert result["vulns"] == []

    @pytest.mark.asyncio
    async def test_enrich_target_truncates_vulns_to_20(self, mock_session):
        client = VulnersClient("test-key")
        # Return 25 exploits
        items = [
            {
                "_source": {
                    "id": f"CVE-2021-{i}",
                    "title": f"Vuln {i}",
                    "description": "",
                    "type": "cve",
                    "cvss": {"score": 5.0},
                    "href": "",
                }
            }
            for i in range(25)
        ]
        _patch_fetch(client, [{"result": "OK", "data": {"search": items}}])
        result = await client.enrich_target("example.com", mock_session)
        # exploits contains all 25, but vulns is capped at 20
        assert len(result["exploits"]) == 25
        assert len(result["vulns"]) == 20


# ---------------------------------------------------------------------------
# Caching behavior
# ---------------------------------------------------------------------------


class TestVulnersClientCaching:
    @pytest.mark.asyncio
    async def test_enrich_target_caches_result(self, mock_session):
        client = VulnersClient("test-key")
        response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2021-1",
                            "title": "Test Vuln",
                            "description": "",
                            "type": "cve",
                            "cvss": {"score": 7.5},
                            "href": "",
                        }
                    }
                ]
            },
        }
        _patch_fetch(client, [response, response])
        r1 = await client.enrich_target("example.com", mock_session)
        r2 = await client.enrich_target("example.com", mock_session)
        # Both should be identical (second served from cache)
        assert r1 == r2
        # Only one actual fetch should have happened (response is only consumed once)
        assert r1["vulns"][0]["id"] == "CVE-2021-1"

    @pytest.mark.asyncio
    async def test_search_exploits_caches_result(self, mock_session):
        client = VulnersClient("test-key")
        response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2020-1",
                            "title": "Cached Exploit",
                            "description": "desc",
                            "type": "cve",
                            "cvss": {"score": 9.0},
                            "href": "https://example.com",
                        }
                    }
                ]
            },
        }
        _patch_fetch(client, [response, None])
        r1 = await client.search_exploits("apache", mock_session)
        r2 = await client.search_exploits("apache", mock_session)
        # Second call should hit the cache
        assert r1 == r2
        assert r1[0]["id"] == "CVE-2020-1"


# ---------------------------------------------------------------------------
# search_exploits
# ---------------------------------------------------------------------------


class TestVulnersClientSearchExploits:
    @pytest.mark.asyncio
    async def test_search_exploits_returns_list(self, mock_session):
        client = VulnersClient("test-key")
        response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2022-100",
                            "title": "Remote Code Execution",
                            "description": "A serious RCE vulnerability in XYZ",
                            "type": "cve",
                            "cvss": {"score": 9.8},
                            "href": "https://vulners.com/cve/CVE-2022-100",
                        }
                    }
                ]
            },
        }
        _patch_fetch(client, [response])
        results = await client.search_exploits("apache struts", mock_session)
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2022-100"
        assert results[0]["title"] == "Remote Code Execution"

    @pytest.mark.asyncio
    async def test_search_exploits_truncates_description(self, mock_session):
        client = VulnersClient("test-key")
        long_desc = "A" * 1000
        response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2022-1",
                            "title": "Long Desc",
                            "description": long_desc,
                            "type": "cve",
                            "cvss": {},
                            "href": "",
                        }
                    }
                ]
            },
        }
        _patch_fetch(client, [response])
        results = await client.search_exploits("test", mock_session)
        assert len(results[0]["description"]) <= 500

    @pytest.mark.asyncio
    async def test_search_exploits_returns_empty_on_none_response(self, mock_session):
        client = VulnersClient("test-key")
        _patch_fetch(client, [None])
        results = await client.search_exploits("nonexistent", mock_session)
        assert results == []

    @pytest.mark.asyncio
    async def test_search_exploits_returns_empty_on_error_result(self, mock_session):
        client = VulnersClient("test-key")
        _patch_fetch(client, [{"result": "error"}])
        results = await client.search_exploits("fail", mock_session)
        assert results == []

    @pytest.mark.asyncio
    async def test_search_exploits_handles_none_description(self, mock_session):
        client = VulnersClient("test-key")
        response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2022-2",
                            "title": "No Desc",
                            "description": None,
                            "type": "cve",
                            "cvss": {},
                            "href": "",
                        }
                    }
                ]
            },
        }
        _patch_fetch(client, [response])
        results = await client.search_exploits("test", mock_session)
        assert results[0]["description"] == ""


# ---------------------------------------------------------------------------
# search_by_cve
# ---------------------------------------------------------------------------


class TestVulnersClientSearchByCVE:
    @pytest.mark.asyncio
    async def test_search_by_cve_delegates_to_search_exploits(self, mock_session):
        client = VulnersClient("test-key")
        response = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2021-44228",
                            "title": "Log4Shell",
                            "description": "Critical RCE",
                            "type": "cve",
                            "cvss": {"score": 10.0},
                            "href": "https://vulners.com/cve/CVE-2021-44228",
                        }
                    }
                ]
            },
        }
        _patch_fetch(client, [response])
        results = await client.search_by_cve("CVE-2021-44228", mock_session)
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_search_by_cve_returns_empty_list_on_failure(self, mock_session):
        client = VulnersClient("test-key")
        _patch_fetch(client, [None])
        results = await client.search_by_cve("CVE-9999-9999", mock_session)
        assert results == []

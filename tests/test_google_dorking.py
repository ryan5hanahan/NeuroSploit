"""
Phase 2 Tests — GoogleDorkClient

Tests Google dorking client for passive OSINT via dork generation and
optional Google Custom Search Engine API execution.
"""

import os
import sys
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.osint.base_client import OSINTClient
from backend.core.osint.google_dorking import DORK_TEMPLATES, GoogleDorkClient


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


class TestGoogleDorkClientBasic:
    def test_inherits_osint_client(self):
        client = GoogleDorkClient("test-key", "cx-123")
        assert isinstance(client, OSINTClient)

    def test_service_name(self):
        client = GoogleDorkClient("test-key")
        assert client.SERVICE_NAME == "google_dorking"

    def test_rate_limit(self):
        client = GoogleDorkClient("test-key")
        assert client.RATE_LIMIT_PER_SECOND == 1.0

    def test_cache_ttl(self):
        client = GoogleDorkClient("test-key")
        assert client.CACHE_TTL_SECONDS == 7200

    def test_enabled_with_api_key_no_cse(self):
        client = GoogleDorkClient("test-key")
        assert client.enabled is True

    def test_enabled_without_api_key(self):
        client = GoogleDorkClient("")
        assert client.enabled is False

    def test_has_cse_requires_both_key_and_cx(self):
        assert GoogleDorkClient("key", "cx")._has_cse is True
        assert GoogleDorkClient("key", "")._has_cse is False
        assert GoogleDorkClient("", "cx")._has_cse is False
        assert GoogleDorkClient("", "")._has_cse is False


# ---------------------------------------------------------------------------
# DORK_TEMPLATES module-level constant
# ---------------------------------------------------------------------------


class TestDorkTemplates:
    def test_all_categories_present(self):
        expected_categories = {
            "sensitive_files",
            "exposed_panels",
            "information_disclosure",
            "api_endpoints",
            "error_messages",
        }
        assert expected_categories.issubset(set(DORK_TEMPLATES.keys()))

    def test_at_least_20_total_templates(self):
        total = sum(len(v) for v in DORK_TEMPLATES.values())
        assert total >= 20

    def test_all_templates_contain_domain_placeholder(self):
        for category, templates in DORK_TEMPLATES.items():
            for template in templates:
                assert "{domain}" in template, (
                    f"Template in category '{category}' is missing {{domain}} placeholder: {template}"
                )


# ---------------------------------------------------------------------------
# generate_dorks
# ---------------------------------------------------------------------------


class TestGoogleDorkClientGenerateDorks:
    def test_generate_dorks_returns_list_of_dicts(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com")
        assert isinstance(dorks, list)
        assert len(dorks) > 0
        for dork in dorks:
            assert "category" in dork
            assert "query" in dork
            assert "search_url" in dork

    def test_generate_dorks_substitutes_domain(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("targetdomain.com")
        for dork in dorks:
            assert "targetdomain.com" in dork["query"]
            assert "{domain}" not in dork["query"]

    def test_generate_dorks_all_categories_covered(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com")
        categories_found = {d["category"] for d in dorks}
        for expected_cat in DORK_TEMPLATES.keys():
            assert expected_cat in categories_found

    def test_generate_dorks_search_url_is_google(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com")
        for dork in dorks:
            assert dork["search_url"].startswith("https://www.google.com/search?q=")

    def test_generate_dorks_search_url_encodes_query(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com")
        for dork in dorks:
            # Ensure the query is properly URL-encoded in the search_url
            encoded_query = urllib.parse.quote(dork["query"])
            assert encoded_query in dork["search_url"]

    def test_generate_dorks_with_no_technology(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com")
        # Should only have base dorks without technology-specific ones
        tech_cats = [d for d in dorks if d["category"].startswith("tech_")]
        assert len(tech_cats) == 0

    def test_generate_dorks_with_wordpress_technology(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com", technology="wordpress")
        tech_cats = [d for d in dorks if d["category"] == "tech_wordpress"]
        assert len(tech_cats) > 0
        for dork in tech_cats:
            assert "example.com" in dork["query"]

    def test_generate_dorks_with_django_technology(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com", technology="django")
        tech_cats = [d for d in dorks if d["category"] == "tech_django"]
        assert len(tech_cats) > 0

    def test_generate_dorks_with_laravel_technology(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com", technology="laravel")
        tech_cats = [d for d in dorks if d["category"] == "tech_laravel"]
        assert len(tech_cats) > 0

    def test_generate_dorks_with_nodejs_technology(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com", technology="nodejs")
        tech_cats = [d for d in dorks if d["category"] == "tech_nodejs"]
        assert len(tech_cats) > 0

    def test_generate_dorks_technology_case_insensitive(self):
        client = GoogleDorkClient("key")
        dorks = client.generate_dorks("example.com", technology="WordPress")
        tech_cats = [d for d in dorks if d["category"] == "tech_wordpress"]
        assert len(tech_cats) > 0

    def test_generate_dorks_unknown_technology_adds_nothing(self):
        client = GoogleDorkClient("key")
        base_count = len(client.generate_dorks("example.com"))
        dorks_with_tech = client.generate_dorks("example.com", technology="cobol")
        assert len(dorks_with_tech) == base_count


# ---------------------------------------------------------------------------
# generate_shell_commands
# ---------------------------------------------------------------------------


class TestGoogleDorkClientShellCommands:
    def test_generate_shell_commands_returns_list(self):
        client = GoogleDorkClient("key")
        commands = client.generate_shell_commands("example.com")
        assert isinstance(commands, list)
        assert len(commands) > 0

    def test_generate_shell_commands_contain_domain(self):
        client = GoogleDorkClient("key")
        commands = client.generate_shell_commands("example.com")
        for cmd in commands:
            assert "example.com" in cmd

    def test_generate_shell_commands_are_curl_based(self):
        client = GoogleDorkClient("key")
        commands = client.generate_shell_commands("example.com")
        for cmd in commands:
            assert "curl" in cmd

    def test_generate_shell_commands_limited_to_three_categories(self):
        client = GoogleDorkClient("key")
        commands = client.generate_shell_commands("example.com")
        assert len(commands) == 3


# ---------------------------------------------------------------------------
# _cse_search
# ---------------------------------------------------------------------------


class TestGoogleDorkClientCSESearch:
    @pytest.mark.asyncio
    async def test_cse_search_returns_empty_when_no_cse(self, mock_session):
        client = GoogleDorkClient("key", "")  # no CSE cx
        result = await client._cse_search("site:example.com filetype:env", mock_session)
        assert result == []

    @pytest.mark.asyncio
    async def test_cse_search_with_valid_response(self, mock_session):
        client = GoogleDorkClient("api-key", "cx-123")
        cse_response = {
            "items": [
                {
                    "title": "Exposed .env file",
                    "link": "https://example.com/.env",
                    "snippet": "DB_PASSWORD=secret ...",
                },
                {
                    "title": "Config file",
                    "link": "https://example.com/config.env",
                    "snippet": "APP_KEY=base64:abc",
                },
            ]
        }
        _patch_fetch(client, [cse_response])
        results = await client._cse_search("site:example.com filetype:env", mock_session)
        assert len(results) == 2
        assert results[0]["title"] == "Exposed .env file"
        assert results[0]["link"] == "https://example.com/.env"
        assert results[0]["snippet"] == "DB_PASSWORD=secret ..."
        assert results[0]["query"] == "site:example.com filetype:env"

    @pytest.mark.asyncio
    async def test_cse_search_returns_empty_on_none_response(self, mock_session):
        client = GoogleDorkClient("api-key", "cx-123")
        _patch_fetch(client, [None])
        results = await client._cse_search("site:example.com inurl:admin", mock_session)
        assert results == []

    @pytest.mark.asyncio
    async def test_cse_search_returns_empty_when_no_items(self, mock_session):
        client = GoogleDorkClient("api-key", "cx-123")
        _patch_fetch(client, [{"searchInformation": {"totalResults": "0"}}])
        results = await client._cse_search("site:example.com inurl:admin", mock_session)
        assert results == []


# ---------------------------------------------------------------------------
# enrich_target
# ---------------------------------------------------------------------------


class TestGoogleDorkClientEnrichTarget:
    @pytest.mark.asyncio
    async def test_enrich_target_without_cse(self, mock_session):
        client = GoogleDorkClient("key")  # No CSE, but has API key
        result = await client.enrich_target("example.com", mock_session)
        assert result["source"] == "google_dorking"
        assert result["dorks_generated"] > 0
        assert len(result["dorks"]) == result["dorks_generated"]
        assert result["results"] == []
        assert len(result["shell_commands"]) > 0

    @pytest.mark.asyncio
    async def test_enrich_target_with_cse_executes_searches(self, mock_session):
        client = GoogleDorkClient("api-key", "cx-123")
        cse_item = {
            "title": "Admin Panel",
            "link": "https://example.com/admin",
            "snippet": "Login required",
        }
        cse_response = {"items": [cse_item]}
        # Return a valid response for each CSE call (3 categories * 2 templates each = 6)
        _patch_fetch(client, [cse_response] * 6)
        result = await client.enrich_target("example.com", mock_session)
        assert result["source"] == "google_dorking"
        assert len(result["results"]) > 0

    @pytest.mark.asyncio
    async def test_enrich_target_caches_result(self, mock_session):
        client = GoogleDorkClient("key")
        r1 = await client.enrich_target("example.com", mock_session)
        r2 = await client.enrich_target("example.com", mock_session)
        assert r1 == r2

    @pytest.mark.asyncio
    async def test_enrich_target_includes_shell_commands(self, mock_session):
        client = GoogleDorkClient("key")
        result = await client.enrich_target("example.com", mock_session)
        assert "shell_commands" in result
        assert isinstance(result["shell_commands"], list)
        assert len(result["shell_commands"]) > 0

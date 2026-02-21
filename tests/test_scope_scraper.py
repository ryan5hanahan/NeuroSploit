"""
Phase 3 Tests — Bug Bounty Scope Scraper

Tests HackerOne and Bugcrowd scope scraping (API and HTML fallback paths).
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.bugbounty.scope_scraper import ScopeScraper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx_manager(resp):
    """Wrap a mock response in an async context manager."""
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_response(status: int, json_data=None, text_data: str = ""):
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data or {})
    resp.text = AsyncMock(return_value=text_data)
    return resp


# ---------------------------------------------------------------------------
# TestScrapeHackeronePage
# ---------------------------------------------------------------------------


class TestScrapeHackeronePage:
    @pytest.mark.asyncio
    async def test_uses_api_when_200(self):
        """Returns parsed API data when the H1 structured-scopes endpoint responds 200."""
        api_payload = {
            "data": [
                {
                    "attributes": {
                        "asset_identifier": "*.example.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "instruction": "",
                        "max_severity": "critical",
                    }
                }
            ]
        }
        mock_resp = _make_response(200, json_data=api_payload)
        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=_make_ctx_manager(mock_resp))

        scraper = ScopeScraper(session=mock_session)
        result = await scraper.scrape_hackerone_page("example")

        assert result["source"] == "h1_api"
        assert result["program"] == "example"
        assert len(result["in_scope"]) == 1
        assert result["in_scope"][0]["asset_identifier"] == "*.example.com"
        assert result["out_of_scope"] == []

    @pytest.mark.asyncio
    async def test_falls_back_to_html_on_api_failure(self):
        """Falls back to HTML page scraping when the API returns non-200."""
        html = (
            'scope-target">api.example.com</td>'
            '<td>*.example.org</td>'
        )
        api_resp = _make_response(403)
        html_resp = _make_response(200, text_data=html)

        call_count = {"n": 0}
        responses = [api_resp, html_resp]

        def _get_cm(*args, **kwargs):
            resp = responses[call_count["n"]]
            call_count["n"] += 1
            return _make_ctx_manager(resp)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=_get_cm)

        scraper = ScopeScraper(session=mock_session)
        result = await scraper.scrape_hackerone_page("example")

        assert result["source"] == "h1_html"

    @pytest.mark.asyncio
    async def test_returns_failed_on_both_errors(self):
        """Returns failed source when both API and page scrape raise exceptions."""
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("network error"))

        scraper = ScopeScraper(session=mock_session)
        result = await scraper.scrape_hackerone_page("bad-program")

        assert result["source"] == "failed"
        assert result["in_scope"] == []
        assert result["out_of_scope"] == []


# ---------------------------------------------------------------------------
# TestParseH1ApiResponse
# ---------------------------------------------------------------------------


class TestParseH1ApiResponse:
    def test_in_scope_and_out_of_scope_split(self):
        scraper = ScopeScraper()
        data = {
            "data": [
                {
                    "attributes": {
                        "asset_identifier": "app.example.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "instruction": "Main app",
                        "max_severity": "high",
                    }
                },
                {
                    "attributes": {
                        "asset_identifier": "staging.example.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": False,
                        "eligible_for_submission": False,
                        "instruction": "",
                        "max_severity": "",
                    }
                },
            ]
        }
        result = scraper._parse_h1_api_response(data, "example")

        assert len(result["in_scope"]) == 1
        assert len(result["out_of_scope"]) == 1
        assert result["in_scope"][0]["asset_identifier"] == "app.example.com"
        assert result["out_of_scope"][0]["asset_identifier"] == "staging.example.com"
        assert result["source"] == "h1_api"

    def test_empty_data_list(self):
        scraper = ScopeScraper()
        result = scraper._parse_h1_api_response({"data": []}, "empty-prog")
        assert result["in_scope"] == []
        assert result["out_of_scope"] == []

    def test_all_fields_preserved(self):
        scraper = ScopeScraper()
        data = {
            "data": [
                {
                    "attributes": {
                        "asset_identifier": "*.corp.com",
                        "asset_type": "WILDCARD",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                        "instruction": "All subdomains",
                        "max_severity": "critical",
                    }
                }
            ]
        }
        result = scraper._parse_h1_api_response(data, "corp")
        asset = result["in_scope"][0]
        assert asset["max_severity"] == "critical"
        assert asset["instruction"] == "All subdomains"
        assert asset["asset_type"] == "WILDCARD"


# ---------------------------------------------------------------------------
# TestParseH1Html
# ---------------------------------------------------------------------------


class TestParseH1Html:
    def test_extracts_domains_from_scope_target_pattern(self):
        scraper = ScopeScraper()
        html = 'scope-target">api.example.com</td><td>app.example.com</td>'
        result = scraper._parse_h1_html(html, "example")

        identifiers = [a["asset_identifier"] for a in result["in_scope"]]
        assert "api.example.com" in identifiers
        assert result["source"] == "h1_html"

    def test_extracts_wildcard_domains(self):
        scraper = ScopeScraper()
        html = "Some text *.example.com and *.example.org are in scope"
        result = scraper._parse_h1_html(html, "example")

        identifiers = [a["asset_identifier"] for a in result["in_scope"]]
        assert "*.example.com" in identifiers
        assert "*.example.org" in identifiers

    def test_deduplicates_domains(self):
        scraper = ScopeScraper()
        # Same domain appears twice in different patterns
        html = (
            'asset_identifier">api.example.com</td>'
            'scope-target">api.example.com</td>'
        )
        result = scraper._parse_h1_html(html, "example")

        identifiers = [a["asset_identifier"] for a in result["in_scope"]]
        assert identifiers.count("api.example.com") == 1

    def test_empty_html_returns_empty_scope(self):
        scraper = ScopeScraper()
        result = scraper._parse_h1_html("", "example")
        assert result["in_scope"] == []
        assert result["out_of_scope"] == []

    def test_out_of_scope_always_empty_for_html_parse(self):
        """HTML parsing cannot distinguish out-of-scope so it stays empty."""
        scraper = ScopeScraper()
        html = "scope-target>admin.example.com"
        result = scraper._parse_h1_html(html, "example")
        assert result["out_of_scope"] == []


# ---------------------------------------------------------------------------
# TestScrapeBugcrowdPage
# ---------------------------------------------------------------------------


class TestScrapeBugcrowdPage:
    @pytest.mark.asyncio
    async def test_successful_scrape(self):
        html = 'scope">api.bugtest.com</td><target">app.bugtest.com</td>'
        mock_resp = _make_response(200, text_data=html)
        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=_make_ctx_manager(mock_resp))

        scraper = ScopeScraper(session=mock_session)
        result = await scraper.scrape_bugcrowd_page("bugtest")

        assert result["source"] == "bugcrowd_html"
        assert result["program"] == "bugtest"

    @pytest.mark.asyncio
    async def test_returns_failed_on_exception(self):
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=Exception("timeout"))

        scraper = ScopeScraper(session=mock_session)
        result = await scraper.scrape_bugcrowd_page("bugtest")

        assert result["source"] == "failed"
        assert result["in_scope"] == []


# ---------------------------------------------------------------------------
# TestParseBugcrowdHtml
# ---------------------------------------------------------------------------


class TestParseBugcrowdHtml:
    def test_extracts_domains_from_scope_pattern(self):
        scraper = ScopeScraper()
        html = 'scope">api.bugtest.com</td><scope">app.bugtest.com</td>'
        result = scraper._parse_bugcrowd_html(html, "bugtest")

        identifiers = [a["asset_identifier"] for a in result["in_scope"]]
        assert "api.bugtest.com" in identifiers
        assert "app.bugtest.com" in identifiers
        assert result["source"] == "bugcrowd_html"

    def test_extracts_domains_from_target_pattern(self):
        scraper = ScopeScraper()
        html = 'target">portal.bugtest.com</td>'
        result = scraper._parse_bugcrowd_html(html, "bugtest")

        identifiers = [a["asset_identifier"] for a in result["in_scope"]]
        assert "portal.bugtest.com" in identifiers

    def test_deduplicates_results(self):
        scraper = ScopeScraper()
        html = 'scope">api.bugtest.com</td><scope">api.bugtest.com</td>'
        result = scraper._parse_bugcrowd_html(html, "bugtest")

        identifiers = [a["asset_identifier"] for a in result["in_scope"]]
        assert identifiers.count("api.bugtest.com") == 1

    def test_all_assets_have_required_fields(self):
        scraper = ScopeScraper()
        html = 'scope">example.bugtest.com</td>'
        result = scraper._parse_bugcrowd_html(html, "bugtest")

        for asset in result["in_scope"]:
            assert "asset_identifier" in asset
            assert "asset_type" in asset
            assert "eligible_for_bounty" in asset
            assert "eligible_for_submission" in asset

    def test_close_clears_session(self):
        """close() should be callable when no session exists."""
        scraper = ScopeScraper()

        import asyncio
        asyncio.get_event_loop().run_until_complete(scraper.close())
        assert scraper._session is None

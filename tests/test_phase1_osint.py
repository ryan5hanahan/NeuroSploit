"""
Phase 1 Tests — OSINT Client Expansion

Tests all 8 new OSINT clients (mock API responses) and aggregator integration.
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.osint.base_client import OSINTClient
from backend.core.osint.securitytrails import SecurityTrailsClient
from backend.core.osint.fofa import FOFAClient
from backend.core.osint.zoomeye import ZoomEyeClient
from backend.core.osint.github_dork import GitHubDorkClient
from backend.core.osint.dehashed import DehashedClient
from backend.core.osint.hibp import HIBPClient
from backend.core.osint.grayhat_warfare import GrayhatWarfareClient
from backend.core.osint.publicwww import PublicWWWClient


@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    session = AsyncMock()
    return session


def _make_response(data, status=200):
    """Helper: build mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=data)
    return resp


def _patch_fetch(client, responses):
    """Patch _fetch_json to return responses in order."""
    call_count = {"n": 0}
    original = client._fetch_json

    async def _mock_fetch(*args, **kwargs):
        idx = call_count["n"]
        call_count["n"] += 1
        if idx < len(responses):
            return responses[idx]
        return None

    client._fetch_json = _mock_fetch


# ============================================================================
# SecurityTrails
# ============================================================================


class TestSecurityTrailsClient:
    def test_inherits_osint_client(self):
        client = SecurityTrailsClient("test-key")
        assert isinstance(client, OSINTClient)
        assert client.SERVICE_NAME == "securitytrails"

    def test_enabled(self):
        assert SecurityTrailsClient("key").enabled
        assert not SecurityTrailsClient("").enabled

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = SecurityTrailsClient("test-key")
        _patch_fetch(client, [
            {"subdomains": ["www", "api", "mail"]},
            {"records": [{"values": [{"ip": "1.2.3.4"}], "first_seen": "2020-01-01", "last_seen": "2024-01-01", "type": "a"}]},
            {"records": [{"hostname": "related.com"}]},
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["source"] == "securitytrails"
        assert "www.example.com" in result["subdomains"]
        assert len(result["dns_history"]) == 1
        assert result["associated_domains"] == ["related.com"]

    @pytest.mark.asyncio
    async def test_enrich_caches(self, mock_session):
        client = SecurityTrailsClient("test-key")
        _patch_fetch(client, [
            {"subdomains": ["www"]}, {}, {},
        ])
        r1 = await client.enrich_target("example.com", mock_session)
        # Second call should return cached
        r2 = await client.enrich_target("example.com", mock_session)
        assert r1 == r2


# ============================================================================
# FOFA
# ============================================================================


class TestFOFAClient:
    def test_dual_auth(self):
        client = FOFAClient("user@test.com", "key123")
        assert client.enabled
        assert client.email == "user@test.com"

    def test_disabled_without_both(self):
        assert not FOFAClient("", "key").enabled
        assert not FOFAClient("email", "").enabled

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = FOFAClient("user@test.com", "key123")
        _patch_fetch(client, [
            {"results": [["1.2.3.4", 80, "http", "Test Site", "nginx", "banner"]]}
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["source"] == "fofa"
        assert 80 in result["ports"]
        assert len(result["services"]) == 1


# ============================================================================
# ZoomEye
# ============================================================================


class TestZoomEyeClient:
    def test_service_name(self):
        client = ZoomEyeClient("key")
        assert client.SERVICE_NAME == "zoomeye"

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = ZoomEyeClient("key")
        _patch_fetch(client, [
            {"matches": [
                {"portinfo": {"port": 443, "service": "https", "product": "nginx", "version": "1.18", "banner": "Server: nginx"},
                 "geoinfo": {"os": "Linux"}}
            ]}
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert 443 in result["ports"]
        assert "Linux" in result["os_fingerprints"]
        assert len(result["banners"]) == 1


# ============================================================================
# GitHub Dork
# ============================================================================


class TestGitHubDorkClient:
    def test_service_name(self):
        client = GitHubDorkClient("ghp_test")
        assert client.SERVICE_NAME == "github_dork"

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = GitHubDorkClient("ghp_test")
        # Return results for first dork, None for the rest
        responses = [
            {"items": [{"repository": {"full_name": "user/repo"}, "path": ".env", "html_url": "https://github.com/user/repo/.env", "score": 1.0}]},
        ] + [None] * 11  # remaining dork patterns
        _patch_fetch(client, responses)
        result = await client.enrich_target("example.com", mock_session)
        assert result["total_leaks"] >= 1
        assert result["code_leaks"][0]["repo"] == "user/repo"


# ============================================================================
# Dehashed
# ============================================================================


class TestDehashedClient:
    def test_dual_auth(self):
        client = DehashedClient("user@test.com", "key")
        assert client.enabled
        assert not DehashedClient("", "key").enabled

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = DehashedClient("user@test.com", "key")
        _patch_fetch(client, [
            {"entries": [
                {"email": "admin@example.com", "database_name": "breach1", "password": "hash123"},
                {"email": "user@example.com", "database_name": "breach2", "hashed_password": "abc"},
            ], "total": 2}
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["source"] == "dehashed"
        assert len(result["breaches"]) == 2
        assert result["credential_count"] == 2


# ============================================================================
# HIBP
# ============================================================================


class TestHIBPClient:
    def test_rate_limit(self):
        client = HIBPClient("key")
        assert client.RATE_LIMIT_PER_SECOND == 0.1  # Very conservative

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = HIBPClient("key")
        _patch_fetch(client, [
            [{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 152445165, "DataClasses": ["Email addresses"], "IsVerified": True, "IsSensitive": False}]
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["total_breaches"] == 1
        assert result["breaches"][0]["name"] == "Adobe"
        assert result["total_pwned_accounts"] == 152445165


# ============================================================================
# GrayhatWarfare
# ============================================================================


class TestGrayhatWarfareClient:
    def test_service_name(self):
        client = GrayhatWarfareClient("key")
        assert client.SERVICE_NAME == "grayhat_warfare"

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = GrayhatWarfareClient("key")
        _patch_fetch(client, [
            # bucket search for "example.com"
            {"buckets": [{"bucket": "example-bucket", "type": "aws", "fileCount": 100, "url": "https://example-bucket.s3.amazonaws.com"}]},
            # bucket search for "example-com"
            {"buckets": []},
            # bucket search for "example"
            {"buckets": []},
            # files search
            {"files": [{"filename": "config.json", "url": "https://example-bucket.s3.amazonaws.com/config.json", "bucket": "example-bucket", "size": 1024}]},
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["total_buckets"] == 1
        assert result["exposed_buckets"][0]["provider"] == "aws"
        assert len(result.get("exposed_files", [])) == 1


# ============================================================================
# PublicWWW
# ============================================================================


class TestPublicWWWClient:
    def test_service_name(self):
        client = PublicWWWClient("key")
        assert client.SERVICE_NAME == "publicwww"

    @pytest.mark.asyncio
    async def test_enrich_target(self, mock_session):
        client = PublicWWWClient("key")
        _patch_fetch(client, [
            [{"url": "https://site1.com", "rank": 100}, {"url": "https://site2.com", "rank": 200}]
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["total_sites"] == 2
        assert result["referencing_sites"][0]["url"] == "https://site1.com"

    @pytest.mark.asyncio
    async def test_enrich_string_response(self, mock_session):
        """PublicWWW sometimes returns plain string URLs."""
        client = PublicWWWClient("key")
        _patch_fetch(client, [
            ["https://site1.com", "https://site2.com"]
        ])
        result = await client.enrich_target("example.com", mock_session)
        assert result["total_sites"] == 2


# ============================================================================
# Aggregator integration
# ============================================================================


class TestAggregatorNewClients:
    @patch.dict("os.environ", {
        "SECURITYTRAILS_API_KEY": "st-key",
        "ZOOMEYE_API_KEY": "zm-key",
        "HIBP_API_KEY": "hibp-key",
    }, clear=False)
    def test_aggregator_discovers_new_clients(self):
        from backend.core.osint.aggregator import OSINTAggregator
        agg = OSINTAggregator()
        names = agg.client_names
        assert "securitytrails" in names
        assert "zoomeye" in names
        assert "hibp" in names

    @patch.dict("os.environ", {
        "FOFA_EMAIL": "user@test.com",
        "FOFA_API_KEY": "fofa-key",
        "DEHASHED_EMAIL": "user@test.com",
        "DEHASHED_API_KEY": "dh-key",
    }, clear=False)
    def test_aggregator_dual_auth_clients(self):
        from backend.core.osint.aggregator import OSINTAggregator
        agg = OSINTAggregator()
        names = agg.client_names
        assert "fofa" in names
        assert "dehashed" in names

    @patch.dict("os.environ", {}, clear=True)
    def test_aggregator_empty_when_no_keys(self):
        from backend.core.osint.aggregator import OSINTAggregator
        agg = OSINTAggregator()
        assert not agg.enabled
        assert agg.client_names == []

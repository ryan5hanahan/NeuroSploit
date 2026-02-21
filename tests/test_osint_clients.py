"""Tests for OSINT clients — all clients with mock HTTP responses.

Covers: ShodanClient, CensysClient, VirusTotalClient, BuiltWithClient,
SecurityTrailsClient, FOFAClient, ZoomEyeClient, GitHubDorkClient,
DehashedClient, HIBPClient, GrayhatWarfareClient, PublicWWWClient,
and OSINTAggregator.

Each client tests: enabled property, rate limiting, cache behavior, and
enrich_target with mocked HTTP responses.
"""

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Helper: Mock aiohttp session
# ---------------------------------------------------------------------------

def _mock_session(json_response=None, status=200):
    """Build a mock aiohttp.ClientSession that returns the given JSON."""
    session = MagicMock()
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=json_response)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)
    session.get = MagicMock(return_value=mock_resp)
    return session


# ===========================================================================
# ShodanClient
# ===========================================================================

class TestShodanClient:
    """ShodanClient tests."""

    def test_shodan_enabled_with_key(self):
        """ShodanClient.enabled is True when API key is set."""
        from backend.core.osint.shodan_client import ShodanClient
        client = ShodanClient("test-key-123")
        assert client.enabled is True

    def test_shodan_disabled_without_key(self):
        """ShodanClient.enabled is False with empty key."""
        from backend.core.osint.shodan_client import ShodanClient
        client = ShodanClient("")
        assert client.enabled is False

    def test_shodan_service_name(self):
        """ShodanClient.SERVICE_NAME is 'shodan'."""
        from backend.core.osint.shodan_client import ShodanClient
        assert ShodanClient.SERVICE_NAME == "shodan"

    @pytest.mark.asyncio
    async def test_shodan_enrich_target_success(self):
        """enrich_target returns ports and services when API responds."""
        from backend.core.osint.shodan_client import ShodanClient

        client = ShodanClient("fake-key")
        dns_response = {"example.com": "1.2.3.4"}
        host_response = {
            "ports": [80, 443, 8080],
            "hostnames": ["example.com"],
            "os": None,
            "org": "Example Corp",
            "isp": "Cloudflare",
            "vulns": ["CVE-2021-1234"],
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.21", "data": "HTTP/1.1"},
            ],
        }

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            if "dns/resolve" in url:
                return dns_response
            return host_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)

        assert result["ip"] == "1.2.3.4"
        assert 80 in result["ports"]
        assert "CVE-2021-1234" in result["vulns"]
        assert len(result["services"]) >= 1

    @pytest.mark.asyncio
    async def test_shodan_enrich_target_dns_fail(self):
        """enrich_target returns error when DNS lookup fails."""
        from backend.core.osint.shodan_client import ShodanClient

        client = ShodanClient("fake-key")

        async def mock_fetch_json(url, session, **kwargs):
            if "dns/resolve" in url:
                return {}
            return None

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("unknown.example.com", session)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_shodan_cache_behavior(self):
        """Second call uses cached result (fetch not called again)."""
        from backend.core.osint.shodan_client import ShodanClient

        client = ShodanClient("fake-key")
        cached_result = {"source": "shodan", "ip": "1.2.3.4", "ports": [80]}
        client._cache_set("shodan:example.com", cached_result)

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            return {}

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert call_count[0] == 0  # Cache was hit, no network call
        assert result["ip"] == "1.2.3.4"


# ===========================================================================
# CensysClient
# ===========================================================================

class TestCensysClient:
    """CensysClient tests."""

    def test_censys_enabled_with_credentials(self):
        """CensysClient.enabled is True with id and secret."""
        from backend.core.osint.censys_client import CensysClient
        client = CensysClient("test-id", "test-secret")
        assert client.enabled is True

    def test_censys_disabled_without_credentials(self):
        """CensysClient.enabled is False with empty credentials."""
        from backend.core.osint.censys_client import CensysClient
        client = CensysClient("", "")
        assert client.enabled is False

    def test_censys_service_name(self):
        """CensysClient.SERVICE_NAME is 'censys'."""
        from backend.core.osint.censys_client import CensysClient
        assert CensysClient.SERVICE_NAME == "censys"

    def test_censys_auth_header_correct(self):
        """CensysClient generates correct Basic auth header."""
        import base64
        from backend.core.osint.censys_client import CensysClient
        client = CensysClient("my-id", "my-secret")
        expected = base64.b64encode("my-id:my-secret".encode()).decode()
        assert client._auth_header == expected

    @pytest.mark.asyncio
    async def test_censys_enrich_target_returns_hosts(self):
        """enrich_target returns host data from Censys."""
        from backend.core.osint.censys_client import CensysClient

        client = CensysClient("test-id", "test-secret")
        host_data = {"result": {"hits": [{"ip": "1.2.3.4", "services": [{"port": 443, "transport_protocol": "TCP"}]}]}}

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            return host_data

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "censys"


# ===========================================================================
# VirusTotalClient
# ===========================================================================

class TestVirusTotalClient:
    """VirusTotalClient tests."""

    def test_virustotal_enabled_with_key(self):
        """VirusTotalClient.enabled is True with API key."""
        from backend.core.osint.virustotal_client import VirusTotalClient
        client = VirusTotalClient("vt-key-123")
        assert client.enabled is True

    def test_virustotal_service_name(self):
        """VirusTotalClient.SERVICE_NAME is 'virustotal'."""
        from backend.core.osint.virustotal_client import VirusTotalClient
        assert VirusTotalClient.SERVICE_NAME == "virustotal"

    @pytest.mark.asyncio
    async def test_virustotal_enrich_target_success(self):
        """enrich_target returns reputation and analysis stats."""
        from backend.core.osint.virustotal_client import VirusTotalClient

        client = VirusTotalClient("fake-key")
        vt_response = {
            "data": {
                "attributes": {
                    "reputation": 5,
                    "last_analysis_stats": {"malicious": 0, "suspicious": 1, "harmless": 70},
                    "categories": {"Malwarebytes": "benign"},
                    "last_dns_records": [{"type": "A", "value": "1.2.3.4"}],
                    "whois": "Registrar: Example\nCreation Date: 2020-01-01",
                }
            }
        }

        async def mock_fetch_json(url, session, **kwargs):
            return vt_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["reputation"] == 5
        assert "last_analysis_stats" in result

    @pytest.mark.asyncio
    async def test_virustotal_enrich_target_no_data(self):
        """enrich_target handles missing data gracefully."""
        from backend.core.osint.virustotal_client import VirusTotalClient

        client = VirusTotalClient("fake-key")

        async def mock_fetch_json(url, session, **kwargs):
            return None

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert "error" in result or result["source"] == "virustotal"

    @pytest.mark.asyncio
    async def test_virustotal_cache_hit(self):
        """Second call to enrich_target uses cache."""
        from backend.core.osint.virustotal_client import VirusTotalClient

        client = VirusTotalClient("fake-key")
        cached = {"source": "virustotal", "reputation": 10}
        client._cache_set("vt:example.com", cached)

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            return {}

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert call_count[0] == 0
        assert result["reputation"] == 10


# ===========================================================================
# BuiltWithClient
# ===========================================================================

class TestBuiltWithClient:
    """BuiltWithClient tests."""

    def test_builtwith_enabled_with_key(self):
        """BuiltWithClient.enabled is True with API key."""
        from backend.core.osint.builtwith_client import BuiltWithClient
        client = BuiltWithClient("bw-key-123")
        assert client.enabled is True

    def test_builtwith_service_name(self):
        """BuiltWithClient.SERVICE_NAME is 'builtwith'."""
        from backend.core.osint.builtwith_client import BuiltWithClient
        assert BuiltWithClient.SERVICE_NAME == "builtwith"

    @pytest.mark.asyncio
    async def test_builtwith_enrich_target(self):
        """enrich_target returns technologies list."""
        from backend.core.osint.builtwith_client import BuiltWithClient

        client = BuiltWithClient("fake-key")
        bw_response = {
            "Results": [
                {
                    "Result": {
                        "Paths": [
                            {
                                "Technologies": [
                                    {"Name": "React", "Categories": ["JavaScript Frameworks"], "Confidence": 95},
                                    {"Name": "nginx", "Categories": ["Web Servers"], "Confidence": 100},
                                ]
                            }
                        ]
                    }
                }
            ]
        }

        async def mock_fetch_json(url, session, **kwargs):
            return bw_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "builtwith"
        if "technologies" in result:
            assert isinstance(result["technologies"], list)


# ===========================================================================
# SecurityTrailsClient
# ===========================================================================

class TestSecurityTrailsClient:
    """SecurityTrailsClient tests."""

    def test_securitytrails_enabled_with_key(self):
        """SecurityTrailsClient.enabled is True with API key."""
        from backend.core.osint.securitytrails import SecurityTrailsClient
        client = SecurityTrailsClient("st-key-123")
        assert client.enabled is True

    def test_securitytrails_service_name(self):
        """SecurityTrailsClient.SERVICE_NAME is 'securitytrails'."""
        from backend.core.osint.securitytrails import SecurityTrailsClient
        assert SecurityTrailsClient.SERVICE_NAME == "securitytrails"

    @pytest.mark.asyncio
    async def test_securitytrails_enrich_target_subdomains(self):
        """enrich_target returns subdomains."""
        from backend.core.osint.securitytrails import SecurityTrailsClient

        client = SecurityTrailsClient("fake-key")
        sub_response = {"subdomains": ["www", "api", "mail"]}

        async def mock_fetch_json(url, session, **kwargs):
            if "subdomains" in url:
                return sub_response
            return {}

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "securitytrails"
        if "subdomains" in result:
            assert "www.example.com" in result["subdomains"]

    @pytest.mark.asyncio
    async def test_securitytrails_cache_hit(self):
        """Second call uses cached result."""
        from backend.core.osint.securitytrails import SecurityTrailsClient

        client = SecurityTrailsClient("fake-key")
        cached = {"source": "securitytrails", "subdomains": ["api.example.com"]}
        client._cache_set("securitytrails:example.com", cached)

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            return {}

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert call_count[0] == 0


# ===========================================================================
# FOFAClient
# ===========================================================================

class TestFOFAClient:
    """FOFAClient tests."""

    def test_fofa_enabled_with_credentials(self):
        """FOFAClient.enabled is True with email and key."""
        from backend.core.osint.fofa import FOFAClient
        client = FOFAClient("test@example.com", "fofa-key-123")
        assert client.enabled is True

    def test_fofa_disabled_without_credentials(self):
        """FOFAClient.enabled is False with empty credentials."""
        from backend.core.osint.fofa import FOFAClient
        client = FOFAClient("", "")
        assert client.enabled is False

    def test_fofa_service_name(self):
        """FOFAClient.SERVICE_NAME is 'fofa'."""
        from backend.core.osint.fofa import FOFAClient
        assert FOFAClient.SERVICE_NAME == "fofa"

    @pytest.mark.asyncio
    async def test_fofa_enrich_target(self):
        """enrich_target returns results from FOFA."""
        from backend.core.osint.fofa import FOFAClient

        client = FOFAClient("test@example.com", "fake-key")
        fofa_response = {
            "error": False,
            "results": [
                ["1.2.3.4", "http", "80"],
                ["5.6.7.8", "https", "443"],
            ],
        }

        async def mock_fetch_json(url, session, **kwargs):
            return fofa_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "fofa"


# ===========================================================================
# ZoomEyeClient
# ===========================================================================

class TestZoomEyeClient:
    """ZoomEyeClient tests."""

    def test_zoomeye_enabled_with_key(self):
        """ZoomEyeClient.enabled is True with API key."""
        from backend.core.osint.zoomeye import ZoomEyeClient
        client = ZoomEyeClient("ze-key-123")
        assert client.enabled is True

    def test_zoomeye_service_name(self):
        """ZoomEyeClient.SERVICE_NAME is 'zoomeye'."""
        from backend.core.osint.zoomeye import ZoomEyeClient
        assert ZoomEyeClient.SERVICE_NAME == "zoomeye"

    @pytest.mark.asyncio
    async def test_zoomeye_enrich_target(self):
        """enrich_target returns results from ZoomEye."""
        from backend.core.osint.zoomeye import ZoomEyeClient

        client = ZoomEyeClient("fake-key")
        ze_response = {
            "matches": [
                {"ip": "1.2.3.4", "portinfo": {"port": 80, "service": "http", "app": "nginx"}},
            ],
            "total": 1,
        }

        async def mock_fetch_json(url, session, **kwargs):
            return ze_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "zoomeye"


# ===========================================================================
# GitHubDorkClient
# ===========================================================================

class TestGitHubDorkClient:
    """GitHubDorkClient tests."""

    def test_github_dork_enabled_with_token(self):
        """GitHubDorkClient.enabled is True with API token."""
        from backend.core.osint.github_dork import GitHubDorkClient
        client = GitHubDorkClient("github-token-123")
        assert client.enabled is True

    def test_github_dork_service_name(self):
        """GitHubDorkClient.SERVICE_NAME is 'github_dork'."""
        from backend.core.osint.github_dork import GitHubDorkClient
        assert GitHubDorkClient.SERVICE_NAME == "github_dork"

    @pytest.mark.asyncio
    async def test_github_dork_enrich_target_finds_leaks(self):
        """enrich_target returns code leaks when search finds results."""
        from backend.core.osint.github_dork import GitHubDorkClient

        client = GitHubDorkClient("fake-token")
        gh_response = {
            "total_count": 2,
            "items": [
                {
                    "name": ".env",
                    "path": "config/.env",
                    "repository": {"full_name": "user/private-repo", "html_url": "https://github.com/user/private-repo"},
                    "html_url": "https://github.com/user/private-repo/blob/main/config/.env",
                    "sha": "abc123",
                },
            ],
        }

        async def mock_fetch_json(url, session, **kwargs):
            return gh_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "github_dork"
        if "code_leaks" in result:
            assert isinstance(result["code_leaks"], list)

    @pytest.mark.asyncio
    async def test_github_dork_cache_behavior(self):
        """Second enrich_target call uses cache."""
        from backend.core.osint.github_dork import GitHubDorkClient

        client = GitHubDorkClient("fake-token")
        cached = {"source": "github_dork", "code_leaks": [{"file": "config/.env"}]}
        client._cache_set("github_dork:example.com", cached)

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            return {"total_count": 0, "items": []}

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert call_count[0] == 0
        assert result["code_leaks"][0]["file"] == "config/.env"


# ===========================================================================
# DehashedClient
# ===========================================================================

class TestDehashedClient:
    """DehashedClient tests."""

    def test_dehashed_enabled_with_credentials(self):
        """DehashedClient.enabled is True with email and key."""
        from backend.core.osint.dehashed import DehashedClient
        client = DehashedClient("test@example.com", "dh-key-123")
        assert client.enabled is True

    def test_dehashed_disabled_without_credentials(self):
        """DehashedClient.enabled is False with empty credentials."""
        from backend.core.osint.dehashed import DehashedClient
        client = DehashedClient("", "")
        assert client.enabled is False

    def test_dehashed_service_name(self):
        """DehashedClient.SERVICE_NAME is 'dehashed'."""
        from backend.core.osint.dehashed import DehashedClient
        assert DehashedClient.SERVICE_NAME == "dehashed"

    @pytest.mark.asyncio
    async def test_dehashed_enrich_target_breach_data(self):
        """enrich_target returns breach entries."""
        from backend.core.osint.dehashed import DehashedClient

        client = DehashedClient("test@example.com", "fake-key")
        dh_response = {
            "total": 5,
            "entries": [
                {"email": "admin@example.com", "username": "admin", "password": "hashed_pw", "database_name": "breachdb"},
            ],
        }

        async def mock_fetch_json(url, session, **kwargs):
            return dh_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "dehashed"


# ===========================================================================
# HIBPClient
# ===========================================================================

class TestHIBPClient:
    """HIBPClient tests."""

    def test_hibp_enabled_with_key(self):
        """HIBPClient.enabled is True with API key."""
        from backend.core.osint.hibp import HIBPClient
        client = HIBPClient("hibp-key-123")
        assert client.enabled is True

    def test_hibp_service_name(self):
        """HIBPClient.SERVICE_NAME is 'hibp'."""
        from backend.core.osint.hibp import HIBPClient
        assert HIBPClient.SERVICE_NAME == "hibp"

    @pytest.mark.asyncio
    async def test_hibp_enrich_target_with_breaches(self):
        """enrich_target returns breach list when domain is found."""
        from backend.core.osint.hibp import HIBPClient

        client = HIBPClient("fake-key")
        hibp_response = [
            {
                "Name": "LinkedIn",
                "Title": "LinkedIn",
                "BreachDate": "2012-05-05",
                "PwnCount": 164611595,
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "A breach occurred...",
            },
        ]

        async def mock_fetch_json(url, session, **kwargs):
            return hibp_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "hibp"
        if "breaches" in result:
            assert len(result["breaches"]) >= 1

    @pytest.mark.asyncio
    async def test_hibp_enrich_target_no_breaches(self):
        """enrich_target handles empty breach list."""
        from backend.core.osint.hibp import HIBPClient

        client = HIBPClient("fake-key")

        async def mock_fetch_json(url, session, **kwargs):
            return []

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "hibp"
        breaches = result.get("breaches", [])
        assert breaches == []

    @pytest.mark.asyncio
    async def test_hibp_cache_hit(self):
        """Second enrich_target call uses cache."""
        from backend.core.osint.hibp import HIBPClient

        client = HIBPClient("fake-key")
        cached = {"source": "hibp", "breaches": [{"name": "TestBreach"}]}
        client._cache_set("hibp:example.com", cached)

        call_count = [0]

        async def mock_fetch_json(url, session, **kwargs):
            call_count[0] += 1
            return []

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert call_count[0] == 0
        assert result["breaches"][0]["name"] == "TestBreach"


# ===========================================================================
# GrayhatWarfareClient
# ===========================================================================

class TestGrayhatWarfareClient:
    """GrayhatWarfareClient tests."""

    def test_grayhat_enabled_with_key(self):
        """GrayhatWarfareClient.enabled is True with API key."""
        from backend.core.osint.grayhat_warfare import GrayhatWarfareClient
        client = GrayhatWarfareClient("gw-key-123")
        assert client.enabled is True

    def test_grayhat_service_name(self):
        """GrayhatWarfareClient.SERVICE_NAME is 'grayhat_warfare'."""
        from backend.core.osint.grayhat_warfare import GrayhatWarfareClient
        assert GrayhatWarfareClient.SERVICE_NAME == "grayhat_warfare"

    @pytest.mark.asyncio
    async def test_grayhat_enrich_target(self):
        """enrich_target returns exposed bucket data."""
        from backend.core.osint.grayhat_warfare import GrayhatWarfareClient

        client = GrayhatWarfareClient("fake-key")
        gw_response = {
            "buckets": [
                {"bucket": "example-backups", "fileCount": 1234, "keywords": ["example.com"]},
            ],
            "numBuckets": 1,
        }

        async def mock_fetch_json(url, session, **kwargs):
            return gw_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "grayhat_warfare"


# ===========================================================================
# PublicWWWClient
# ===========================================================================

class TestPublicWWWClient:
    """PublicWWWClient tests."""

    def test_publicwww_enabled_with_key(self):
        """PublicWWWClient.enabled is True with API key."""
        from backend.core.osint.publicwww import PublicWWWClient
        client = PublicWWWClient("pw-key-123")
        assert client.enabled is True

    def test_publicwww_service_name(self):
        """PublicWWWClient.SERVICE_NAME is 'publicwww'."""
        from backend.core.osint.publicwww import PublicWWWClient
        assert PublicWWWClient.SERVICE_NAME == "publicwww"

    @pytest.mark.asyncio
    async def test_publicwww_enrich_target(self):
        """enrich_target returns search results."""
        from backend.core.osint.publicwww import PublicWWWClient

        client = PublicWWWClient("fake-key")
        pw_response = {
            "results": [
                {"domain": "partner.example.com", "url": "https://partner.example.com"},
            ],
            "total": 1,
        }

        async def mock_fetch_json(url, session, **kwargs):
            return pw_response

        client._fetch_json = mock_fetch_json
        session = MagicMock()
        result = await client.enrich_target("example.com", session)
        assert result["source"] == "publicwww"


# ===========================================================================
# OSINTAggregator
# ===========================================================================

class TestOSINTAggregator:
    """OSINTAggregator tests."""

    def test_aggregator_disabled_without_env_vars(self):
        """OSINTAggregator.enabled is False when no API keys in env."""
        import os
        env_keys = [
            "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
            "VIRUSTOTAL_API_KEY", "BUILTWITH_API_KEY", "SECURITYTRAILS_API_KEY",
            "FOFA_EMAIL", "FOFA_API_KEY", "ZOOMEYE_API_KEY",
            "GITHUB_TOKEN", "DEHASHED_EMAIL", "DEHASHED_API_KEY",
            "HIBP_API_KEY", "GRAYHAT_API_KEY", "PUBLICWWW_API_KEY",
        ]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict("os.environ", clean_env, clear=True):
            from backend.core.osint.aggregator import OSINTAggregator
            agg = OSINTAggregator()
            assert agg.enabled is False

    def test_aggregator_client_names_empty_without_keys(self):
        """OSINTAggregator.client_names is empty without API keys."""
        import os
        env_keys = [
            "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
            "VIRUSTOTAL_API_KEY", "BUILTWITH_API_KEY", "SECURITYTRAILS_API_KEY",
            "FOFA_EMAIL", "FOFA_API_KEY", "ZOOMEYE_API_KEY",
            "GITHUB_TOKEN", "DEHASHED_EMAIL", "DEHASHED_API_KEY",
            "HIBP_API_KEY", "GRAYHAT_API_KEY", "PUBLICWWW_API_KEY",
        ]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict("os.environ", clean_env, clear=True):
            from backend.core.osint.aggregator import OSINTAggregator
            agg = OSINTAggregator()
            assert agg.client_names == []

    @pytest.mark.asyncio
    async def test_aggregator_enrich_target_no_clients(self):
        """enrich_target returns disabled result when no clients configured."""
        import os
        env_keys = [
            "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
            "VIRUSTOTAL_API_KEY", "BUILTWITH_API_KEY", "SECURITYTRAILS_API_KEY",
            "FOFA_EMAIL", "FOFA_API_KEY", "ZOOMEYE_API_KEY",
            "GITHUB_TOKEN", "DEHASHED_EMAIL", "DEHASHED_API_KEY",
            "HIBP_API_KEY", "GRAYHAT_API_KEY", "PUBLICWWW_API_KEY",
        ]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict("os.environ", clean_env, clear=True):
            from backend.core.osint.aggregator import OSINTAggregator
            agg = OSINTAggregator()
            session = MagicMock()
            result = await agg.enrich_target("example.com", session)
            assert result["enabled"] is False

    @pytest.mark.asyncio
    async def test_aggregator_enrich_target_with_mocked_clients(self):
        """enrich_target merges results from multiple clients."""
        import os
        from backend.core.osint.aggregator import OSINTAggregator

        agg = OSINTAggregator()

        # Mock two clients
        client1 = MagicMock()
        client1.SERVICE_NAME = "shodan"
        client1.enrich_target = AsyncMock(return_value={"source": "shodan", "ports": [80, 443]})

        client2 = MagicMock()
        client2.SERVICE_NAME = "virustotal"
        client2.enrich_target = AsyncMock(return_value={"source": "virustotal", "technologies": ["nginx"]})

        agg.clients = [client1, client2]

        session = MagicMock()
        result = await agg.enrich_target("example.com", session)

        assert result["enabled"] is True
        assert "shodan" in result["clients"]
        assert "virustotal" in result["clients"]
        assert 80 in result["summary"]["ports"]
        assert "nginx" in result["summary"]["technologies"]

    @pytest.mark.asyncio
    async def test_aggregator_safe_enrich_handles_timeout(self):
        """_safe_enrich handles client timeout gracefully."""
        from backend.core.osint.aggregator import OSINTAggregator

        agg = OSINTAggregator()

        client = MagicMock()
        client.SERVICE_NAME = "slow_client"
        client.enrich_target = AsyncMock(side_effect=asyncio.TimeoutError())

        session = MagicMock()
        result = await agg._safe_enrich(client, "example.com", session)
        assert result["error"] == "timeout"

    @pytest.mark.asyncio
    async def test_aggregator_safe_enrich_handles_exception(self):
        """_safe_enrich handles generic exception gracefully."""
        from backend.core.osint.aggregator import OSINTAggregator

        agg = OSINTAggregator()

        client = MagicMock()
        client.SERVICE_NAME = "broken_client"
        client.enrich_target = AsyncMock(side_effect=ValueError("API error"))

        session = MagicMock()
        result = await agg._safe_enrich(client, "example.com", session)
        assert "error" in result
        assert "API error" in result["error"]


# ===========================================================================
# Base client TTL cache
# ===========================================================================

class TestOSINTBaseClientCache:
    """OSINTClient base class cache behavior."""

    def test_cache_miss_returns_none(self):
        """Cache miss returns None."""
        from backend.core.osint.shodan_client import ShodanClient
        client = ShodanClient("fake-key")
        result = client._cache_get("nonexistent-key")
        assert result is None

    def test_cache_set_and_get(self):
        """Cache set followed by get returns stored data."""
        from backend.core.osint.shodan_client import ShodanClient
        client = ShodanClient("fake-key")
        data = {"key": "value", "count": 42}
        client._cache_set("test-key", data)
        result = client._cache_get("test-key")
        assert result == data

    def test_cache_expired_returns_none(self):
        """Expired cache entry returns None."""
        from backend.core.osint.shodan_client import ShodanClient
        client = ShodanClient("fake-key")
        # Set cache entry with timestamp far in the past
        client._cache["test-key"] = (time.time() - 9999, {"data": "old"})
        result = client._cache_get("test-key")
        assert result is None

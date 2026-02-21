"""Integration tests — Tool execution against real targets.

Tests basic tool functionality with live target containers.
Marked with @pytest.mark.integration.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.mark.integration
@pytest.mark.asyncio
class TestShellToolLive:
    """Test shell tool execution against live targets."""

    async def test_nmap_scan_runs(self, check_juice_shop, juice_shop_url):
        """Verify nmap can scan the Juice Shop target."""
        import asyncio
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-p", "3000", "juice-shop",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode()
        assert "3000" in output

    async def test_curl_reaches_target(self, check_juice_shop, juice_shop_url):
        """Verify curl can reach the Juice Shop."""
        import asyncio
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", juice_shop_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        assert stdout.decode().strip() == "200"


@pytest.mark.integration
@pytest.mark.asyncio
class TestHTTPToolLive:
    """Test HTTP-based tool interactions with live targets."""

    async def test_aiohttp_get_target(self, check_juice_shop, juice_shop_url):
        """Basic aiohttp GET request to Juice Shop."""
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(juice_shop_url) as resp:
                assert resp.status == 200
                text = await resp.text()
                assert len(text) > 0

    async def test_api_endpoint_discovery(self, check_juice_shop, juice_shop_url):
        """Verify known API endpoints are discoverable."""
        import aiohttp
        endpoints = [
            "/rest/products/search?q=",
            "/api/SecurityQuestions/",
            "/rest/user/login",
        ]
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                async with session.get(f"{juice_shop_url}{endpoint}") as resp:
                    assert resp.status in (200, 401, 403), \
                        f"Unexpected status {resp.status} for {endpoint}"

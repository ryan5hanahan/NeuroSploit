"""Integration tests — Agent run against OWASP Juice Shop.

These tests require a running Juice Shop container accessible via Docker network.
Marked with @pytest.mark.integration to allow selective execution.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.mark.integration
@pytest.mark.asyncio
class TestJuiceShopReachability:
    """Basic reachability and configuration tests for Juice Shop target."""

    async def test_juice_shop_is_reachable(self, check_juice_shop, juice_shop_url):
        """Verify Juice Shop is accessible and returns HTTP 200."""
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(juice_shop_url) as resp:
                assert resp.status == 200

    async def test_juice_shop_has_rest_api(self, check_juice_shop, juice_shop_url):
        """Juice Shop should expose a REST API."""
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{juice_shop_url}/rest/products/search?q=") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert "data" in data

    async def test_juice_shop_login_endpoint(self, check_juice_shop, juice_shop_url):
        """Juice Shop should have a login endpoint."""
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{juice_shop_url}/rest/user/login",
                json={"email": "test@test.com", "password": "wrong"},
            ) as resp:
                # Should return 401 for bad credentials, not 404
                assert resp.status == 401


@pytest.mark.integration
@pytest.mark.asyncio
class TestJuiceShopBenchmarkTarget:
    """Test benchmark target definition against live Juice Shop."""

    async def test_target_objective_is_descriptive(self):
        """JuiceShopTarget objective should be a non-empty string."""
        from benchmark.targets.juice_shop import JuiceShopTarget
        target = JuiceShopTarget()
        objective = target.get_objective()
        assert isinstance(objective, str)
        assert len(objective) > 50  # Should be a descriptive objective

    async def test_target_healthcheck_url_matches_juice_shop(self, juice_shop_url):
        """Target healthcheck URL should be resolvable."""
        from benchmark.targets.juice_shop import JuiceShopTarget
        target = JuiceShopTarget()
        url = target.get_healthcheck_url()
        assert "3000" in url or "juice" in url

    async def test_ground_truth_file_exists(self):
        """Ground truth YAML should exist at the path specified by the target."""
        from benchmark.targets.juice_shop import JuiceShopTarget
        target = JuiceShopTarget()
        gt_path = target.get_ground_truth_path()
        assert Path(gt_path).exists(), f"Ground truth file not found: {gt_path}"

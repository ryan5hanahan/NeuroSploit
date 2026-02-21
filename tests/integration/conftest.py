"""Integration test fixtures — resolve target URLs from Docker network."""
import os
import sys
from pathlib import Path

import pytest
import aiohttp

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture
def juice_shop_url():
    """Resolve Juice Shop URL from Docker network or env var."""
    return os.environ.get("JUICE_SHOP_URL", "http://juice-shop:3000")


@pytest.fixture
def dvwa_url():
    """Resolve DVWA URL from Docker network or env var."""
    return os.environ.get("DVWA_URL", "http://dvwa:80")


@pytest.fixture
async def check_juice_shop(juice_shop_url):
    """Skip test if Juice Shop is not reachable."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(juice_shop_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    pytest.skip(f"Juice Shop not reachable at {juice_shop_url}")
    except Exception:
        pytest.skip(f"Juice Shop not reachable at {juice_shop_url}")


@pytest.fixture
async def check_dvwa(dvwa_url):
    """Skip test if DVWA is not reachable."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(dvwa_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    pytest.skip(f"DVWA not reachable at {dvwa_url}")
    except Exception:
        pytest.skip(f"DVWA not reachable at {dvwa_url}")

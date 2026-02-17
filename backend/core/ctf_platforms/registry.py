"""
Platform Registry — auto-detection and lookup for CTF platform adapters.

Usage:
    adapter = await detect_platform(target, session)   # auto-detect
    adapter = get_adapter("juice_shop")                # explicit lookup
"""
from typing import Dict, Optional, Type

import aiohttp

from backend.core.ctf_platforms.base import CTFPlatformAdapter
from backend.core.ctf_platforms.juice_shop import JuiceShopAdapter


# All registered adapters, keyed by platform_name.
# Add new platforms here as they are implemented.
_ADAPTERS: Dict[str, Type[CTFPlatformAdapter]] = {
    JuiceShopAdapter.platform_name: JuiceShopAdapter,
}


def get_adapter(platform_name: str) -> Optional[CTFPlatformAdapter]:
    """Return an instantiated adapter by name, or None if unknown."""
    cls = _ADAPTERS.get(platform_name)
    return cls() if cls else None


async def detect_platform(
    target: str, session: aiohttp.ClientSession
) -> Optional[CTFPlatformAdapter]:
    """Probe the target and return the first matching platform adapter.

    Iterates through registered adapters and returns the first one whose
    ``detect()`` method returns True.  Returns None if no platform matches.
    """
    for cls in _ADAPTERS.values():
        adapter = cls()
        try:
            if await adapter.detect(target, session):
                return adapter
        except Exception:
            continue
    return None

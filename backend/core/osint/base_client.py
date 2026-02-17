"""
OSINT Base Client — ABC for all OSINT API integrations.

Provides: rate limiting, TTL cache, standard interface.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)


class OSINTClient(ABC):
    """Abstract base class for OSINT API clients."""

    # Subclasses override these
    SERVICE_NAME: str = "osint"
    RATE_LIMIT_PER_SECOND: float = 1.0
    CACHE_TTL_SECONDS: int = 3600  # 1 hour

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: Dict[str, tuple] = {}  # key -> (timestamp, data)
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def _rate_limit(self):
        """Enforce per-service rate limiting."""
        async with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / self.RATE_LIMIT_PER_SECOND
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_time = time.monotonic()

    def _cache_get(self, key: str) -> Optional[Any]:
        """Get from TTL cache, returns None if expired or missing."""
        if key in self._cache:
            ts, data = self._cache[key]
            if time.time() - ts < self.CACHE_TTL_SECONDS:
                return data
            del self._cache[key]
        return None

    def _cache_set(self, key: str, data: Any):
        """Store in TTL cache."""
        self._cache[key] = (time.time(), data)

    async def _fetch_json(
        self,
        url: str,
        session: aiohttp.ClientSession,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Rate-limited JSON GET request."""
        await self._rate_limit()
        try:
            async with session.get(
                url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=30), ssl=False
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                logger.warning(f"{self.SERVICE_NAME} API returned {resp.status} for {url}")
                return None
        except Exception as e:
            logger.warning(f"{self.SERVICE_NAME} API error: {e}")
            return None

    @abstractmethod
    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Enrich a target domain with OSINT data.

        Returns a dict with service-specific keys.
        """
        ...

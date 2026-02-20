"""Platform registry — singleton registry for bug bounty providers.

New platforms just add a line in init_platforms(). No governance code changes.
"""

import logging
from typing import Optional

from backend.core.bugbounty.provider import BugBountyProvider

logger = logging.getLogger(__name__)


class PlatformRegistry:
    """Registry of bug bounty platform providers."""

    def __init__(self):
        self._providers: dict[str, BugBountyProvider] = {}

    def register(self, name: str, provider: BugBountyProvider) -> None:
        """Register a provider by platform name."""
        self._providers[name] = provider
        logger.info(f"Registered bug bounty provider: {name}")

    def get(self, name: str) -> Optional[BugBountyProvider]:
        """Get a provider by name, or None."""
        return self._providers.get(name)

    def list_platforms(self) -> list[str]:
        """Return all registered platform names."""
        return list(self._providers.keys())

    def get_enabled(self) -> dict[str, BugBountyProvider]:
        """Return only providers with valid credentials."""
        return {
            name: p for name, p in self._providers.items() if p.enabled
        }


# Module-level singleton
_registry = PlatformRegistry()


def get_platform_registry() -> PlatformRegistry:
    """Return the singleton PlatformRegistry instance."""
    return _registry


def init_platforms() -> None:
    """Initialize and register all platform providers.

    Called once at application startup. To add a new platform,
    import and register it here.
    """
    from backend.core.bugbounty.hackerone_provider import HackerOneProvider
    _registry.register("hackerone", HackerOneProvider())
    logger.info(f"Bug bounty platforms initialized: {_registry.list_platforms()}")

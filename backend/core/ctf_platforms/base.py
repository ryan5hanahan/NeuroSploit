"""
CTFPlatformAdapter — abstract base class for CTF platform integrations.

Each platform (Juice Shop, HackTheBox, etc.) implements this interface
so the CTFCoordinator can remain platform-agnostic.
"""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import aiohttp


@dataclass
class ChallengeInfo:
    """Normalized representation of a CTF challenge."""
    challenge_id: Any
    name: str
    category: str = "unknown"
    difficulty: int = 0
    solved: bool = False
    max_difficulty: int = 6  # platform-specific scale


class CTFPlatformAdapter(ABC):
    """Interface for platform-specific CTF behavior.

    Subclasses provide:
      - Detection: can we identify this target as platform X?
      - Challenge tracking: poll solved state, register newly solved
      - Platform-specific probes: exploit methods unique to the platform
      - Platform-specific paths, credentials, and field names
    """

    platform_name: str = "generic"

    @abstractmethod
    async def detect(self, target: str, session: aiohttp.ClientSession) -> bool:
        """Return True if the target is identified as this platform."""
        ...

    # ------------------------------------------------------------------
    # Challenge tracking
    # ------------------------------------------------------------------

    @abstractmethod
    async def poll_challenges(
        self, target: str, session: aiohttp.ClientSession
    ) -> Dict[Any, ChallengeInfo]:
        """Fetch current challenge state from the platform.

        Returns a dict keyed by challenge_id -> ChallengeInfo.
        Empty dict if the platform has no challenge API.
        """
        ...

    def get_solved_ids(self, challenges: Dict[Any, ChallengeInfo]) -> Set[Any]:
        """Extract IDs of solved challenges from a poll result."""
        return {cid for cid, c in challenges.items() if c.solved}

    def difficulty_to_severity(self, difficulty: int) -> str:
        """Map platform difficulty to finding severity. Override per-platform."""
        return "medium"

    # ------------------------------------------------------------------
    # Platform-specific content
    # ------------------------------------------------------------------

    def get_platform_credentials(self) -> List[Tuple[str, str]]:
        """Return (username, password) pairs specific to this platform.

        These are prepended to the generic credential list during testing.
        """
        return []

    def get_platform_login_paths(self) -> List[str]:
        """Return login/auth endpoint paths specific to this platform.

        Paths are relative (e.g., '/rest/user/login').
        """
        return []

    def get_platform_api_paths(self) -> List[str]:
        """Return API endpoint paths specific to this platform.

        Used for authenticated admin probes. Paths are relative.
        """
        return []

    def get_platform_hidden_paths(self) -> List[str]:
        """Return hidden page paths specific to this platform (SPA routes, etc.)."""
        return []

    def get_platform_search_paths(self) -> List[str]:
        """Return search endpoint paths specific to this platform."""
        return []

    def get_platform_field_names(self) -> Dict[str, List[str]]:
        """Return field name variants for common entities.

        Example: {"product_id": ["ProductId", "product_id", "productId"]}
        Used for building payloads against platform-specific schemas.
        """
        return {}

    # ------------------------------------------------------------------
    # Platform-specific probes
    # ------------------------------------------------------------------

    async def run_platform_probes(
        self,
        session: aiohttp.ClientSession,
        target: str,
        auth_headers: Dict[str, str],
        log_callback: Callable,
        recon_data: Any = None,
    ) -> List[Dict]:
        """Run exploit probes specific to this platform.

        Returns a list of finding dicts. Default: no platform-specific probes.
        """
        return []

    async def run_platform_browser_probes(
        self,
        validator: Any,
        target: str,
        log_callback: Callable,
    ) -> List[Dict]:
        """Run browser-based probes specific to this platform.

        Returns a list of finding dicts. Default: no platform-specific browser probes.
        """
        return []

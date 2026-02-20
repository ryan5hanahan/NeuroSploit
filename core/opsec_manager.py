"""
sploit.ai - Opsec Profile Manager

Provides per-scan opsec posture control. Three built-in profiles:
  - stealth:    Low-and-slow, proxy routing, jitter, header randomization
  - balanced:   Moderate speed, good default for most engagements
  - aggressive: Maximum speed, use only on owned targets

Profiles map tool names to CLI flag overrides plus global settings
(jitter, proxy routing, DNS-over-HTTPS, etc.).

Usage:
    opsec = OpsecManager()
    flags = opsec.build_flag_args("nuclei", "stealth")
    # => ['-rate-limit', '10', '-concurrency', '2', '-timeout', '900', '-headless']
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Flags passed as bare flags (no value) when set to True
_BARE_FLAGS = {"headless", "random-agent", "silent", "no-color"}

# nmap uses a special flag format: -T2 instead of -T 2
_NMAP_COMBINED_FLAGS = {"-T"}


class OpsecManager:
    """Loads opsec profiles and produces CLI flag lists for sandbox tools."""

    def __init__(
        self,
        profiles_path: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        self._profiles_path = profiles_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config", "opsec_profiles.json"
        )
        self._config_path = config_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config", "config.json"
        )
        self._profiles: Dict[str, Any] = {}
        self._default_profile: str = "balanced"
        self._load()

    def _load(self):
        """Load profiles JSON and resolve the default from config."""
        # Load profiles
        try:
            with open(self._profiles_path) as f:
                data = json.load(f)
            self._profiles = data.get("profiles", {})
        except Exception as e:
            logger.warning(f"Could not load opsec profiles from {self._profiles_path}: {e}")
            self._profiles = {}

        # Resolve default profile from config.json
        try:
            with open(self._config_path) as f:
                cfg = json.load(f)
            self._default_profile = (
                cfg.get("opsec", {}).get("default_profile", "balanced")
            )
        except Exception:
            self._default_profile = "balanced"

    def _resolve_profile(self, profile_name: Optional[str] = None) -> str:
        """Resolve profile name, falling back to configured default."""
        name = profile_name or self._default_profile
        if name not in self._profiles:
            logger.warning(
                f"Opsec profile '{name}' not found, falling back to 'balanced'"
            )
            name = "balanced"
        return name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_tool_flags(self, tool: str, profile_name: Optional[str] = None) -> Dict:
        """Get the raw flag dict for a tool under a profile.

        Returns empty dict if tool has no overrides in the profile.
        """
        name = self._resolve_profile(profile_name)
        profile = self._profiles.get(name, {})
        return dict(profile.get("tools", {}).get(tool, {}))

    def build_flag_args(
        self, tool: str, profile_name: Optional[str] = None
    ) -> List[str]:
        """Build a CLI args list from the profile flags for a tool.

        Handles bare flags (e.g. --headless), nmap combined flags (-T2),
        and standard key-value flags (-rate-limit 10).
        """
        flags = self.get_tool_flags(tool, profile_name)
        args: List[str] = []

        for key, value in flags.items():
            flag = key if key.startswith("-") else f"-{key}"

            # nmap combined flags: -T2 instead of -T 2
            if flag in _NMAP_COMBINED_FLAGS:
                args.append(f"{flag}{value}")
                continue

            # Bare flags: --headless, --random-agent
            if key in _BARE_FLAGS:
                if value:
                    args.append(f"-{key}")
                continue

            # Standard key-value
            args.extend([flag, str(value)])

        return args

    def get_global_settings(self, profile_name: Optional[str] = None) -> Dict:
        """Get the global settings dict for a profile."""
        name = self._resolve_profile(profile_name)
        profile = self._profiles.get(name, {})
        return dict(profile.get("global", {}))

    def should_use_proxy(self, profile_name: Optional[str] = None) -> bool:
        """Check if the profile enables proxy routing.

        Returns True for 'auto' (use if proxy is up) or explicit True.
        """
        settings = self.get_global_settings(profile_name)
        routing = settings.get("proxy_routing", "off")
        return routing in ("auto", True, "true")

    def get_jitter_range(
        self, profile_name: Optional[str] = None
    ) -> Tuple[float, float]:
        """Get the (min, max) jitter range in seconds for a profile.

        Returns (0.0, 0.0) if no jitter configured.
        """
        settings = self.get_global_settings(profile_name)
        jitter_ms = settings.get("request_jitter_ms", [0, 0])
        if isinstance(jitter_ms, list) and len(jitter_ms) == 2:
            return (jitter_ms[0] / 1000.0, jitter_ms[1] / 1000.0)
        return (0.0, 0.0)

    def merge_flags(
        self, profile_flags: Dict, user_flags: Dict
    ) -> Dict:
        """Merge profile flags with user-provided flags. User flags win."""
        merged = dict(profile_flags)
        merged.update(user_flags)
        return merged

    @property
    def default_profile(self) -> str:
        return self._default_profile

    @property
    def available_profiles(self) -> List[str]:
        return list(self._profiles.keys())

    def profile_description(self, profile_name: Optional[str] = None) -> str:
        """Get the human-readable description of a profile."""
        name = self._resolve_profile(profile_name)
        profile = self._profiles.get(name, {})
        return profile.get("description", "")

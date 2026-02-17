"""
CTF Platform Adapters — pluggable platform detection and challenge tracking.

Each adapter implements CTFPlatformAdapter for a specific CTF platform
(Juice Shop, HackTheBox, etc.), providing platform-specific:
  - Challenge polling and solved-state tracking
  - Default credentials
  - Known URL paths and API endpoints
  - Platform-specific exploit probes
"""
from backend.core.ctf_platforms.base import CTFPlatformAdapter
from backend.core.ctf_platforms.juice_shop import JuiceShopAdapter
from backend.core.ctf_platforms.registry import detect_platform, get_adapter

__all__ = [
    "CTFPlatformAdapter",
    "JuiceShopAdapter",
    "detect_platform",
    "get_adapter",
]

"""
sploit.ai - Bug Bounty Integration

Read-only HackerOne integration + scope parsing + duplicate detection.
Multi-platform provider abstraction + governance bridge.
No auto-submission.
"""

from backend.core.bugbounty.hackerone_client import HackerOneClient
from backend.core.bugbounty.scope_parser import ScopeParser, ScopeRule
from backend.core.bugbounty.duplicate_detector import DuplicateDetector
from backend.core.bugbounty.report_formatter import H1ReportFormatter
from backend.core.bugbounty.registry import get_platform_registry, init_platforms

__all__ = [
    "HackerOneClient",
    "ScopeParser",
    "ScopeRule",
    "DuplicateDetector",
    "H1ReportFormatter",
    "get_platform_registry",
    "init_platforms",
]

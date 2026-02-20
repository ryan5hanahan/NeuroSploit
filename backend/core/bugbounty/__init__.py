"""
NeuroSploit v3 - Bug Bounty Integration (MVP)

Read-only HackerOne integration + scope parsing + duplicate detection.
No auto-submission.
"""

from backend.core.bugbounty.hackerone_client import HackerOneClient
from backend.core.bugbounty.scope_parser import ScopeParser, ScopeRule
from backend.core.bugbounty.duplicate_detector import DuplicateDetector
from backend.core.bugbounty.report_formatter import H1ReportFormatter

__all__ = ["HackerOneClient", "ScopeParser", "ScopeRule", "DuplicateDetector", "H1ReportFormatter"]

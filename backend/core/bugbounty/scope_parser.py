"""
Bug Bounty Scope Parser — Parse in-scope/out-of-scope assets into URL matching rules.
"""

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ScopeRule:
    """A single scope rule derived from a bug bounty program."""
    pattern: str  # The asset identifier (domain, wildcard, URL, IP range)
    asset_type: str  # "URL", "DOMAIN", "WILDCARD", "IP_ADDRESS", "CIDR", etc.
    in_scope: bool = True
    eligible_for_bounty: bool = False
    max_severity: str = ""
    instruction: str = ""


class ScopeParser:
    """Parses bug bounty scope data into URL-matching rules."""

    def __init__(self, scope_data: dict):
        """
        Args:
            scope_data: Dict with "in_scope" and "out_of_scope" lists
                        from HackerOneClient.get_scope()
        """
        self.rules: List[ScopeRule] = []
        self._parse(scope_data)

    def _parse(self, scope_data: dict):
        """Parse scope data into rules."""
        for asset in scope_data.get("in_scope", []):
            self.rules.append(ScopeRule(
                pattern=asset.get("asset_identifier", ""),
                asset_type=asset.get("asset_type", "URL"),
                in_scope=True,
                eligible_for_bounty=asset.get("eligible_for_bounty", False),
                max_severity=asset.get("max_severity", ""),
                instruction=asset.get("instruction", ""),
            ))

        for asset in scope_data.get("out_of_scope", []):
            self.rules.append(ScopeRule(
                pattern=asset.get("asset_identifier", ""),
                asset_type=asset.get("asset_type", "URL"),
                in_scope=False,
            ))

        logger.info(
            f"Scope parser loaded {len(self.rules)} rules "
            f"({sum(1 for r in self.rules if r.in_scope)} in-scope, "
            f"{sum(1 for r in self.rules if not r.in_scope)} out-of-scope)"
        )

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in scope.

        Out-of-scope rules take precedence over in-scope rules.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check out-of-scope first (takes precedence)
        for rule in self.rules:
            if not rule.in_scope and self._matches(hostname, url, rule):
                return False

        # Check in-scope
        for rule in self.rules:
            if rule.in_scope and self._matches(hostname, url, rule):
                return True

        # Default: not in scope if no rules match
        return False

    def get_in_scope_domains(self) -> List[str]:
        """Get list of in-scope domain patterns."""
        return [r.pattern for r in self.rules if r.in_scope]

    def get_bounty_eligible_domains(self) -> List[str]:
        """Get domains eligible for bounty."""
        return [r.pattern for r in self.rules if r.in_scope and r.eligible_for_bounty]

    def _matches(self, hostname: str, url: str, rule: ScopeRule) -> bool:
        """Check if a hostname/URL matches a scope rule."""
        pattern = rule.pattern.lower().strip()
        hostname = hostname.lower()

        if not pattern:
            return False

        # Wildcard patterns (*.example.com)
        if pattern.startswith("*."):
            base = pattern[2:]
            return hostname == base or hostname.endswith("." + base)

        # URL patterns
        if pattern.startswith("http://") or pattern.startswith("https://"):
            parsed_pattern = urlparse(pattern)
            pattern_host = (parsed_pattern.hostname or "").lower()
            if pattern_host and not self._host_matches(hostname, pattern_host):
                return False
            # If pattern has a path, check URL path
            if parsed_pattern.path and parsed_pattern.path != "/":
                return url.lower().startswith(pattern.lower())
            return True

        # Domain patterns
        if self._host_matches(hostname, pattern):
            return True

        # Glob-style matching as fallback
        return fnmatch.fnmatch(hostname, pattern)

    @staticmethod
    def _host_matches(hostname: str, pattern: str) -> bool:
        """Check if hostname matches a pattern (exact or subdomain)."""
        pattern = pattern.lower().rstrip("/")
        hostname = hostname.lower()
        return hostname == pattern or hostname.endswith("." + pattern)

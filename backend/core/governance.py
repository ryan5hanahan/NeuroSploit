"""
sploit.ai - Governance Agent

Scope enforcement for agent and sub-agent tasks. Ensures all scans stay
within the boundaries of the requested operation — targets, tactics, and
techniques are enforced at the data level, not just the prompt level.

Pattern: same as StrategyAdapter — initialized in constructor, passed to
agent, consulted via method calls. No separate process, no MCP server.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vuln-type → Nuclei template tag mapping
# ---------------------------------------------------------------------------
_VULN_TYPE_TO_NUCLEI_TAG: Dict[str, str] = {
    # Injection
    "sqli_error": "sqli", "sqli_union": "sqli", "sqli_blind": "sqli",
    "sqli_time": "sqli", "nosql_injection": "nosqli",
    "ldap_injection": "ldap", "xpath_injection": "xpathi",
    "command_injection": "rce", "ssti": "ssti",
    "soap_injection": "injection",
    # XSS
    "xss_reflected": "xss", "xss_stored": "xss", "xss_dom": "xss",
    "blind_xss": "xss", "css_injection": "xss",
    # File / path
    "lfi": "lfi", "rfi": "rfi", "path_traversal": "lfi",
    "file_upload": "fileupload", "arbitrary_file_read": "lfi",
    # SSRF / XXE
    "ssrf": "ssrf", "ssrf_cloud": "ssrf", "xxe": "xxe",
    # Auth / session
    "auth_bypass": "auth-bypass", "jwt_manipulation": "jwt",
    "session_fixation": "session", "csrf": "csrf",
    "privilege_escalation": "auth-bypass",
    "bola": "idor", "bfla": "idor", "idor": "idor",
    "mass_assignment": "idor",
    # Deserialization / RCE
    "insecure_deserialization": "deserialization",
    # Misconfig / info
    "cors_misconfig": "cors", "security_headers": "misconfig",
    "ssl_issues": "ssl", "http_methods": "misconfig",
    "directory_listing": "exposure", "debug_mode": "misconfig",
    "exposed_admin_panel": "exposure", "exposed_api_docs": "exposure",
    "insecure_cookie_flags": "misconfig",
    "http_smuggling": "smuggling", "cache_poisoning": "misconfig",
    "open_redirect": "redirect",
    # Logic / data
    "host_header_injection": "header-injection",
    "subdomain_takeover": "takeover",
    "sensitive_data_exposure": "exposure",
    "information_disclosure": "exposure",
    "api_key_exposure": "exposure",
    "source_code_disclosure": "exposure",
    "backup_file_exposure": "exposure",
    # Cloud / API
    "s3_bucket_misconfiguration": "aws", "cloud_metadata_exposure": "cloud",
    "graphql_introspection": "graphql", "graphql_dos": "graphql",
    # Supply chain
    "vulnerable_dependency": "cve", "outdated_component": "cve",
}


class ScopeProfile(str, Enum):
    """Scope profile — determines baseline restrictiveness."""
    VULN_LAB = "vuln_lab"
    FULL_AUTO = "full_auto"
    RECON_ONLY = "recon_only"
    CTF = "ctf"
    CUSTOM = "custom"


@dataclass(frozen=True)
class ScanScope:
    """Immutable scope definition — once created, cannot be altered by agent code."""
    profile: ScopeProfile
    allowed_domains: FrozenSet[str]
    allowed_vuln_types: FrozenSet[str]   # Empty = all allowed
    allowed_phases: FrozenSet[str]       # Empty = all allowed
    skip_subdomain_enum: bool = False
    skip_port_scan: bool = False
    max_recon_depth: str = "medium"      # "quick" | "medium" | "full"
    nuclei_template_tags: Optional[str] = None
    include_subdomains: bool = True      # *.example.com in scope if example.com allowed
    allowed_cidrs: FrozenSet[str] = frozenset()  # CIDR ranges (e.g. "192.168.1.0/24")


@dataclass
class _Violation:
    """Record of a governance enforcement action."""
    timestamp: float
    method: str
    detail: str


class GovernanceAgent:
    """Lightweight enforcement layer consulted at key decision points.

    All methods are no-ops when the scope is fully permissive (empty
    allow-lists = everything allowed). Violations are recorded for the
    final audit trail in the report.
    """

    def __init__(
        self,
        scope: ScanScope,
        log_callback: Optional[Callable] = None,
    ):
        self.scope = scope
        self._log = log_callback
        self._violations: List[_Violation] = []
        self._start_time = time.time()

    async def _emit(self, level: str, msg: str):
        if self._log:
            await self._log(level, msg)

    def _record(self, method: str, detail: str):
        self._violations.append(_Violation(
            timestamp=time.time(),
            method=method,
            detail=detail,
        ))

    # ------------------------------------------------------------------
    # Enforcement methods
    # ------------------------------------------------------------------

    def filter_vuln_types(self, vuln_types: List[str]) -> List[str]:
        """Whitelist filter on vulnerability type list.

        Called at _test_all_vulnerabilities() as the critical backstop.
        """
        if not self.scope.allowed_vuln_types:
            return vuln_types  # No restriction

        original_count = len(vuln_types)
        filtered = [vt for vt in vuln_types if vt in self.scope.allowed_vuln_types]

        blocked = original_count - len(filtered)
        if blocked > 0:
            self._record("filter_vuln_types",
                         f"Blocked {blocked}/{original_count} types, "
                         f"allowed: {sorted(self.scope.allowed_vuln_types)}")
        return filtered

    def scope_attack_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Filter priority_vulns in an attack plan dict.

        Called after _ai_analyze_attack_surface() and on the default plan.
        Ensures the allowed types are always present in the plan even if
        the AI omitted them.
        """
        if not self.scope.allowed_vuln_types:
            return plan

        original = plan.get("priority_vulns", [])
        filtered = [vt for vt in original if vt in self.scope.allowed_vuln_types]

        # Ensure every allowed type is present
        for vt in self.scope.allowed_vuln_types:
            if vt not in filtered:
                filtered.append(vt)

        blocked = len(original) - len([vt for vt in original if vt in self.scope.allowed_vuln_types])
        if blocked > 0:
            self._record("scope_attack_plan",
                         f"Scoped plan from {len(original)} to {len(filtered)} types")

        plan = dict(plan)  # shallow copy
        plan["priority_vulns"] = filtered
        return plan

    def constrain_analysis_prompt(self, prompt: str) -> str:
        """Append scope constraint to the AI analysis prompt.

        Called in _ai_analyze_attack_surface() before sending to LLM.
        """
        if not self.scope.allowed_vuln_types:
            return prompt

        types_str = ", ".join(sorted(self.scope.allowed_vuln_types))
        constraint = (
            f"\n\n## SCOPE CONSTRAINT (MANDATORY)\n"
            f"This scan is scoped to ONLY the following vulnerability types: {types_str}\n"
            f"Your priority_vulns list MUST contain ONLY these types. "
            f"Do NOT include any other vulnerability types."
        )
        return prompt + constraint

    def should_port_scan(self) -> bool:
        """Whether Naabu port scan should run."""
        return not self.scope.skip_port_scan

    def should_enumerate_subdomains(self) -> bool:
        """Whether subdomain enumeration should run."""
        return not self.scope.skip_subdomain_enum

    def get_nuclei_template_tags(self) -> Optional[str]:
        """Return Nuclei template tags for scoping, or None for all."""
        return self.scope.nuclei_template_tags

    def is_url_in_scope(self, url: str) -> bool:
        """Check if a URL's domain (and port, if scoped) is within scope.

        Supports:
          - Exact domain match
          - Subdomain inheritance (*.example.com if include_subdomains=True)
          - CIDR range matching for IP-based targets
          - Host:port matching
        """
        if not self.scope.allowed_domains and not self.scope.allowed_cidrs:
            return True
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = parsed.hostname or ""
            netloc = parsed.netloc or ""

            # 1. Exact domain or netloc match
            if host in self.scope.allowed_domains or netloc in self.scope.allowed_domains:
                return True

            # 2. Subdomain inheritance: foo.bar.example.com matches example.com
            if self.scope.include_subdomains and host:
                for domain in self.scope.allowed_domains:
                    if host.endswith(f".{domain}"):
                        return True

            # 3. CIDR matching for IP-based targets
            if self.scope.allowed_cidrs and host:
                import ipaddress as _ipaddr
                try:
                    target_ip = _ipaddr.ip_address(host)
                    for cidr in self.scope.allowed_cidrs:
                        try:
                            if target_ip in _ipaddr.ip_network(cidr, strict=False):
                                return True
                        except ValueError:
                            continue
                except ValueError:
                    pass  # host is not an IP address

            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Audit / reporting
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        """Summary dict for inclusion in the final report."""
        return {
            "scope_profile": self.scope.profile.value,
            "allowed_vuln_types": sorted(self.scope.allowed_vuln_types) if self.scope.allowed_vuln_types else "all",
            "allowed_domains": sorted(self.scope.allowed_domains) if self.scope.allowed_domains else "all",
            "skip_subdomain_enum": self.scope.skip_subdomain_enum,
            "skip_port_scan": self.scope.skip_port_scan,
            "max_recon_depth": self.scope.max_recon_depth,
            "nuclei_template_tags": self.scope.nuclei_template_tags,
            "violations_count": len(self._violations),
            "violations": [
                {"method": v.method, "detail": v.detail}
                for v in self._violations
            ],
        }


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract hostname from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def _has_explicit_port(url: str) -> bool:
    """Check if the URL contains an explicit (non-default) port."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.port is None:
        return False
    # 80 and 443 are defaults — not explicit
    return not (
        (parsed.scheme == "http" and parsed.port == 80) or
        (parsed.scheme == "https" and parsed.port == 443)
    )


def _extract_netloc(url: str) -> str:
    """Extract host:port from a URL (port included only if non-default)."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc or parsed.hostname or url


def _nuclei_tags_for_vuln_type(vuln_type: str) -> Optional[str]:
    """Map a vuln_type to the corresponding Nuclei template tag."""
    return _VULN_TYPE_TO_NUCLEI_TAG.get(vuln_type)


def _scope_domains(target_url: str) -> FrozenSet[str]:
    """Build allowed_domains set: include netloc when port is explicit."""
    domain = _extract_domain(target_url)
    if _has_explicit_port(target_url):
        netloc = _extract_netloc(target_url)
        return frozenset({domain, netloc})
    return frozenset({domain})


def create_vuln_lab_scope(target_url: str, vuln_type: str) -> ScanScope:
    """Tight scope for VulnLab single-vulnerability tests."""
    return ScanScope(
        profile=ScopeProfile.VULN_LAB,
        allowed_domains=_scope_domains(target_url),
        allowed_vuln_types=frozenset({vuln_type}),
        allowed_phases=frozenset(),  # all phases allowed (recon needed to find endpoints)
        skip_subdomain_enum=True,
        skip_port_scan=True,
        max_recon_depth="quick",
        nuclei_template_tags=_nuclei_tags_for_vuln_type(vuln_type),
    )


def create_full_auto_scope(target_url: "str | list[str]") -> ScanScope:
    """Permissive scope for full-auto scans — all types, same-domain.

    Accepts a single URL or a list of URLs. If any target URL includes an
    explicit port (e.g. :33000), testing is scoped to that port only and
    port scanning / subdomain enum is skipped.
    """
    urls = [target_url] if isinstance(target_url, str) else target_url
    all_domains: set = set()
    any_explicit_port = False
    for u in urls:
        all_domains.update(_scope_domains(u))
        if _has_explicit_port(u):
            any_explicit_port = True
    return ScanScope(
        profile=ScopeProfile.FULL_AUTO,
        allowed_domains=frozenset(all_domains),
        allowed_vuln_types=frozenset(),  # all allowed
        allowed_phases=frozenset(),      # all allowed
        skip_subdomain_enum=any_explicit_port,
        skip_port_scan=any_explicit_port,
        max_recon_depth="full",
        nuclei_template_tags=None,
    )


def create_ctf_scope(target_url: "str | list[str]") -> ScanScope:
    """Permissive scope for CTF challenges — all vuln types, medium recon."""
    urls = [target_url] if isinstance(target_url, str) else target_url
    all_domains: set = set()
    for u in urls:
        all_domains.update(_scope_domains(u))
    return ScanScope(
        profile=ScopeProfile.CTF,
        allowed_domains=frozenset(all_domains),
        allowed_vuln_types=frozenset(),   # empty = ALL types allowed
        allowed_phases=frozenset(),       # all phases allowed
        skip_subdomain_enum=True,
        skip_port_scan=True,
        max_recon_depth="medium",
        nuclei_template_tags=None,        # run all Nuclei templates
    )


def create_recon_only_scope(target_url: "str | list[str]") -> ScanScope:
    """Recon-only scope — no vulnerability testing phases."""
    urls = [target_url] if isinstance(target_url, str) else target_url
    all_domains: set = set()
    any_explicit_port = False
    for u in urls:
        all_domains.update(_scope_domains(u))
        if _has_explicit_port(u):
            any_explicit_port = True
    return ScanScope(
        profile=ScopeProfile.RECON_ONLY,
        allowed_domains=frozenset(all_domains),
        allowed_vuln_types=frozenset(),
        allowed_phases=frozenset({"recon", "report"}),
        skip_subdomain_enum=any_explicit_port,
        skip_port_scan=any_explicit_port,
        max_recon_depth="full",
        nuclei_template_tags=None,
    )

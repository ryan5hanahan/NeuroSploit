"""
NeuroSploit v3 - Governance Scope Enforcement

Centralized enforcement layer that prevents phase-inappropriate actions.
Example: exploitation MUST NOT be attempted during a recon task.

Components:
  - ActionCategory: Enum of action classification levels
  - ActionClassifier: Maps tools/methods to action categories
  - PhasePolicy: Defines what each phase is allowed to do
  - GovernanceDecision: Result of a governance check
  - GovernanceViolation: Audit record of a policy violation
  - GovernanceGate: Central enforcer — all actions pass through here
"""

import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action categories (ordered from least to most intrusive)
# ---------------------------------------------------------------------------

class ActionCategory(str, Enum):
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    ANALYSIS = "analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


# ---------------------------------------------------------------------------
# Phase policy — what each scan phase is allowed to do
# ---------------------------------------------------------------------------

DEFAULT_PHASE_POLICY: Dict[str, Dict[str, List[str]]] = {
    "recon": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "passive_recon": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.ACTIVE_RECON,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "initializing": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "analyzing": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.ACTIVE_RECON,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "testing": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "exploitation": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "full_auto": {
        "allowed": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.ANALYSIS,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.REPORTING,
        ],
        "denied": [
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "reporting": {
        "allowed": [
            ActionCategory.REPORTING,
            ActionCategory.ANALYSIS,
        ],
        "denied": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
    "completed": {
        "allowed": [
            ActionCategory.REPORTING,
            ActionCategory.ANALYSIS,
        ],
        "denied": [
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.POST_EXPLOITATION,
        ],
    },
}


# TaskCategory → maximum allowed phase ceiling
TASK_CATEGORY_PHASE_CEILING: Dict[str, str] = {
    "recon": "recon",
    "vulnerability": "testing",
    "exploitation": "exploitation",
    "reporting": "reporting",
    "custom": "full_auto",
    "full_auto": "full_auto",
}


# Phase ordering for ceiling enforcement
PHASE_RANK: Dict[str, int] = {
    "initializing": 0,
    "passive_recon": 1,
    "recon": 2,
    "analyzing": 3,
    "testing": 4,
    "exploitation": 5,
    "full_auto": 6,
    "reporting": 7,
    "completed": 8,
}


# ---------------------------------------------------------------------------
# Action classifier — maps tools, MCP calls, and methods to categories
# ---------------------------------------------------------------------------

# Default classification for all known tools/methods
ACTION_CLASSIFICATION: Dict[str, str] = {
    # External tools → category
    "subfinder": ActionCategory.ACTIVE_RECON,
    "httpx": ActionCategory.ACTIVE_RECON,
    "nmap": ActionCategory.ACTIVE_RECON,
    "katana": ActionCategory.ACTIVE_RECON,
    "gau": ActionCategory.PASSIVE_RECON,
    "waybackurls": ActionCategory.PASSIVE_RECON,
    "nuclei": ActionCategory.VULNERABILITY_SCAN,
    "sqlmap": ActionCategory.EXPLOITATION,
    "commix": ActionCategory.EXPLOITATION,
    "hydra": ActionCategory.EXPLOITATION,
    "ffuf": ActionCategory.ACTIVE_RECON,
    "nikto": ActionCategory.VULNERABILITY_SCAN,
    "gobuster": ActionCategory.ACTIVE_RECON,
    "dirsearch": ActionCategory.ACTIVE_RECON,
    "dalfox": ActionCategory.VULNERABILITY_SCAN,
    "arjun": ActionCategory.ACTIVE_RECON,
    "wafw00f": ActionCategory.ACTIVE_RECON,
    "masscan": ActionCategory.ACTIVE_RECON,
    "whatweb": ActionCategory.ACTIVE_RECON,
    "dnsx": ActionCategory.PASSIVE_RECON,
    "dig": ActionCategory.PASSIVE_RECON,
    "whois": ActionCategory.PASSIVE_RECON,
    "curl": ActionCategory.ACTIVE_RECON,
    "wfuzz": ActionCategory.VULNERABILITY_SCAN,

    # MCP tools → category
    "screenshot_capture": ActionCategory.ACTIVE_RECON,
    "payload_delivery": ActionCategory.EXPLOITATION,
    "dns_lookup": ActionCategory.PASSIVE_RECON,
    "port_scan": ActionCategory.ACTIVE_RECON,
    "technology_detect": ActionCategory.ACTIVE_RECON,
    "subdomain_enumerate": ActionCategory.ACTIVE_RECON,
    "save_finding": ActionCategory.ANALYSIS,
    "get_vuln_prompt": ActionCategory.ANALYSIS,
    "execute_nuclei": ActionCategory.VULNERABILITY_SCAN,
    "execute_naabu": ActionCategory.ACTIVE_RECON,
    "sandbox_health": ActionCategory.ANALYSIS,
    "sandbox_exec": ActionCategory.EXPLOITATION,

    # Internal agent methods → category
    "_test_payload": ActionCategory.VULNERABILITY_SCAN,
    "_test_single_param": ActionCategory.VULNERABILITY_SCAN,
    "_scan_for_vuln_type": ActionCategory.VULNERABILITY_SCAN,
    "_test_security_headers": ActionCategory.VULNERABILITY_SCAN,
    "_test_cors": ActionCategory.VULNERABILITY_SCAN,
    "_test_information_disclosure": ActionCategory.VULNERABILITY_SCAN,
    "_ai_test_vulnerability": ActionCategory.VULNERABILITY_SCAN,
    "_run_recon_only": ActionCategory.ACTIVE_RECON,
    "_run_full_auto": ActionCategory.EXPLOITATION,
    "_run_auto_pentest": ActionCategory.EXPLOITATION,
    "_run_prompt_only": ActionCategory.EXPLOITATION,
    "_run_analyze_only": ActionCategory.ANALYSIS,
    "_generate_report": ActionCategory.REPORTING,
    "_initial_probe": ActionCategory.ACTIVE_RECON,
    "_discover_endpoints": ActionCategory.ACTIVE_RECON,
    "_discover_parameters": ActionCategory.ACTIVE_RECON,
    "_detect_technologies": ActionCategory.ACTIVE_RECON,

    # Chain engine derived vuln types → exploitation since they attempt to exploit
    "auth_bypass": ActionCategory.EXPLOITATION,
    "default_credentials": ActionCategory.EXPLOITATION,
    "privilege_escalation": ActionCategory.EXPLOITATION,
    "brute_force": ActionCategory.EXPLOITATION,

    # Reporting
    "report_generation": ActionCategory.REPORTING,
}

# Unclassified actions default to the most restrictive category
DEFAULT_UNCLASSIFIED_CATEGORY = ActionCategory.EXPLOITATION


class ActionClassifier:
    """Classifies actions (tools, methods, vuln types) into ActionCategory."""

    _custom_overrides: Dict[str, str] = {}

    @classmethod
    def classify(cls, action: str) -> str:
        """Return the ActionCategory for an action string.

        Lookup order:
          1. Custom overrides (from config)
          2. Built-in ACTION_CLASSIFICATION table
          3. Heuristic matching (prefix/suffix)
          4. Default (most restrictive)
        """
        action_lower = action.lower().strip()

        # 1. Custom overrides
        if action_lower in cls._custom_overrides:
            return cls._custom_overrides[action_lower]

        # 2. Direct lookup
        if action_lower in ACTION_CLASSIFICATION:
            return ACTION_CLASSIFICATION[action_lower]

        # 3. Heuristic matching
        # Recon-related keywords
        recon_keywords = [
            "recon", "discover", "enumerate", "crawl", "probe",
            "fingerprint", "detect", "subdomain", "dns",
        ]
        for kw in recon_keywords:
            if kw in action_lower:
                return ActionCategory.ACTIVE_RECON

        # Analysis-related keywords
        analysis_keywords = ["analyze", "analysis", "report", "summary", "log"]
        for kw in analysis_keywords:
            if kw in action_lower:
                return ActionCategory.ANALYSIS

        # Scan/test keywords → vulnerability_scan
        scan_keywords = ["scan", "test", "check", "verify", "audit"]
        for kw in scan_keywords:
            if kw in action_lower:
                return ActionCategory.VULNERABILITY_SCAN

        # Exploit keywords
        exploit_keywords = [
            "exploit", "payload", "inject", "bypass", "brute",
            "crack", "escalat", "lateral",
        ]
        for kw in exploit_keywords:
            if kw in action_lower:
                return ActionCategory.EXPLOITATION

        # 4. Default — most restrictive
        return DEFAULT_UNCLASSIFIED_CATEGORY

    @classmethod
    def load_custom_overrides(cls, overrides: Dict[str, str]):
        """Load custom classification overrides from config."""
        cls._custom_overrides = {k.lower(): v for k, v in overrides.items()}

    @classmethod
    def get_classification(cls, action: str) -> Dict[str, str]:
        """Return full classification info for debugging."""
        category = cls.classify(action)
        source = "custom" if action.lower() in cls._custom_overrides else (
            "builtin" if action.lower() in ACTION_CLASSIFICATION else "heuristic"
        )
        return {"action": action, "category": category, "source": source}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GovernanceViolation:
    """Audit record of a policy violation."""
    scan_id: str
    phase: str
    action: str
    action_category: str
    allowed_categories: List[str]
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    disposition: str = "blocked"  # "blocked" | "warned"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase,
            "action": self.action,
            "action_category": self.action_category,
            "allowed_categories": [str(c) for c in self.allowed_categories],
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "disposition": self.disposition,
        }


@dataclass
class GovernanceDecision:
    """Result of a governance check."""
    allowed: bool
    action_category: str = ""
    reason: str = ""
    violation: Optional[GovernanceViolation] = None


# ---------------------------------------------------------------------------
# GovernanceGate — the central enforcer
# ---------------------------------------------------------------------------

class GovernanceGate:
    """Central enforcement point for phase-scoped action governance.

    Usage:
        gate = GovernanceGate(scan_id="abc", governance_mode="strict")
        gate.set_phase("recon")

        decision = gate.check("payload_delivery", {"url": "..."})
        if not decision.allowed:
            log(decision.reason)
            return  # action blocked

        # ... proceed with action ...
    """

    def __init__(
        self,
        scan_id: str,
        governance_mode: str = "strict",
        phase_policy: Optional[Dict] = None,
        phase_ceiling: Optional[str] = None,
        violation_callback: Optional[Callable] = None,
    ):
        self.scan_id = scan_id
        self.governance_mode = governance_mode  # "strict" | "warn" | "off"
        self.policy = phase_policy or DEFAULT_PHASE_POLICY
        self.current_phase: str = "initializing"
        self.phase_ceiling: Optional[str] = phase_ceiling
        self.violations: List[GovernanceViolation] = []
        self.checks_performed: int = 0
        self.checks_blocked: int = 0
        self.violation_callback = violation_callback

    @property
    def is_enabled(self) -> bool:
        return self.governance_mode != "off"

    @property
    def is_strict(self) -> bool:
        return self.governance_mode == "strict"

    def set_phase(self, phase: str):
        """Update the current scan phase, respecting the ceiling."""
        if self.phase_ceiling:
            ceiling_rank = PHASE_RANK.get(self.phase_ceiling, 99)
            requested_rank = PHASE_RANK.get(phase, 99)
            if requested_rank > ceiling_rank:
                logger.warning(
                    f"[Governance] Phase '{phase}' exceeds ceiling "
                    f"'{self.phase_ceiling}' for scan {self.scan_id}. "
                    f"Clamping to ceiling."
                )
                phase = self.phase_ceiling
        self.current_phase = phase
        logger.debug(f"[Governance] Phase set to '{phase}' for scan {self.scan_id}")

    def check(self, action: str, context: Optional[Dict] = None) -> GovernanceDecision:
        """Check whether an action is permitted in the current phase.

        Returns GovernanceDecision with allowed=True/False, category, and reason.
        """
        self.checks_performed += 1

        # Fast path: governance disabled
        if not self.is_enabled:
            category = ActionClassifier.classify(action)
            return GovernanceDecision(allowed=True, action_category=category)

        category = ActionClassifier.classify(action)
        phase_rules = self.policy.get(self.current_phase, {})
        allowed_categories = phase_rules.get("allowed", [])

        # Convert to string values for comparison
        allowed_str = [
            c.value if isinstance(c, ActionCategory) else str(c)
            for c in allowed_categories
        ]
        category_str = category.value if isinstance(category, ActionCategory) else str(category)

        if category_str in allowed_str:
            return GovernanceDecision(allowed=True, action_category=category_str)

        # --- VIOLATION ---
        self.checks_blocked += 1

        disposition = "blocked" if self.is_strict else "warned"
        violation = GovernanceViolation(
            scan_id=self.scan_id,
            phase=self.current_phase,
            action=action,
            action_category=category_str,
            allowed_categories=allowed_str,
            context=context or {},
            disposition=disposition,
        )
        self.violations.append(violation)

        # Fire callback for real-time notification (WebSocket, DB persistence)
        if self.violation_callback:
            try:
                self.violation_callback(violation)
            except Exception as e:
                logger.debug(f"Violation callback error: {e}")

        reason = (
            f"{'BLOCKED' if self.is_strict else 'WARNING'}: "
            f"'{action}' (category: {category_str}) is not permitted "
            f"during phase '{self.current_phase}'. "
            f"Allowed categories: {allowed_str}"
        )

        logger.warning(f"[Governance] {reason}")

        if self.is_strict:
            return GovernanceDecision(
                allowed=False,
                action_category=category_str,
                reason=reason,
                violation=violation,
            )
        else:
            # Warn mode: log violation but allow execution
            return GovernanceDecision(
                allowed=True,
                action_category=category_str,
                reason=reason,
                violation=violation,
            )

    def get_violations(self) -> List[GovernanceViolation]:
        """Return all violations recorded during this scan."""
        return list(self.violations)

    def get_stats(self) -> Dict:
        """Return governance statistics for reporting."""
        blocked = [v for v in self.violations if v.disposition == "blocked"]
        warned = [v for v in self.violations if v.disposition == "warned"]
        by_category: Dict[str, int] = {}
        for v in self.violations:
            by_category[v.action_category] = by_category.get(v.action_category, 0) + 1

        return {
            "governance_mode": self.governance_mode,
            "current_phase": self.current_phase,
            "phase_ceiling": self.phase_ceiling,
            "checks_performed": self.checks_performed,
            "checks_blocked": self.checks_blocked,
            "total_violations": len(self.violations),
            "violations_blocked": len(blocked),
            "violations_warned": len(warned),
            "violations_by_category": by_category,
        }

    def get_allowed_categories(self) -> List[str]:
        """Return the list of allowed categories for the current phase."""
        phase_rules = self.policy.get(self.current_phase, {})
        return [
            c.value if isinstance(c, ActionCategory) else str(c)
            for c in phase_rules.get("allowed", [])
        ]


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------

def create_governance_gate(
    scan_id: str,
    scan_config: Optional[Dict] = None,
    task_category: Optional[str] = None,
    violation_callback: Optional[Callable] = None,
) -> GovernanceGate:
    """Create a GovernanceGate from scan config and task category.

    Args:
        scan_id: The scan identifier.
        scan_config: The scan.config dict (may contain governance overrides).
        task_category: Task category from TaskLibrary (recon, vulnerability, etc.).
        violation_callback: Called on each violation for real-time notification.

    Returns:
        Configured GovernanceGate instance.
    """
    config = scan_config or {}
    gov_config = config.get("governance", {})

    # Mode: strict (default), warn, or off
    mode = gov_config.get("mode", "strict")

    # Phase ceiling from task category
    ceiling = None
    if task_category:
        ceiling = TASK_CATEGORY_PHASE_CEILING.get(task_category)

    # Build policy with optional overrides
    policy = dict(DEFAULT_PHASE_POLICY)
    overrides = gov_config.get("policy_overrides", {})
    for phase, rules in overrides.items():
        if phase in policy:
            policy[phase] = {**policy[phase], **rules}
        else:
            policy[phase] = rules

    # Load custom action classifications
    custom_classifications = gov_config.get("custom_classifications", {})
    if custom_classifications:
        ActionClassifier.load_custom_overrides(custom_classifications)

    return GovernanceGate(
        scan_id=scan_id,
        governance_mode=mode,
        phase_policy=policy,
        phase_ceiling=ceiling,
        violation_callback=violation_callback,
    )

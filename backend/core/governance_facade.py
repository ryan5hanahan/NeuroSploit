"""
sploit.ai - Unified Governance Facade

Single interface combining scope enforcement (GovernanceAgent) with
phase-action enforcement (GovernanceGate). All downstream code interacts
with this facade — never with the individual layers directly.

Scope layer:  Controls WHAT can be tested (vuln types, domains, tools).
Phase layer:  Controls WHEN actions can happen (no exploitation during recon).
"""

import asyncio
import json
import logging
import uuid
from typing import Any, Callable, Dict, List, Optional

from backend.core.governance import (
    GovernanceAgent,
    ScanScope,
    ScopeProfile,
    create_bug_bounty_scope,
    create_ctf_scope,
    create_pentest_scope,
    create_auto_pwn_scope,
    _create_single_vuln_scope,
    # Backward-compat aliases
    create_vuln_lab_scope,
    create_full_auto_scope,
    create_recon_only_scope,
)
from backend.core.governance_gate import (
    ActionClassifier,
    GovernanceDecision,
    GovernanceGate,
    GovernanceViolation,
    TASK_CATEGORY_PHASE_CEILING,
    create_governance_gate,
)

logger = logging.getLogger(__name__)


class Governance:
    """Unified governance facade combining scope and phase-action enforcement.

    Scope methods delegate to GovernanceAgent (what can be tested).
    Phase methods delegate to GovernanceGate (when actions are permitted).
    Both layers share a single violation store and callback mechanism.

    Usage:
        gov = create_governance(scan_id="abc", target_url="https://example.com",
                                scope_profile="full_auto", governance_mode="warn")

        # Scope methods (backward-compatible with GovernanceAgent):
        gov.filter_vuln_types(types)
        gov.scope_attack_plan(plan)
        gov.is_url_in_scope(url)

        # Phase methods (new):
        gov.set_phase("testing")
        decision = gov.check_action("sqlmap", {"target": url})
        if not decision.allowed:
            return  # blocked

        # Unified audit:
        gov.get_violations()
        gov.get_summary()
    """

    def __init__(
        self,
        scope_agent: GovernanceAgent,
        phase_gate: Optional[GovernanceGate] = None,
        scan_id: str = "",
        violation_callback: Optional[Callable] = None,
        db_persist_fn: Optional[Callable] = None,
    ):
        self._scope_agent = scope_agent
        self._phase_gate = phase_gate
        self.scan_id = scan_id
        self._violation_callback = violation_callback
        self._db_persist_fn = db_persist_fn

    # ------------------------------------------------------------------
    # Backward-compatible property: self.governance.scope
    # ------------------------------------------------------------------

    @property
    def scope(self) -> ScanScope:
        """Expose ScanScope for backward compat with existing agent code."""
        return self._scope_agent.scope

    # ------------------------------------------------------------------
    # Scope layer delegation (GovernanceAgent)
    # ------------------------------------------------------------------

    def filter_vuln_types(self, vuln_types: List[str]) -> List[str]:
        """Whitelist filter on vulnerability type list."""
        original_count = len(vuln_types)
        result = self._scope_agent.filter_vuln_types(vuln_types)
        blocked = original_count - len(result)
        if blocked > 0:
            self._record_scope_violation(
                "filter_vuln_types",
                f"Blocked {blocked}/{original_count} vuln types",
            )
        return result

    def scope_attack_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Filter priority_vulns in an attack plan dict."""
        original = plan.get("priority_vulns", [])
        result = self._scope_agent.scope_attack_plan(plan)
        scoped = result.get("priority_vulns", [])
        blocked = len(original) - len([v for v in original if v in scoped])
        if blocked > 0:
            self._record_scope_violation(
                "scope_attack_plan",
                f"Scoped plan from {len(original)} to {len(scoped)} types",
            )
        return result

    def constrain_analysis_prompt(self, prompt: str) -> str:
        """Append scope constraint to the AI analysis prompt."""
        return self._scope_agent.constrain_analysis_prompt(prompt)

    def should_port_scan(self) -> bool:
        return self._scope_agent.should_port_scan()

    def should_enumerate_subdomains(self) -> bool:
        return self._scope_agent.should_enumerate_subdomains()

    def get_nuclei_template_tags(self) -> Optional[str]:
        return self._scope_agent.get_nuclei_template_tags()

    def is_url_in_scope(self, url: str) -> bool:
        return self._scope_agent.is_url_in_scope(url)

    def check_finding_severity(self, severity: str, target_url: str) -> tuple:
        """Check severity against per-asset max_severity limit (bug bounty).

        Returns (within_limit, effective_severity).
        """
        within_limit, effective_sev = self._scope_agent.check_finding_severity(severity, target_url)
        if not within_limit:
            self._record_scope_violation(
                "check_finding_severity",
                f"Severity capped: {severity} -> {effective_sev} for {target_url}",
            )
        return within_limit, effective_sev

    # ------------------------------------------------------------------
    # Phase-action layer delegation (GovernanceGate)
    # ------------------------------------------------------------------

    def set_phase(self, phase: str):
        """Update the current scan phase (only ScanService should call this)."""
        if self._phase_gate:
            self._phase_gate.set_phase(phase)

    def check_action(self, action: str, context: Optional[Dict] = None) -> GovernanceDecision:
        """Check whether an action is permitted in the current phase.

        Returns GovernanceDecision. When no phase gate is configured,
        always returns allowed=True.
        """
        if not self._phase_gate:
            return GovernanceDecision(allowed=True)
        decision = self._phase_gate.check(action, context)
        if decision.violation:
            self._on_violation(decision.violation)
        return decision

    def get_allowed_categories(self) -> List[str]:
        """Return the allowed action categories for the current phase."""
        if not self._phase_gate:
            return []
        return self._phase_gate.get_allowed_categories()

    @property
    def current_phase(self) -> str:
        """The current scan phase from the phase gate."""
        if self._phase_gate:
            return self._phase_gate.current_phase
        return "unknown"

    @property
    def governance_mode(self) -> str:
        """The phase gate mode (strict/warn/off)."""
        if self._phase_gate:
            return self._phase_gate.governance_mode
        return "off"

    # ------------------------------------------------------------------
    # Unified audit trail
    # ------------------------------------------------------------------

    def get_violations(self) -> List[GovernanceViolation]:
        """Return all violations from both layers."""
        violations: List[GovernanceViolation] = []
        # Scope layer violations (convert from _Violation to GovernanceViolation)
        for v in self._scope_agent._violations:
            violations.append(GovernanceViolation(
                scan_id=self.scan_id,
                phase=self.current_phase,
                action=v.method,
                action_category="scope",
                allowed_categories=[],
                detail=v.detail,
                layer="scope",
            ))
        # Phase layer violations
        if self._phase_gate:
            violations.extend(self._phase_gate.get_violations())
        return violations

    def get_summary(self) -> Dict[str, Any]:
        """Merged summary from both layers for reports."""
        summary: Dict[str, Any] = {}

        # Scope summary
        summary["scope"] = self._scope_agent.get_summary()

        # Phase gate summary
        if self._phase_gate:
            summary["phase_gate"] = self._phase_gate.get_stats()
        else:
            summary["phase_gate"] = {"governance_mode": "off"}

        # Combined counts
        all_violations = self.get_violations()
        summary["total_violations"] = len(all_violations)
        summary["scope_violations"] = len([v for v in all_violations if v.layer == "scope"])
        summary["phase_violations"] = len([v for v in all_violations if v.layer == "phase"])

        return summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_scope_violation(self, method: str, detail: str):
        """Record a scope-layer violation and fire callbacks."""
        violation = GovernanceViolation(
            scan_id=self.scan_id,
            phase=self.current_phase,
            action=method,
            action_category="scope",
            allowed_categories=[],
            detail=detail,
            disposition="warned",  # scope layer always warns (filters data, doesn't block)
            layer="scope",
        )
        self._on_violation(violation)

    def _on_violation(self, violation: GovernanceViolation):
        """Fire violation callback and optional DB persist."""
        if self._violation_callback:
            try:
                self._violation_callback(violation)
            except Exception as e:
                logger.debug(f"Violation callback error: {e}")

        if self._db_persist_fn:
            try:
                self._db_persist_fn(violation)
            except Exception as e:
                logger.debug(f"Violation DB persist error: {e}")


# ---------------------------------------------------------------------------
# Unified factory
# ---------------------------------------------------------------------------

_SCOPE_FACTORIES = {
    # New profiles
    "bug_bounty": lambda url, vt: create_bug_bounty_scope(url),
    "ctf": lambda url, vt: create_ctf_scope(url),
    "pentest": lambda url, vt: create_pentest_scope(url),
    "auto_pwn": lambda url, vt: create_auto_pwn_scope(url),
    # VulnLab helper (single vuln type restriction on pentest profile)
    "vuln_lab": lambda url, vt: _create_single_vuln_scope(url, vt),
    # Backward-compatible aliases
    "full_auto": lambda url, vt: create_pentest_scope(url),
    "recon_only": lambda url, vt: create_recon_only_scope(url),
    "custom": lambda url, vt: create_pentest_scope(url),
}

# Profile → default governance mode
_PROFILE_DEFAULT_MODE: Dict[str, str] = {
    "bug_bounty": "strict",
    "ctf": "off",
    "pentest": "warn",
    "auto_pwn": "off",
    # Backward-compat aliases
    "full_auto": "warn",
    "recon_only": "strict",
    "vuln_lab": "warn",
    "custom": "warn",
}


def create_governance(
    scan_id: str,
    target_url: str,
    scope_profile: str = "full_auto",
    vuln_type: Optional[str] = None,
    governance_mode: str = "warn",
    task_category: Optional[str] = None,
    scan_config: Optional[Dict] = None,
    log_callback: Optional[Callable] = None,
    violation_callback: Optional[Callable] = None,
    db_persist_fn: Optional[Callable] = None,
) -> Governance:
    """Unified factory — creates both governance layers and wraps in facade.

    Args:
        scan_id: The scan identifier.
        target_url: The primary target URL (for domain scoping).
        scope_profile: One of "bug_bounty", "ctf", "pentest", "auto_pwn" (or legacy aliases).
        vuln_type: Required for vuln_lab profile (the specific vuln type to test).
        governance_mode: Phase gate mode — "strict", "warn", or "off".
        task_category: Task category for phase ceiling (recon, vulnerability, etc.).
        scan_config: Full scan.config dict (may contain governance overrides).
        log_callback: Async callback for governance log messages.
        violation_callback: Called on each violation for real-time notification.
        db_persist_fn: Called to persist violations to the database.

    Returns:
        Configured Governance facade instance.
    """
    # Load global config overrides
    config = scan_config or {}
    gov_config = config.get("governance", {})

    # Load action classification overrides from config
    _load_classification_overrides(gov_config)

    # Resolve governance mode: scan config > explicit param > profile default > "warn"
    profile_default_mode = _PROFILE_DEFAULT_MODE.get(scope_profile, "warn")
    effective_mode = gov_config.get("mode", governance_mode or profile_default_mode)

    # Force governance mode for specific profiles (cannot be overridden)
    if scope_profile in ("ctf", "auto_pwn"):
        effective_mode = "off"
    elif scope_profile == "bug_bounty":
        effective_mode = "strict"
    elif scope_profile == "recon_only":
        effective_mode = "strict"

    # 1. Create scope layer
    factory = _SCOPE_FACTORIES.get(scope_profile)
    if not factory:
        logger.warning(f"Unknown scope profile '{scope_profile}', falling back to full_auto")
        factory = _SCOPE_FACTORIES["full_auto"]
    scope = factory(target_url, vuln_type or "")
    scope_agent = GovernanceAgent(scope, log_callback=log_callback)

    # 2. Create phase-action layer
    phase_gate = None
    if effective_mode != "off":
        phase_gate = create_governance_gate(
            scan_id=scan_id,
            scan_config={"governance": {"mode": effective_mode, **gov_config}},
            task_category=task_category,
        )

    # 3. Wire default callbacks if not provided
    if not violation_callback:
        violation_callback = _make_ws_violation_callback(scan_id)
    if not db_persist_fn:
        db_persist_fn = _make_db_persist_fn(scan_id)

    return Governance(
        scope_agent=scope_agent,
        phase_gate=phase_gate,
        scan_id=scan_id,
        violation_callback=violation_callback,
        db_persist_fn=db_persist_fn,
    )


def _make_ws_violation_callback(scan_id: str) -> Callable:
    """Create a callback that broadcasts violations via WebSocket."""
    def _callback(violation: GovernanceViolation):
        try:
            from backend.api.websocket import manager as ws_manager
            violation_dict = violation.to_dict()
            # Schedule the async broadcast from sync context
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(
                    ws_manager.broadcast_governance_violation(scan_id, violation_dict)
                )
            except RuntimeError:
                pass  # No running loop — skip WS broadcast
        except Exception:
            pass
    return _callback


def _make_db_persist_fn(scan_id: str) -> Callable:
    """Create a callback that persists violations to the database."""
    def _persist(violation: GovernanceViolation):
        try:
            from backend.db.database import async_session_factory
            from backend.models.governance_violation import GovernanceViolationRecord

            async def _do_persist():
                async with async_session_factory() as session:
                    record = GovernanceViolationRecord(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        layer=getattr(violation, "layer", "phase"),
                        phase=getattr(violation, "phase", None),
                        action=getattr(violation, "action", None),
                        action_category=getattr(violation, "action_category", None),
                        allowed_categories=getattr(violation, "allowed_categories", []),
                        context=getattr(violation, "context", None),
                        disposition=getattr(violation, "disposition", "blocked"),
                        detail=getattr(violation, "detail", None),
                    )
                    session.add(record)
                    await session.commit()

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_do_persist())
            except RuntimeError:
                pass  # No running loop — skip DB persist
        except Exception as e:
            logger.debug(f"Violation DB persist error: {e}")
    return _persist


def _load_classification_overrides(gov_config: Dict):
    """Load action classification overrides from governance config."""
    # Global config file overrides
    try:
        with open("config/config.json") as f:
            global_config = json.load(f)
        global_gov = global_config.get("governance", {})
        global_classifications = global_gov.get("action_classifications", {})
        if global_classifications:
            ActionClassifier.load_custom_overrides(global_classifications)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Per-scan overrides take precedence
    scan_classifications = gov_config.get("custom_classifications", {})
    if scan_classifications:
        ActionClassifier.load_custom_overrides(scan_classifications)

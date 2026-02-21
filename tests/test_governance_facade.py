"""
Tests for backend.core.governance_facade — Unified Governance facade.

Covers:
  - Scope method delegation (all 7 GovernanceAgent methods)
  - Phase method delegation (set_phase, check_action)
  - Unified violation store (scope + phase violations merged)
  - CTF mode (phase gate disabled, scope still active)
  - Backward compatibility (self.governance.scope works)
  - create_governance() factory for all profiles
  - Violation callback mechanism
  - New profiles: bug_bounty, pentest, auto_pwn
"""

import pytest
from unittest.mock import MagicMock
from backend.core.governance import (
    GovernanceAgent,
    ScopeProfile,
    create_pentest_scope,
    create_auto_pwn_scope,
    create_bug_bounty_scope,
    create_ctf_scope,
    _create_single_vuln_scope,
    create_vuln_lab_scope,
    create_full_auto_scope,
    create_recon_only_scope,
)
from backend.core.governance_gate import (
    GovernanceGate,
    GovernanceViolation,
)
from backend.core.governance_facade import (
    Governance,
    create_governance,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_facade(
    scope_profile="pentest",
    target="https://example.com",
    vuln_type=None,
    governance_mode="strict",
    scan_id="test-scan",
):
    """Build a Governance facade for testing."""
    if scope_profile == "vuln_lab":
        scope = _create_single_vuln_scope(target, vuln_type or "xss_reflected")
    elif scope_profile == "ctf":
        scope = create_ctf_scope(target)
    elif scope_profile == "recon_only":
        scope = create_recon_only_scope(target)
    elif scope_profile == "bug_bounty":
        scope = create_bug_bounty_scope(target)
    elif scope_profile == "auto_pwn":
        scope = create_auto_pwn_scope(target)
    else:
        scope = create_pentest_scope(target)

    agent = GovernanceAgent(scope)

    gate = None
    if governance_mode != "off":
        gate = GovernanceGate(scan_id=scan_id, governance_mode=governance_mode)

    return Governance(
        scope_agent=agent,
        phase_gate=gate,
        scan_id=scan_id,
    )


ALL_VULN_TYPES = [
    "sqli_error", "xss_reflected", "lfi", "ssrf", "command_injection",
    "csrf", "xxe", "path_traversal", "idor", "jwt_manipulation",
]


# ===================================================================
# Scope delegation
# ===================================================================

class TestScopeDelegation:

    def test_filter_vuln_types_vuln_lab(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected")
        result = gov.filter_vuln_types(ALL_VULN_TYPES)
        assert result == ["xss_reflected"]

    def test_filter_vuln_types_pentest(self):
        gov = _make_facade(scope_profile="pentest")
        result = gov.filter_vuln_types(ALL_VULN_TYPES)
        assert result == ALL_VULN_TYPES

    def test_scope_attack_plan(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="sqli_error")
        plan = {"priority_vulns": ["sqli_error", "xss_reflected", "lfi"]}
        scoped = gov.scope_attack_plan(plan)
        assert "sqli_error" in scoped["priority_vulns"]
        assert "xss_reflected" not in scoped["priority_vulns"]

    def test_constrain_analysis_prompt_vuln_lab(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected")
        result = gov.constrain_analysis_prompt("Analyze target.")
        assert "SCOPE CONSTRAINT" in result
        assert "xss_reflected" in result

    def test_constrain_analysis_prompt_pentest(self):
        gov = _make_facade(scope_profile="pentest")
        result = gov.constrain_analysis_prompt("Analyze target.")
        assert result == "Analyze target."

    def test_should_port_scan(self):
        gov_lab = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected")
        assert gov_lab.should_port_scan() is False

        gov_pentest = _make_facade(scope_profile="pentest")
        assert gov_pentest.should_port_scan() is True

    def test_should_enumerate_subdomains(self):
        gov_lab = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected")
        assert gov_lab.should_enumerate_subdomains() is False

    def test_get_nuclei_template_tags(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected")
        assert gov.get_nuclei_template_tags() == "xss"

    def test_is_url_in_scope(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected",
                           target="https://example.com")
        assert gov.is_url_in_scope("https://example.com/api") is True
        assert gov.is_url_in_scope("https://evil.com/api") is False


# ===================================================================
# Backward compatibility
# ===================================================================

class TestBackwardCompat:

    def test_scope_property_returns_scan_scope_pentest(self):
        gov = _make_facade(scope_profile="pentest")
        assert gov.scope.profile == ScopeProfile.PENTEST
        assert isinstance(gov.scope.allowed_domains, frozenset)

    def test_scope_property_vuln_lab(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="sqli_error")
        assert gov.scope.profile == ScopeProfile.PENTEST
        assert gov.scope.allowed_vuln_types == frozenset({"sqli_error"})

    def test_scope_property_is_immutable(self):
        gov = _make_facade(scope_profile="pentest")
        with pytest.raises(AttributeError):
            gov.scope.skip_port_scan = True


# ===================================================================
# Phase-action delegation
# ===================================================================

class TestPhaseDelegation:

    def test_set_phase(self):
        gov = _make_facade(governance_mode="strict")
        gov.set_phase("recon")
        assert gov.current_phase == "recon"

    def test_check_action_allowed(self):
        gov = _make_facade(governance_mode="strict")
        gov.set_phase("recon")
        decision = gov.check_action("dns_lookup")
        assert decision.allowed is True

    def test_check_action_blocked_strict(self):
        gov = _make_facade(governance_mode="strict")
        gov.set_phase("recon")
        decision = gov.check_action("sqlmap")
        assert decision.allowed is False

    def test_check_action_warned(self):
        gov = _make_facade(governance_mode="warn")
        gov.set_phase("recon")
        decision = gov.check_action("sqlmap")
        assert decision.allowed is True
        assert decision.violation is not None

    def test_get_allowed_categories(self):
        gov = _make_facade(governance_mode="strict")
        gov.set_phase("recon")
        cats = gov.get_allowed_categories()
        assert "passive_recon" in cats
        assert "active_recon" in cats
        assert "exploitation" not in cats

    def test_governance_mode_property(self):
        gov = _make_facade(governance_mode="warn")
        assert gov.governance_mode == "warn"


# ===================================================================
# No phase gate (off mode)
# ===================================================================

class TestNoPhaseGate:

    def test_check_action_always_allowed(self):
        gov = _make_facade(governance_mode="off")
        decision = gov.check_action("sqlmap")
        assert decision.allowed is True

    def test_set_phase_is_noop(self):
        gov = _make_facade(governance_mode="off")
        gov.set_phase("recon")
        assert gov.current_phase == "unknown"

    def test_governance_mode_is_off(self):
        gov = _make_facade(governance_mode="off")
        assert gov.governance_mode == "off"

    def test_get_allowed_categories_empty(self):
        gov = _make_facade(governance_mode="off")
        assert gov.get_allowed_categories() == []


# ===================================================================
# CTF mode
# ===================================================================

class TestCTFMode:

    def test_ctf_scope_with_gate_off(self):
        gov = _make_facade(scope_profile="ctf", governance_mode="off")
        assert gov.scope.profile == ScopeProfile.CTF
        assert gov.is_url_in_scope("https://example.com/api") is True
        assert gov.is_url_in_scope("https://other.com") is False
        decision = gov.check_action("sqlmap")
        assert decision.allowed is True

    def test_ctf_all_vuln_types_pass(self):
        gov = _make_facade(scope_profile="ctf", governance_mode="off")
        result = gov.filter_vuln_types(ALL_VULN_TYPES)
        assert result == ALL_VULN_TYPES


# ===================================================================
# Bug Bounty mode
# ===================================================================

class TestBugBountyMode:

    def test_bug_bounty_scope_profile(self):
        gov = _make_facade(scope_profile="bug_bounty", governance_mode="strict")
        assert gov.scope.profile == ScopeProfile.BUG_BOUNTY

    def test_bug_bounty_full_recon(self):
        gov = _make_facade(scope_profile="bug_bounty")
        assert gov.scope.max_recon_depth == "full"

    def test_bug_bounty_all_vuln_types_pass(self):
        gov = _make_facade(scope_profile="bug_bounty", governance_mode="strict")
        result = gov.filter_vuln_types(ALL_VULN_TYPES)
        assert result == ALL_VULN_TYPES


# ===================================================================
# Auto Pwn mode
# ===================================================================

class TestAutoPwnMode:

    def test_auto_pwn_scope_profile(self):
        gov = _make_facade(scope_profile="auto_pwn", governance_mode="off")
        assert gov.scope.profile == ScopeProfile.AUTO_PWN

    def test_auto_pwn_all_vuln_types_pass(self):
        gov = _make_facade(scope_profile="auto_pwn", governance_mode="off")
        result = gov.filter_vuln_types(ALL_VULN_TYPES)
        assert result == ALL_VULN_TYPES


# ===================================================================
# Unified violation store
# ===================================================================

class TestUnifiedViolations:

    def test_phase_violations_in_get_violations(self):
        gov = _make_facade(governance_mode="strict")
        gov.set_phase("recon")
        gov.check_action("sqlmap")
        violations = gov.get_violations()
        assert len(violations) == 1
        assert violations[0].layer == "phase"
        assert violations[0].action == "sqlmap"

    def test_scope_violations_in_get_violations(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected",
                           governance_mode="strict")
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])
        violations = gov.get_violations()
        scope_violations = [v for v in violations if v.layer == "scope"]
        assert len(scope_violations) == 1

    def test_both_layers_combined(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected",
                           governance_mode="strict")
        gov.set_phase("recon")
        gov.check_action("sqlmap")
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])
        violations = gov.get_violations()
        layers = {v.layer for v in violations}
        assert "scope" in layers
        assert "phase" in layers

    def test_no_violations_when_all_allowed(self):
        gov = _make_facade(scope_profile="pentest", governance_mode="strict")
        gov.set_phase("full_auto")
        gov.check_action("nmap")
        gov.filter_vuln_types(ALL_VULN_TYPES)
        violations = gov.get_violations()
        assert len(violations) == 0


# ===================================================================
# get_summary
# ===================================================================

class TestGetSummary:

    def test_summary_structure(self):
        gov = _make_facade(governance_mode="strict")
        summary = gov.get_summary()
        assert "scope" in summary
        assert "phase_gate" in summary
        assert "total_violations" in summary
        assert "scope_violations" in summary
        assert "phase_violations" in summary

    def test_summary_counts(self):
        gov = _make_facade(scope_profile="vuln_lab", vuln_type="xss_reflected",
                           governance_mode="strict")
        gov.set_phase("recon")
        gov.check_action("sqlmap")
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])
        summary = gov.get_summary()
        assert summary["phase_violations"] >= 1
        assert summary["scope_violations"] >= 1
        assert summary["total_violations"] == summary["scope_violations"] + summary["phase_violations"]

    def test_summary_with_gate_off(self):
        gov = _make_facade(governance_mode="off")
        summary = gov.get_summary()
        assert summary["phase_gate"]["governance_mode"] == "off"
        assert summary["total_violations"] == 0


# ===================================================================
# Violation callback
# ===================================================================

class TestViolationCallback:

    def test_callback_fires_on_phase_violation(self):
        violations = []
        scope = create_pentest_scope("https://example.com")
        agent = GovernanceAgent(scope)
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gov = Governance(
            scope_agent=agent, phase_gate=gate, scan_id="t1",
            violation_callback=lambda v: violations.append(v),
        )
        gov.set_phase("recon")
        gov.check_action("sqlmap")
        assert len(violations) == 1
        assert violations[0].layer == "phase"

    def test_callback_fires_on_scope_violation(self):
        violations = []
        scope = _create_single_vuln_scope("https://example.com", "xss_reflected")
        agent = GovernanceAgent(scope)
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gov = Governance(
            scope_agent=agent, phase_gate=gate, scan_id="t1",
            violation_callback=lambda v: violations.append(v),
        )
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])
        scope_violations = [v for v in violations if v.layer == "scope"]
        assert len(scope_violations) == 1

    def test_db_persist_fn_fires(self):
        persisted = []
        scope = create_pentest_scope("https://example.com")
        agent = GovernanceAgent(scope)
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gov = Governance(
            scope_agent=agent, phase_gate=gate, scan_id="t1",
            db_persist_fn=lambda v: persisted.append(v),
        )
        gov.set_phase("recon")
        gov.check_action("sqlmap")
        assert len(persisted) == 1


# ===================================================================
# create_governance() factory
# ===================================================================

class TestCreateGovernanceFactory:

    def test_pentest_profile(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="pentest", governance_mode="warn",
        )
        assert gov.scope.profile == ScopeProfile.PENTEST
        assert gov.governance_mode == "warn"

    def test_vuln_lab_profile(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="vuln_lab", vuln_type="sqli_error",
            governance_mode="strict",
        )
        assert gov.scope.profile == ScopeProfile.PENTEST
        assert gov.scope.allowed_vuln_types == frozenset({"sqli_error"})

    def test_ctf_profile_gate_off(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="ctf", governance_mode="off",
        )
        assert gov.scope.profile == ScopeProfile.CTF
        assert gov.governance_mode == "off"
        assert gov.check_action("sqlmap").allowed is True

    def test_bug_bounty_profile(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="bug_bounty",
        )
        assert gov.scope.profile == ScopeProfile.BUG_BOUNTY
        # Bug bounty forces strict mode
        assert gov.governance_mode == "strict"

    def test_auto_pwn_profile(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="auto_pwn",
        )
        assert gov.scope.profile == ScopeProfile.AUTO_PWN
        # Auto pwn forces off mode
        assert gov.governance_mode == "off"

    def test_unknown_profile_falls_back(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="nonexistent",
        )
        assert gov.scope.profile == ScopeProfile.PENTEST

    def test_full_auto_alias(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="full_auto",
        )
        assert gov.scope.profile == ScopeProfile.PENTEST

    def test_recon_only_alias(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="recon_only",
        )
        # recon_only forces strict mode
        assert gov.governance_mode == "strict"

    def test_scan_config_overrides_mode(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="pentest",
            governance_mode="strict",
            scan_config={"governance": {"mode": "warn"}},
        )
        assert gov.governance_mode == "warn"

    def test_task_category_sets_phase_ceiling(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict", task_category="recon",
        )
        gov.set_phase("exploitation")
        assert gov.current_phase == "recon"

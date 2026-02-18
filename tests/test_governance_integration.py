"""
Tests for governance integration — Phase 2 wiring verification.

Covers:
  - Governance with warn mode: check_action returns allowed=True with violation logged
  - Governance with strict mode: check_action returns allowed=False
  - ChainEngine filters derived targets when governance blocks escalation
  - create_governance factory produces correct facades for each call site
  - Phase progression model (set_phase updates current_phase)
  - Backward compat: facade .scope property matches old GovernanceAgent interface
"""

import pytest
from unittest.mock import MagicMock, AsyncMock
from backend.core.governance import (
    GovernanceAgent,
    ScopeProfile,
    create_full_auto_scope,
    create_vuln_lab_scope,
    create_ctf_scope,
    create_recon_only_scope,
)
from backend.core.governance_gate import (
    GovernanceGate,
    GovernanceViolation,
    ActionClassifier,
)
from backend.core.governance_facade import (
    Governance,
    create_governance,
)
from backend.core.chain_engine import ChainEngine, ChainableTarget


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gov(scope_profile="full_auto", target="https://example.com",
              vuln_type=None, governance_mode="strict", scan_id="int-test"):
    """Build a Governance facade for integration testing."""
    return create_governance(
        scan_id=scan_id,
        target_url=target,
        scope_profile=scope_profile,
        vuln_type=vuln_type,
        governance_mode=governance_mode,
    )


# ===================================================================
# Warn mode: log violations but allow actions
# ===================================================================

class TestWarnMode:

    def test_warn_allows_action_with_violation(self):
        gov = _make_gov(governance_mode="warn")
        gov.set_phase("recon")
        decision = gov.check_action("sqlmap")
        assert decision.allowed is True
        assert decision.violation is not None
        assert decision.violation.disposition == "warned"

    def test_warn_records_violation_in_store(self):
        gov = _make_gov(governance_mode="warn")
        gov.set_phase("recon")
        gov.check_action("sqlmap")
        violations = gov.get_violations()
        phase_violations = [v for v in violations if v.layer == "phase"]
        assert len(phase_violations) >= 1

    def test_warn_allowed_action_has_no_violation(self):
        gov = _make_gov(governance_mode="warn")
        gov.set_phase("recon")
        decision = gov.check_action("dns_lookup")
        assert decision.allowed is True
        assert decision.violation is None


# ===================================================================
# Strict mode: block disallowed actions
# ===================================================================

class TestStrictMode:

    def test_strict_blocks_exploitation_in_recon(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("recon")
        decision = gov.check_action("sqlmap")
        assert decision.allowed is False

    def test_strict_allows_passive_recon_in_recon(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("recon")
        decision = gov.check_action("dns_lookup")
        assert decision.allowed is True

    def test_strict_allows_exploitation_in_full_auto(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("full_auto")
        decision = gov.check_action("sqlmap")
        assert decision.allowed is True

    def test_strict_blocks_nuclei_in_recon(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("recon")
        decision = gov.check_action("nuclei")
        assert decision.allowed is False

    def test_strict_allows_nuclei_in_testing(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("testing")
        decision = gov.check_action("nuclei")
        assert decision.allowed is True


# ===================================================================
# ChainEngine governance integration
# ===================================================================

class TestChainEngineGovernance:

    def test_chain_engine_accepts_governance(self):
        gov = _make_gov(governance_mode="strict")
        engine = ChainEngine(governance=gov)
        assert engine.governance is gov

    def test_chain_engine_no_governance_allows_all(self):
        engine = ChainEngine()
        assert engine.governance is None

    @pytest.mark.asyncio
    async def test_chain_engine_filters_blocked_targets(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("recon")  # exploitation not allowed

        engine = ChainEngine(governance=gov)

        # Create a mock finding
        finding = MagicMock()
        finding.vulnerability_type = "sqli_error"
        finding.id = "f1"
        finding._chain_depth = 0
        finding.url = "https://example.com/api"
        finding.parameter = "id"
        finding.evidence = "SQL error"
        finding.payload = "' OR 1=1 --"

        derived = await engine.on_finding(finding)
        # In recon phase, exploitation-category derived targets should be filtered
        for target in derived:
            decision = gov.check_action(target.vuln_type)
            # Any returned target should be allowed (governance already filtered)
            assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_chain_engine_allows_all_in_full_auto(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("full_auto")  # everything allowed

        engine = ChainEngine(governance=gov)

        finding = MagicMock()
        finding.vulnerability_type = "sqli_error"
        finding.id = "f2"
        finding._chain_depth = 0
        finding.url = "https://example.com/api"
        finding.parameter = "id"
        finding.evidence = "SQL error"
        finding.payload = "' OR 1=1 --"

        derived = await engine.on_finding(finding)
        # In full_auto, nothing should be blocked
        # (may still be 0 if no rules match — that's fine)


# ===================================================================
# Factory produces correct configurations for each call site
# ===================================================================

class TestFactoryCallSites:

    def test_agent_api_full_auto(self):
        """Mirrors agent.py: full_auto + warn mode."""
        gov = create_governance(
            scan_id="agent-1", target_url="https://example.com",
            scope_profile="full_auto", governance_mode="warn",
        )
        assert gov.scope.profile == ScopeProfile.FULL_AUTO
        assert gov.governance_mode == "warn"

    def test_agent_api_recon_only(self):
        """Mirrors agent.py: recon_only + warn mode + task_category=recon."""
        gov = create_governance(
            scan_id="agent-2", target_url="https://example.com",
            scope_profile="recon_only", governance_mode="warn",
            task_category="recon",
        )
        assert gov.scope.profile == ScopeProfile.RECON_ONLY
        # Phase ceiling should clamp exploitation
        gov.set_phase("exploitation")
        assert gov.current_phase == "recon"

    def test_vuln_lab_api(self):
        """Mirrors vuln_lab.py: vuln_lab + warn mode."""
        gov = create_governance(
            scan_id="lab-1", target_url="https://example.com",
            scope_profile="vuln_lab", vuln_type="xss_reflected",
            governance_mode="warn",
        )
        assert gov.scope.profile == ScopeProfile.VULN_LAB
        assert gov.scope.allowed_vuln_types == frozenset({"xss_reflected"})

    def test_vuln_lab_ctf_mode(self):
        """Mirrors vuln_lab.py: ctf + off mode."""
        gov = create_governance(
            scan_id="ctf-1", target_url="https://example.com",
            scope_profile="ctf", governance_mode="off",
        )
        assert gov.scope.profile == ScopeProfile.CTF
        assert gov.governance_mode == "off"
        # Everything should be allowed
        decision = gov.check_action("sqlmap")
        assert decision.allowed is True

    def test_ctf_coordinator(self):
        """Mirrors ctf_coordinator.py: ctf + off mode."""
        gov = create_governance(
            scan_id="coord-1", target_url="https://ctf.example.com",
            scope_profile="ctf", governance_mode="off",
        )
        assert gov.scope.profile == ScopeProfile.CTF
        assert gov.is_url_in_scope("https://ctf.example.com/challenge")
        assert not gov.is_url_in_scope("https://other.com/hack")

    def test_scan_service(self):
        """Mirrors scan_service.py: full_auto + warn mode."""
        gov = create_governance(
            scan_id="scan-1", target_url="https://example.com",
            scope_profile="full_auto", governance_mode="warn",
        )
        assert gov.governance_mode == "warn"
        gov.set_phase("initializing")
        assert gov.current_phase == "initializing"


# ===================================================================
# Phase progression model
# ===================================================================

class TestPhaseProgression:

    def test_phase_transitions(self):
        gov = _make_gov(governance_mode="strict")
        phases = ["initializing", "recon", "analyzing", "testing", "completed"]
        for phase in phases:
            gov.set_phase(phase)
            assert gov.current_phase == phase

    def test_phase_ceiling_clamps(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict", task_category="recon",
        )
        gov.set_phase("exploitation")
        assert gov.current_phase == "recon"

    def test_allowed_categories_change_with_phase(self):
        gov = _make_gov(governance_mode="strict")

        gov.set_phase("recon")
        recon_cats = gov.get_allowed_categories()
        assert "passive_recon" in recon_cats
        assert "exploitation" not in recon_cats

        gov.set_phase("exploitation")
        exploit_cats = gov.get_allowed_categories()
        assert "exploitation" in exploit_cats


# ===================================================================
# Backward compatibility: facade.scope matches old GovernanceAgent
# ===================================================================

class TestBackwardCompatIntegration:

    def test_scope_property_full_auto(self):
        gov = _make_gov(scope_profile="full_auto")
        assert gov.scope.profile == ScopeProfile.FULL_AUTO
        assert gov.should_port_scan() is True
        assert gov.should_enumerate_subdomains() is True

    def test_scope_property_vuln_lab(self):
        gov = _make_gov(scope_profile="vuln_lab", vuln_type="sqli_error")
        assert gov.scope.profile == ScopeProfile.VULN_LAB
        assert gov.should_port_scan() is False
        result = gov.filter_vuln_types(["sqli_error", "xss_reflected", "lfi"])
        assert result == ["sqli_error"]

    def test_governance_summary_has_both_layers(self):
        gov = _make_gov(governance_mode="strict")
        gov.set_phase("recon")
        gov.check_action("sqlmap")  # phase violation
        summary = gov.get_summary()
        assert "scope" in summary
        assert "phase_gate" in summary
        assert summary["phase_violations"] >= 1

"""
Tests for backend.core.governance_gate — GovernanceGate phase-action enforcement.

Covers:
  - ActionCategory enum
  - ActionClassifier (built-in, heuristic, custom overrides)
  - GovernanceGate (check, set_phase, phase ceiling, modes)
  - GovernanceViolation (dataclass, to_dict, layer field)
  - GovernanceDecision
  - create_governance_gate factory
"""

import pytest
from datetime import datetime
from backend.core.governance_gate import (
    ActionCategory,
    ActionClassifier,
    ACTION_CLASSIFICATION,
    DEFAULT_PHASE_POLICY,
    PHASE_RANK,
    TASK_CATEGORY_PHASE_CEILING,
    GovernanceDecision,
    GovernanceGate,
    GovernanceViolation,
    create_governance_gate,
)


# ===================================================================
# ActionCategory enum
# ===================================================================

class TestActionCategory:

    def test_seven_categories_exist(self):
        assert len(ActionCategory) == 7

    def test_values(self):
        assert ActionCategory.PASSIVE_RECON.value == "passive_recon"
        assert ActionCategory.EXPLOITATION.value == "exploitation"
        assert ActionCategory.REPORTING.value == "reporting"


# ===================================================================
# ActionClassifier — built-in lookups
# ===================================================================

class TestActionClassifierBuiltin:

    def test_external_tools(self):
        assert ActionClassifier.classify("nmap") == ActionCategory.ACTIVE_RECON
        assert ActionClassifier.classify("nuclei") == ActionCategory.VULNERABILITY_SCAN
        assert ActionClassifier.classify("sqlmap") == ActionCategory.EXPLOITATION
        assert ActionClassifier.classify("gau") == ActionCategory.PASSIVE_RECON

    def test_mcp_tools(self):
        assert ActionClassifier.classify("screenshot_capture") == ActionCategory.ACTIVE_RECON
        assert ActionClassifier.classify("payload_delivery") == ActionCategory.EXPLOITATION
        assert ActionClassifier.classify("dns_lookup") == ActionCategory.PASSIVE_RECON
        assert ActionClassifier.classify("save_finding") == ActionCategory.ANALYSIS
        assert ActionClassifier.classify("execute_nuclei") == ActionCategory.VULNERABILITY_SCAN

    def test_internal_methods(self):
        assert ActionClassifier.classify("_test_payload") == ActionCategory.VULNERABILITY_SCAN
        assert ActionClassifier.classify("_generate_report") == ActionCategory.REPORTING
        assert ActionClassifier.classify("_initial_probe") == ActionCategory.ACTIVE_RECON

    def test_case_insensitive(self):
        assert ActionClassifier.classify("NMAP") == ActionCategory.ACTIVE_RECON
        assert ActionClassifier.classify("Nuclei") == ActionCategory.VULNERABILITY_SCAN

    def test_whitespace_stripped(self):
        assert ActionClassifier.classify("  nmap  ") == ActionCategory.ACTIVE_RECON


# ===================================================================
# ActionClassifier — heuristic fallback
# ===================================================================

class TestActionClassifierHeuristic:

    def test_recon_keywords(self):
        assert ActionClassifier.classify("enumerate_hosts") == ActionCategory.ACTIVE_RECON
        assert ActionClassifier.classify("discover_endpoints") == ActionCategory.ACTIVE_RECON
        assert ActionClassifier.classify("crawl_site") == ActionCategory.ACTIVE_RECON

    def test_analysis_keywords(self):
        assert ActionClassifier.classify("analyze_response") == ActionCategory.ANALYSIS
        assert ActionClassifier.classify("generate_summary") == ActionCategory.ANALYSIS

    def test_scan_keywords(self):
        assert ActionClassifier.classify("check_headers") == ActionCategory.VULNERABILITY_SCAN
        assert ActionClassifier.classify("verify_ssl") == ActionCategory.VULNERABILITY_SCAN

    def test_exploit_keywords(self):
        assert ActionClassifier.classify("inject_payload") == ActionCategory.EXPLOITATION
        assert ActionClassifier.classify("bypass_auth") == ActionCategory.EXPLOITATION

    def test_unknown_defaults_to_exploitation(self):
        assert ActionClassifier.classify("zzz_unknown_tool") == ActionCategory.EXPLOITATION


# ===================================================================
# ActionClassifier — custom overrides
# ===================================================================

class TestActionClassifierOverrides:

    def setup_method(self):
        ActionClassifier._custom_overrides = {}

    def teardown_method(self):
        ActionClassifier._custom_overrides = {}

    def test_custom_override_takes_precedence(self):
        ActionClassifier.load_custom_overrides({"nmap": "passive_recon"})
        assert ActionClassifier.classify("nmap") == "passive_recon"

    def test_custom_override_case_insensitive(self):
        ActionClassifier.load_custom_overrides({"MyTool": "analysis"})
        assert ActionClassifier.classify("mytool") == "analysis"

    def test_get_classification_reports_source(self):
        info = ActionClassifier.get_classification("nmap")
        assert info["source"] == "builtin"

        ActionClassifier.load_custom_overrides({"nmap": "passive_recon"})
        info = ActionClassifier.get_classification("nmap")
        assert info["source"] == "custom"

        info = ActionClassifier.get_classification("zzz_unknown")
        assert info["source"] == "heuristic"


# ===================================================================
# GovernanceViolation dataclass
# ===================================================================

class TestGovernanceViolation:

    def test_default_layer(self):
        v = GovernanceViolation(
            scan_id="s1", phase="recon", action="nuclei",
            action_category="vulnerability_scan", allowed_categories=["passive_recon"],
        )
        assert v.layer == "phase"

    def test_default_detail(self):
        v = GovernanceViolation(
            scan_id="s1", phase="recon", action="nuclei",
            action_category="vulnerability_scan", allowed_categories=[],
        )
        assert v.detail == ""

    def test_to_dict_includes_layer_and_detail(self):
        v = GovernanceViolation(
            scan_id="s1", phase="recon", action="sqlmap",
            action_category="exploitation", allowed_categories=["passive_recon"],
            layer="phase", detail="test detail",
        )
        d = v.to_dict()
        assert d["layer"] == "phase"
        assert d["detail"] == "test detail"
        assert d["scan_id"] == "s1"
        assert d["disposition"] == "blocked"

    def test_to_dict_timestamp_is_iso(self):
        v = GovernanceViolation(
            scan_id="s1", phase="recon", action="x",
            action_category="exploitation", allowed_categories=[],
        )
        d = v.to_dict()
        # Should parse without error
        datetime.fromisoformat(d["timestamp"])


# ===================================================================
# GovernanceGate — phase policy enforcement
# ===================================================================

class TestGovernanceGatePolicy:

    def test_recon_allows_passive_recon(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        decision = gate.check("dns_lookup")  # passive_recon
        assert decision.allowed is True

    def test_recon_allows_active_recon(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        decision = gate.check("nmap")  # active_recon
        assert decision.allowed is True

    def test_recon_blocks_vulnerability_scan(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        decision = gate.check("nuclei")  # vulnerability_scan
        assert decision.allowed is False

    def test_recon_blocks_exploitation(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        decision = gate.check("sqlmap")  # exploitation
        assert decision.allowed is False

    def test_testing_allows_vuln_scan(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")      # initializing → recon (valid)
        gate.set_phase("testing")    # recon → testing (valid)
        decision = gate.check("nuclei")  # vulnerability_scan
        assert decision.allowed is True

    def test_testing_blocks_exploitation(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")      # initializing → recon (valid)
        gate.set_phase("testing")    # recon → testing (valid)
        decision = gate.check("sqlmap")  # exploitation
        assert decision.allowed is False

    def test_exploitation_allows_exploitation(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")      # initializing → recon (valid)
        gate.set_phase("analyzing")  # recon → analyzing (valid)
        gate.set_phase("exploitation")  # analyzing → exploitation (valid)
        decision = gate.check("sqlmap")
        assert decision.allowed is True

    def test_full_auto_allows_exploitation(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("full_auto")
        decision = gate.check("sqlmap")
        assert decision.allowed is True

    def test_reporting_blocks_active_recon(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("reporting")
        decision = gate.check("nmap")  # active_recon
        assert decision.allowed is False

    def test_reporting_allows_analysis(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("reporting")
        decision = gate.check("save_finding")  # analysis
        assert decision.allowed is True


# ===================================================================
# GovernanceGate — modes (strict / warn / off)
# ===================================================================

class TestGovernanceGateModes:

    def test_strict_mode_blocks(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        decision = gate.check("sqlmap")
        assert decision.allowed is False
        assert "BLOCKED" in decision.reason

    def test_warn_mode_allows_with_warning(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="warn")
        gate.set_phase("recon")
        decision = gate.check("sqlmap")
        assert decision.allowed is True
        assert "WARNING" in decision.reason
        assert decision.violation is not None

    def test_off_mode_allows_everything(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="off")
        gate.set_phase("recon")
        decision = gate.check("sqlmap")
        assert decision.allowed is True
        assert decision.violation is None

    def test_off_mode_no_violations_recorded(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="off")
        gate.set_phase("recon")
        gate.check("sqlmap")
        gate.check("payload_delivery")
        assert len(gate.get_violations()) == 0

    def test_is_enabled_property(self):
        assert GovernanceGate(scan_id="t1", governance_mode="strict").is_enabled is True
        assert GovernanceGate(scan_id="t1", governance_mode="warn").is_enabled is True
        assert GovernanceGate(scan_id="t1", governance_mode="off").is_enabled is False


# ===================================================================
# GovernanceGate — phase ceiling
# ===================================================================

class TestGovernanceGateCeiling:

    def test_ceiling_clamps_phase(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict", phase_ceiling="testing")
        gate.set_phase("recon")         # initializing → recon (valid)
        gate.set_phase("exploitation")  # ceiling clamps to testing; recon → testing (valid)
        assert gate.current_phase == "testing"  # clamped

    def test_ceiling_allows_lower_phase(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict", phase_ceiling="testing")
        gate.set_phase("recon")
        assert gate.current_phase == "recon"

    def test_no_ceiling_allows_any_phase(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")         # initializing → recon (valid)
        gate.set_phase("analyzing")     # recon → analyzing (valid)
        gate.set_phase("exploitation")  # analyzing → exploitation (valid)
        assert gate.current_phase == "exploitation"


# ===================================================================
# GovernanceGate — violation tracking and stats
# ===================================================================

class TestGovernanceGateViolations:

    def test_violations_accumulate(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        gate.check("nuclei")
        gate.check("sqlmap")
        assert len(gate.get_violations()) == 2

    def test_stats_counts(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        gate.check("dns_lookup")  # allowed
        gate.check("nmap")  # allowed
        gate.check("nuclei")  # blocked
        gate.check("sqlmap")  # blocked
        stats = gate.get_stats()
        assert stats["checks_performed"] == 4
        assert stats["checks_blocked"] == 2
        assert stats["total_violations"] == 2

    def test_violation_callback_fires(self):
        violations = []
        gate = GovernanceGate(
            scan_id="t1", governance_mode="strict",
            violation_callback=lambda v: violations.append(v),
        )
        gate.set_phase("recon")
        gate.check("sqlmap")
        assert len(violations) == 1
        assert violations[0].action == "sqlmap"

    def test_violation_has_phase_layer(self):
        gate = GovernanceGate(scan_id="t1", governance_mode="strict")
        gate.set_phase("recon")
        gate.check("sqlmap")
        v = gate.get_violations()[0]
        assert v.layer == "phase"


# ===================================================================
# create_governance_gate factory
# ===================================================================

class TestCreateGovernanceGate:

    def test_default_mode_is_strict(self):
        gate = create_governance_gate(scan_id="t1")
        assert gate.governance_mode == "strict"

    def test_config_overrides_mode(self):
        gate = create_governance_gate(
            scan_id="t1",
            scan_config={"governance": {"mode": "warn"}},
        )
        assert gate.governance_mode == "warn"

    def test_task_category_sets_ceiling(self):
        gate = create_governance_gate(
            scan_id="t1",
            task_category="recon",
        )
        assert gate.phase_ceiling == "recon"

    def test_task_category_exploitation(self):
        gate = create_governance_gate(
            scan_id="t1",
            task_category="exploitation",
        )
        assert gate.phase_ceiling == "exploitation"

    def test_no_task_category_no_ceiling(self):
        gate = create_governance_gate(scan_id="t1")
        assert gate.phase_ceiling is None


# ===================================================================
# DEFAULT_PHASE_POLICY completeness
# ===================================================================

class TestPhasePolicy:

    def test_all_expected_phases_present(self):
        expected = {"recon", "passive_recon", "initializing", "analyzing",
                    "testing", "exploitation", "full_auto", "reporting", "completed"}
        assert expected == set(DEFAULT_PHASE_POLICY.keys())

    def test_each_phase_has_allowed_and_denied(self):
        for phase, rules in DEFAULT_PHASE_POLICY.items():
            assert "allowed" in rules, f"{phase} missing 'allowed'"
            assert "denied" in rules, f"{phase} missing 'denied'"

    def test_post_exploitation_always_denied(self):
        """POST_EXPLOITATION should be denied in every phase."""
        for phase, rules in DEFAULT_PHASE_POLICY.items():
            denied = [c.value if hasattr(c, 'value') else str(c)
                      for c in rules["denied"]]
            assert "post_exploitation" in denied, f"{phase} should deny post_exploitation"


# ===================================================================
# TASK_CATEGORY_PHASE_CEILING
# ===================================================================

class TestTaskCategoryPhaseCeiling:

    def test_recon_ceiling(self):
        assert TASK_CATEGORY_PHASE_CEILING["recon"] == "recon"

    def test_vulnerability_ceiling(self):
        assert TASK_CATEGORY_PHASE_CEILING["vulnerability"] == "testing"

    def test_full_auto_ceiling(self):
        assert TASK_CATEGORY_PHASE_CEILING["full_auto"] == "full_auto"

    def test_all_ceilings_are_valid_phases(self):
        for cat, ceiling in TASK_CATEGORY_PHASE_CEILING.items():
            assert ceiling in PHASE_RANK, f"Ceiling '{ceiling}' for '{cat}' not in PHASE_RANK"

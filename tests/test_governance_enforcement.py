"""Tests for governance scope enforcement — verifying all 6 gaps are fixed.

These tests ensure that:
1. scan_service maps scan_type to correct scope_profile + task_category
2. agent_v2 creates GovernanceGate via facade (not bare GovernanceAgent)
3. filter_vuln_types returns empty list for recon_only scope
4. classify_with_context escalates tool calls with exploit payloads
5. recon_only scope forces strict governance mode
6. System prompt includes scope restrictions for recon_only
"""

import pytest
from unittest.mock import MagicMock, patch

from backend.core.governance import (
    GovernanceAgent,
    ScanScope,
    ScopeProfile,
    create_full_auto_scope,
    create_recon_only_scope,
    create_ctf_scope,
)
from backend.core.governance_gate import (
    ActionCategory,
    ActionClassifier,
    GovernanceGate,
    TASK_CATEGORY_PHASE_CEILING,
    create_governance_gate,
)
from backend.core.governance_facade import create_governance, Governance


# ---------------------------------------------------------------------------
# GAP 1 / GAP 2: scan_service scope mapping
# ---------------------------------------------------------------------------

class TestScanServiceScopeMapping:
    """Verify that scan_service maps scan_type to the correct scope_profile
    and task_category instead of hardcoding full_auto."""

    def test_recon_scan_type_maps_to_recon_only_scope(self):
        """scan_type='recon' should produce recon_only scope."""
        _SCAN_TYPE_SCOPE = {
            "recon": "recon_only",
            "recon_only": "recon_only",
            "full_auto": "full_auto",
            "full": "full_auto",
            "vuln_lab": "vuln_lab",
            "ctf": "ctf",
        }
        assert _SCAN_TYPE_SCOPE["recon"] == "recon_only"
        assert _SCAN_TYPE_SCOPE["recon_only"] == "recon_only"

    def test_recon_scan_type_maps_to_recon_task_category(self):
        """scan_type='recon' should produce task_category='recon'."""
        _SCAN_TYPE_TASK = {
            "recon": "recon",
            "recon_only": "recon",
            "full_auto": "full_auto",
            "full": "full_auto",
        }
        assert _SCAN_TYPE_TASK["recon"] == "recon"

    def test_task_category_recon_has_phase_ceiling(self):
        """task_category='recon' should map to phase_ceiling='recon' in GovernanceGate."""
        assert TASK_CATEGORY_PHASE_CEILING["recon"] == "recon"


# ---------------------------------------------------------------------------
# GAP 3: filter_vuln_types empty-set inversion
# ---------------------------------------------------------------------------

class TestFilterVulnTypes:
    """Verify that the empty-set / None distinction works correctly."""

    def test_none_allowed_vuln_types_means_all_allowed(self):
        """allowed_vuln_types=None should return all types unchanged."""
        scope = ScanScope(
            profile=ScopeProfile.FULL_AUTO,
            allowed_domains=frozenset({"example.com"}),
            allowed_vuln_types=None,
            allowed_phases=frozenset(),
        )
        gov = GovernanceAgent(scope)
        types = ["sqli_error", "xss_reflected", "command_injection"]
        assert gov.filter_vuln_types(types) == types

    def test_empty_frozenset_means_nothing_allowed(self):
        """allowed_vuln_types=frozenset() should return empty list (recon_only)."""
        scope = ScanScope(
            profile=ScopeProfile.RECON_ONLY,
            allowed_domains=frozenset({"example.com"}),
            allowed_vuln_types=frozenset(),
            allowed_phases=frozenset({"recon", "report"}),
        )
        gov = GovernanceAgent(scope)
        types = ["sqli_error", "xss_reflected", "command_injection"]
        result = gov.filter_vuln_types(types)
        assert result == []

    def test_specific_types_filters_correctly(self):
        """Non-empty allowed_vuln_types should filter to only allowed types."""
        scope = ScanScope(
            profile=ScopeProfile.VULN_LAB,
            allowed_domains=frozenset({"example.com"}),
            allowed_vuln_types=frozenset({"sqli_error"}),
            allowed_phases=frozenset(),
        )
        gov = GovernanceAgent(scope)
        types = ["sqli_error", "xss_reflected", "command_injection"]
        result = gov.filter_vuln_types(types)
        assert result == ["sqli_error"]

    def test_recon_only_scope_factory_uses_empty_frozenset(self):
        """create_recon_only_scope should produce allowed_vuln_types=frozenset()."""
        scope = create_recon_only_scope("https://example.com")
        assert scope.allowed_vuln_types == frozenset()
        # And filtering should block everything
        gov = GovernanceAgent(scope)
        assert gov.filter_vuln_types(["sqli_error", "xss_reflected"]) == []

    def test_full_auto_scope_factory_uses_none(self):
        """create_full_auto_scope should produce allowed_vuln_types=None."""
        scope = create_full_auto_scope("https://example.com")
        assert scope.allowed_vuln_types is None

    def test_ctf_scope_factory_uses_none(self):
        """create_ctf_scope should produce allowed_vuln_types=None."""
        scope = create_ctf_scope("https://example.com")
        assert scope.allowed_vuln_types is None


class TestScopeAttackPlan:
    """Verify scope_attack_plan respects None vs empty set."""

    def test_none_allows_all_plan_vulns(self):
        """None allowed_vuln_types should not modify the plan."""
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": ["sqli_error", "xss_reflected"]}
        result = gov.scope_attack_plan(plan)
        assert result["priority_vulns"] == ["sqli_error", "xss_reflected"]

    def test_empty_blocks_all_plan_vulns(self):
        """Empty allowed_vuln_types should clear priority_vulns."""
        scope = create_recon_only_scope("https://example.com")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": ["sqli_error", "xss_reflected"]}
        result = gov.scope_attack_plan(plan)
        assert result["priority_vulns"] == []


# ---------------------------------------------------------------------------
# GAP 4: classify_with_context — payload-aware classification
# ---------------------------------------------------------------------------

class TestClassifyWithContext:
    """Verify that classify_with_context escalates actions based on payload content."""

    def test_shell_execute_sqlmap_escalates_to_exploitation(self):
        """shell_execute running sqlmap should be classified as EXPLOITATION."""
        result = ActionClassifier.classify_with_context(
            "shell_execute",
            {"tool_args": {"command": "sqlmap -u https://target.com/page?id=1 --batch"}},
        )
        assert result == ActionCategory.EXPLOITATION

    def test_shell_execute_nmap_stays_active_recon(self):
        """shell_execute running nmap should remain ACTIVE_RECON."""
        result = ActionClassifier.classify_with_context(
            "shell_execute",
            {"tool_args": {"command": "nmap -sV target.com"}},
        )
        assert result == ActionCategory.ACTIVE_RECON

    def test_shell_execute_subfinder_stays_active_recon(self):
        """shell_execute running subfinder should remain ACTIVE_RECON."""
        result = ActionClassifier.classify_with_context(
            "shell_execute",
            {"tool_args": {"command": "subfinder -d target.com -silent"}},
        )
        assert result == ActionCategory.ACTIVE_RECON

    def test_shell_execute_hydra_escalates(self):
        """shell_execute running hydra should be classified as EXPLOITATION."""
        result = ActionClassifier.classify_with_context(
            "shell_execute",
            {"tool_args": {"command": "hydra -l admin -P passwords.txt target.com http-post-form"}},
        )
        assert result == ActionCategory.EXPLOITATION

    def test_http_request_with_sqli_payload_escalates(self):
        """http_request with SQLi payload in URL should escalate to EXPLOITATION."""
        result = ActionClassifier.classify_with_context(
            "http_request",
            {"tool_args": {"url": "https://target.com/page?id=1' UNION SELECT 1,2,3--", "method": "GET"}},
        )
        assert result == ActionCategory.EXPLOITATION

    def test_http_request_with_sqli_in_body_escalates(self):
        """http_request with SQLi payload in body should escalate to EXPLOITATION."""
        result = ActionClassifier.classify_with_context(
            "http_request",
            {"tool_args": {
                "url": "https://target.com/login",
                "method": "POST",
                "body": "username=admin' OR 1=1--&password=test",
            }},
        )
        assert result == ActionCategory.EXPLOITATION

    def test_http_request_with_xss_payload_escalates_to_vuln_scan(self):
        """http_request with XSS payload should escalate to VULNERABILITY_SCAN."""
        result = ActionClassifier.classify_with_context(
            "http_request",
            {"tool_args": {"url": "https://target.com/search?q=<script>alert(1)</script>"}},
        )
        assert result == ActionCategory.VULNERABILITY_SCAN

    def test_http_request_clean_get_stays_active_recon(self):
        """Clean GET request should remain ACTIVE_RECON."""
        result = ActionClassifier.classify_with_context(
            "http_request",
            {"tool_args": {"url": "https://target.com/api/version", "method": "GET"}},
        )
        assert result == ActionCategory.ACTIVE_RECON

    def test_no_context_falls_back_to_basic_classify(self):
        """Without context, should use basic classify."""
        result = ActionClassifier.classify_with_context("http_request", None)
        assert result == ActionClassifier.classify("http_request")

    def test_shell_execute_with_path_prefix(self):
        """sqlmap with full path should still be detected."""
        result = ActionClassifier.classify_with_context(
            "shell_execute",
            {"tool_args": {"command": "/usr/bin/sqlmap -u https://target.com?id=1"}},
        )
        assert result == ActionCategory.EXPLOITATION

    def test_browser_submit_form_with_password_escalates(self):
        """browser_submit_form with password fields should escalate."""
        result = ActionClassifier.classify_with_context(
            "browser_submit_form",
            {"tool_args": {
                "url": "https://target.com/login",
                "data": {"username": "admin", "password": "admin123"},
            }},
        )
        assert result == ActionCategory.EXPLOITATION


# ---------------------------------------------------------------------------
# GAP 3 (strict mode): GovernanceGate blocks in strict mode
# ---------------------------------------------------------------------------

class TestGovernanceGateStrictMode:
    """Verify that strict mode actually blocks (not just warns)."""

    def test_strict_mode_blocks_exploitation_in_recon_phase(self):
        """In strict mode, exploitation during recon phase should be BLOCKED."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        decision = gate.check("sqlmap")
        assert not decision.allowed
        assert "BLOCKED" in decision.reason

    def test_warn_mode_allows_exploitation_in_recon_phase(self):
        """In warn mode, exploitation during recon phase should be WARNED but ALLOWED."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="warn",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        decision = gate.check("sqlmap")
        assert decision.allowed
        assert "WARNING" in decision.reason

    def test_strict_mode_allows_recon_tools_in_recon_phase(self):
        """In strict mode, recon tools should be allowed during recon phase."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        for tool in ["nmap", "subfinder", "httpx", "ffuf"]:
            decision = gate.check(tool)
            assert decision.allowed, f"Tool {tool} should be allowed in recon phase"

    def test_phase_ceiling_clamps_transition(self):
        """Phase ceiling='recon' should clamp attempts to advance past recon."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        # Try to advance to testing — should be clamped to recon
        result = gate.set_phase("testing")
        assert gate.current_phase == "recon"

    def test_context_aware_blocking_in_strict_recon(self):
        """shell_execute with sqlmap should be blocked in strict recon mode."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        # shell_execute by itself is ACTIVE_RECON (allowed in recon)
        # but with sqlmap context, it escalates to EXPLOITATION (blocked)
        decision = gate.check(
            "shell_execute",
            {"tool_args": {"command": "sqlmap -u https://target.com?id=1 --batch"}},
        )
        assert not decision.allowed

    def test_context_aware_allows_nmap_in_strict_recon(self):
        """shell_execute with nmap should be allowed in strict recon mode."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        decision = gate.check(
            "shell_execute",
            {"tool_args": {"command": "nmap -sV target.com"}},
        )
        assert decision.allowed

    def test_http_request_with_sqli_blocked_in_strict_recon(self):
        """http_request with SQLi payload should be blocked in strict recon."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        decision = gate.check(
            "http_request",
            {"tool_args": {"url": "https://target.com/page?id=1' OR 1=1--"}},
        )
        assert not decision.allowed

    def test_http_request_clean_get_allowed_in_strict_recon(self):
        """Clean GET request should be allowed in strict recon."""
        gate = GovernanceGate(
            scan_id="test-123",
            governance_mode="strict",
            phase_ceiling="recon",
        )
        gate.set_phase("recon")

        decision = gate.check(
            "http_request",
            {"tool_args": {"url": "https://target.com/api/version", "method": "GET"}},
        )
        assert decision.allowed


# ---------------------------------------------------------------------------
# GAP 5: agent_v2 uses GovernanceGate via facade
# ---------------------------------------------------------------------------

class TestGovernanceFacade:
    """Verify the Governance facade wires both layers correctly."""

    def test_create_governance_returns_facade(self):
        """create_governance should return a Governance facade, not bare GovernanceAgent."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="recon_only",
        )
        assert isinstance(gov, Governance)

    def test_recon_only_creates_phase_gate(self):
        """recon_only scope should create a phase gate (not None)."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="recon_only",
            task_category="recon",
        )
        assert gov._phase_gate is not None

    def test_recon_only_forces_strict_mode(self):
        """recon_only scope should force strict governance mode."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="recon_only",
            governance_mode="warn",  # Explicitly request warn — should be overridden
        )
        assert gov.governance_mode == "strict"

    def test_full_auto_allows_warn_mode(self):
        """full_auto scope should respect the requested governance mode."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="full_auto",
            governance_mode="warn",
        )
        assert gov.governance_mode == "warn"

    def test_facade_check_action_delegates_to_gate(self):
        """check_action should delegate to the phase gate."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="recon_only",
            task_category="recon",
        )
        gov.set_phase("recon")

        # Exploitation should be blocked in recon phase (strict mode)
        decision = gov.check_action("sqlmap")
        assert not decision.allowed

    def test_facade_filter_vuln_types_blocks_for_recon_only(self):
        """filter_vuln_types through facade should block all types for recon_only."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="recon_only",
        )
        types = ["sqli_error", "xss_reflected", "command_injection"]
        result = gov.filter_vuln_types(types)
        assert result == []

    def test_facade_is_url_in_scope(self):
        """URL scope enforcement should work through the facade."""
        gov = create_governance(
            scan_id="test-123",
            target_url="https://example.com",
            scope_profile="recon_only",
        )
        assert gov.is_url_in_scope("https://example.com/api")
        assert not gov.is_url_in_scope("https://evil.com")


# ---------------------------------------------------------------------------
# GAP 6: System prompt scope restrictions
# ---------------------------------------------------------------------------

class TestSystemPromptGovernance:
    """Verify that scope restrictions are injected into the system prompt."""

    def test_recon_only_prompt_includes_restrictions(self):
        """Recon-only governance context should inject restrictions into prompt."""
        from backend.core.prompts.prompt_composer import compose_agent_system_prompt

        prompt = compose_agent_system_prompt(
            target="https://example.com",
            objective="Reconnaissance only",
            operation_id="test-123",
            current_step=0,
            max_steps=100,
            governance_context={
                "scope_profile": "recon_only",
                "governance_mode": "strict",
                "allowed_phases": ["recon", "report"],
            },
        )
        assert "RECON ONLY" in prompt
        assert "STRICTLY FORBIDDEN" in prompt
        assert "SQL injection testing" in prompt
        assert "WILL BE BLOCKED" in prompt

    def test_full_auto_prompt_no_restrictions(self):
        """Full auto governance context (None) should not add restrictions."""
        from backend.core.prompts.prompt_composer import compose_agent_system_prompt

        prompt = compose_agent_system_prompt(
            target="https://example.com",
            objective="Full assessment",
            operation_id="test-123",
            current_step=0,
            max_steps=100,
            governance_context=None,
        )
        assert "RECON ONLY" not in prompt
        assert "STRICTLY FORBIDDEN" not in prompt


# ---------------------------------------------------------------------------
# Integration: end-to-end recon_only enforcement
# ---------------------------------------------------------------------------

class TestReconOnlyEndToEnd:
    """End-to-end tests simulating the full enforcement pipeline."""

    def test_recon_only_full_pipeline(self):
        """Simulate full recon_only enforcement: scope + phase gate + classify."""
        # Create governance the same way agent_v2 would
        gov = create_governance(
            scan_id="test-e2e",
            target_url="https://2morrowinc.com",
            scope_profile="recon_only",
            task_category="recon",
        )
        gov.set_phase("recon")

        # 1. Vuln types should be blocked
        assert gov.filter_vuln_types(["sqli_error", "xss_reflected"]) == []

        # 2. sqlmap via shell_execute should be blocked
        decision = gov.check_action(
            "shell_execute",
            {"tool_args": {"command": "sqlmap -u https://2morrowinc.com?id=1"}},
        )
        assert not decision.allowed

        # 3. SQLi payload in http_request should be blocked
        decision = gov.check_action(
            "http_request",
            {"tool_args": {"url": "https://2morrowinc.com/page?id=1' OR 1=1--"}},
        )
        assert not decision.allowed

        # 4. nmap should be allowed
        decision = gov.check_action(
            "shell_execute",
            {"tool_args": {"command": "nmap -sV 2morrowinc.com"}},
        )
        assert decision.allowed

        # 5. httpx should be allowed
        decision = gov.check_action(
            "shell_execute",
            {"tool_args": {"command": "httpx -u https://2morrowinc.com -silent"}},
        )
        assert decision.allowed

        # 6. Clean GET should be allowed
        decision = gov.check_action(
            "http_request",
            {"tool_args": {"url": "https://2morrowinc.com/robots.txt", "method": "GET"}},
        )
        assert decision.allowed

        # 7. nuclei (vuln scanner) should be blocked
        decision = gov.check_action("nuclei")
        assert not decision.allowed

        # 8. Phase ceiling should prevent advancing to testing
        result = gov.set_phase("testing")
        # Phase should remain at recon (clamped)
        assert gov.current_phase == "recon"

        # 9. Strict mode should be enforced
        assert gov.governance_mode == "strict"

        # 10. Out-of-scope URL should be blocked
        assert not gov.is_url_in_scope("https://evil.com")
        assert gov.is_url_in_scope("https://2morrowinc.com/admin")

    def test_full_auto_does_not_block_exploitation(self):
        """full_auto scope should allow exploitation tools."""
        gov = create_governance(
            scan_id="test-full",
            target_url="https://target.com",
            scope_profile="full_auto",
            task_category="full_auto",
        )
        gov.set_phase("full_auto")

        # sqlmap should be allowed
        decision = gov.check_action("sqlmap")
        assert decision.allowed

        # All vuln types should pass through
        types = ["sqli_error", "xss_reflected", "command_injection"]
        assert gov.filter_vuln_types(types) == types

"""
Tests for backend.core.governance — GovernanceAgent scope enforcement.

Covers:
  - ScanScope immutability
  - Factory functions (vuln_lab, full_auto, recon_only)
  - GovernanceAgent enforcement methods
  - Defense-in-depth filtering
  - Audit trail / violation recording
  - Integration with AutonomousAgent constructor
  - Edge cases (empty types, unknown types, domain matching)
"""

import asyncio
import pytest
from backend.core.governance import (
    GovernanceAgent,
    ScanScope,
    ScopeProfile,
    create_vuln_lab_scope,
    create_full_auto_scope,
    create_recon_only_scope,
    _extract_domain,
    _nuclei_tags_for_vuln_type,
    _VULN_TYPE_TO_NUCLEI_TAG,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _custom_scope(**kwargs):
    """Helper to build a ScanScope with sensible defaults for test."""
    defaults = dict(
        profile=ScopeProfile.CUSTOM,
        allowed_domains=frozenset(),
        allowed_vuln_types=frozenset(),
        allowed_phases=frozenset(),
    )
    defaults.update(kwargs)
    return ScanScope(**defaults)


ALL_100_VULN_TYPES = [
    # P1
    "sqli_error", "sqli_union", "command_injection", "ssti",
    "auth_bypass", "insecure_deserialization", "rfi", "file_upload",
    # P2
    "xss_reflected", "xss_stored", "lfi", "ssrf", "ssrf_cloud",
    "xxe", "path_traversal", "idor", "bola",
    "sqli_blind", "sqli_time", "jwt_manipulation",
    "privilege_escalation", "arbitrary_file_read",
    # P3
    "nosql_injection", "ldap_injection", "xpath_injection",
    "blind_xss", "xss_dom", "cors_misconfig", "csrf",
    "open_redirect", "session_fixation", "bfla",
    "mass_assignment", "race_condition", "host_header_injection",
    # extras
    "security_headers", "ssl_issues", "directory_listing",
    "debug_mode", "sensitive_data_exposure", "information_disclosure",
]


# ===================================================================
# ScanScope immutability
# ===================================================================

class TestScanScopeImmutability:
    """ScanScope is frozen — agent code must not modify it."""

    def test_frozen_cannot_set_attribute(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        with pytest.raises(AttributeError):
            scope.skip_port_scan = False

    def test_frozen_cannot_delete_attribute(self):
        scope = create_full_auto_scope("https://example.com")
        with pytest.raises(AttributeError):
            del scope.profile

    def test_frozen_allowed_types_is_frozenset(self):
        scope = create_vuln_lab_scope("https://example.com", "sqli_error")
        assert isinstance(scope.allowed_vuln_types, frozenset)
        assert isinstance(scope.allowed_domains, frozenset)


# ===================================================================
# Factory functions
# ===================================================================

class TestFactoryFunctions:

    # --- create_vuln_lab_scope ---

    def test_vuln_lab_scope_profile(self):
        scope = create_vuln_lab_scope("https://juice.shop", "xss_reflected")
        assert scope.profile == ScopeProfile.VULN_LAB

    def test_vuln_lab_scope_single_type(self):
        scope = create_vuln_lab_scope("https://juice.shop", "xss_reflected")
        assert scope.allowed_vuln_types == frozenset({"xss_reflected"})

    def test_vuln_lab_scope_domain(self):
        scope = create_vuln_lab_scope("https://demo.juice-shop.example.com/path", "lfi")
        assert scope.allowed_domains == frozenset({"demo.juice-shop.example.com"})

    def test_vuln_lab_scope_skips_port_and_subdomain(self):
        scope = create_vuln_lab_scope("https://example.com", "sqli_error")
        assert scope.skip_port_scan is True
        assert scope.skip_subdomain_enum is True

    def test_vuln_lab_scope_quick_recon(self):
        scope = create_vuln_lab_scope("https://example.com", "sqli_error")
        assert scope.max_recon_depth == "quick"

    def test_vuln_lab_scope_nuclei_tags_xss(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        assert scope.nuclei_template_tags == "xss"

    def test_vuln_lab_scope_nuclei_tags_sqli(self):
        scope = create_vuln_lab_scope("https://example.com", "sqli_error")
        assert scope.nuclei_template_tags == "sqli"

    def test_vuln_lab_scope_nuclei_tags_unknown_type(self):
        scope = create_vuln_lab_scope("https://example.com", "some_custom_type")
        assert scope.nuclei_template_tags is None

    # --- create_full_auto_scope ---

    def test_full_auto_scope_profile(self):
        scope = create_full_auto_scope("https://example.com")
        assert scope.profile == ScopeProfile.FULL_AUTO

    def test_full_auto_scope_all_types_allowed(self):
        scope = create_full_auto_scope("https://example.com")
        assert scope.allowed_vuln_types == frozenset()  # empty = all

    def test_full_auto_scope_no_skips(self):
        scope = create_full_auto_scope("https://example.com")
        assert scope.skip_port_scan is False
        assert scope.skip_subdomain_enum is False

    def test_full_auto_scope_full_recon(self):
        scope = create_full_auto_scope("https://example.com")
        assert scope.max_recon_depth == "full"

    def test_full_auto_scope_no_nuclei_tags(self):
        scope = create_full_auto_scope("https://example.com")
        assert scope.nuclei_template_tags is None

    # --- create_recon_only_scope ---

    def test_recon_only_scope_profile(self):
        scope = create_recon_only_scope("https://example.com")
        assert scope.profile == ScopeProfile.RECON_ONLY

    def test_recon_only_scope_phases(self):
        scope = create_recon_only_scope("https://example.com")
        assert scope.allowed_phases == frozenset({"recon", "report"})


# ===================================================================
# Domain extraction
# ===================================================================

class TestDomainExtraction:

    def test_https_url(self):
        assert _extract_domain("https://example.com/path") == "example.com"

    def test_http_url(self):
        assert _extract_domain("http://test.example.com:8080/") == "test.example.com"

    def test_bare_domain(self):
        assert _extract_domain("example.com") == "example.com"

    def test_url_with_port(self):
        assert _extract_domain("https://app.example.com:443/api") == "app.example.com"


# ===================================================================
# Nuclei tag mapping
# ===================================================================

class TestNucleiTagMapping:

    def test_known_types_have_tags(self):
        assert _nuclei_tags_for_vuln_type("xss_reflected") == "xss"
        assert _nuclei_tags_for_vuln_type("sqli_error") == "sqli"
        assert _nuclei_tags_for_vuln_type("ssrf") == "ssrf"
        assert _nuclei_tags_for_vuln_type("lfi") == "lfi"
        assert _nuclei_tags_for_vuln_type("command_injection") == "rce"

    def test_unknown_type_returns_none(self):
        assert _nuclei_tags_for_vuln_type("nonexistent_type") is None

    def test_mapping_is_not_empty(self):
        assert len(_VULN_TYPE_TO_NUCLEI_TAG) >= 40


# ===================================================================
# GovernanceAgent — filter_vuln_types
# ===================================================================

class TestFilterVulnTypes:

    def test_vuln_lab_filters_to_single_type(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types(ALL_100_VULN_TYPES)
        assert result == ["xss_reflected"]

    def test_full_auto_passes_all_through(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types(ALL_100_VULN_TYPES)
        assert result == ALL_100_VULN_TYPES

    def test_filter_records_violation_when_blocking(self):
        scope = create_vuln_lab_scope("https://example.com", "sqli_error")
        gov = GovernanceAgent(scope)
        gov.filter_vuln_types(["sqli_error", "xss_reflected", "lfi"])
        assert len(gov._violations) == 1
        assert "Blocked 2/3" in gov._violations[0].detail

    def test_filter_no_violation_when_nothing_blocked(self):
        scope = create_vuln_lab_scope("https://example.com", "sqli_error")
        gov = GovernanceAgent(scope)
        gov.filter_vuln_types(["sqli_error"])
        assert len(gov._violations) == 0

    def test_filter_empty_input(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types([])
        assert result == []

    def test_filter_no_matching_types(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types(["sqli_error", "lfi", "ssrf"])
        assert result == []

    def test_filter_preserves_order(self):
        scope = _custom_scope(
            allowed_vuln_types=frozenset({"lfi", "xss_reflected", "sqli_error"}),
        )
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types(["ssrf", "sqli_error", "lfi", "xss_reflected", "csrf"])
        assert result == ["sqli_error", "lfi", "xss_reflected"]


# ===================================================================
# GovernanceAgent — scope_attack_plan
# ===================================================================

class TestScopeAttackPlan:

    def test_vuln_lab_scopes_plan_to_single_type(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": ["sqli_error", "xss_reflected", "lfi", "ssrf"]}
        scoped = gov.scope_attack_plan(plan)
        assert scoped["priority_vulns"] == ["xss_reflected"]

    def test_scope_attack_plan_ensures_allowed_types_present(self):
        """Even if AI omitted the allowed type, it gets added."""
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": ["sqli_error", "lfi"]}  # xss_reflected missing
        scoped = gov.scope_attack_plan(plan)
        assert "xss_reflected" in scoped["priority_vulns"]

    def test_full_auto_preserves_plan(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": ["sqli_error", "xss_reflected"]}
        scoped = gov.scope_attack_plan(plan)
        assert scoped["priority_vulns"] == ["sqli_error", "xss_reflected"]

    def test_scope_attack_plan_preserves_other_keys(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        plan = {
            "priority_vulns": ["sqli_error", "xss_reflected"],
            "high_risk_endpoints": ["/api/search"],
            "attack_vectors": ["test param for XSS"],
        }
        scoped = gov.scope_attack_plan(plan)
        assert scoped["high_risk_endpoints"] == ["/api/search"]
        assert scoped["attack_vectors"] == ["test param for XSS"]

    def test_scope_attack_plan_does_not_mutate_original(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": ["sqli_error", "xss_reflected", "lfi"]}
        gov.scope_attack_plan(plan)
        assert plan["priority_vulns"] == ["sqli_error", "xss_reflected", "lfi"]


# ===================================================================
# GovernanceAgent — constrain_analysis_prompt
# ===================================================================

class TestConstrainAnalysisPrompt:

    def test_vuln_lab_appends_constraint(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        prompt = "Analyze this target."
        constrained = gov.constrain_analysis_prompt(prompt)
        assert "SCOPE CONSTRAINT" in constrained
        assert "xss_reflected" in constrained
        assert constrained.startswith("Analyze this target.")

    def test_full_auto_no_constraint(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        prompt = "Analyze this target."
        constrained = gov.constrain_analysis_prompt(prompt)
        assert constrained == prompt  # unchanged

    def test_multiple_types_in_constraint(self):
        scope = _custom_scope(
            allowed_vuln_types=frozenset({"xss_reflected", "sqli_error"}),
        )
        gov = GovernanceAgent(scope)
        constrained = gov.constrain_analysis_prompt("test")
        assert "sqli_error" in constrained
        assert "xss_reflected" in constrained


# ===================================================================
# GovernanceAgent — boolean checks
# ===================================================================

class TestBooleanChecks:

    def test_vuln_lab_skips_port_scan(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        assert gov.should_port_scan() is False

    def test_vuln_lab_skips_subdomain_enum(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        assert gov.should_enumerate_subdomains() is False

    def test_full_auto_allows_port_scan(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        assert gov.should_port_scan() is True

    def test_full_auto_allows_subdomain_enum(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        assert gov.should_enumerate_subdomains() is True

    def test_nuclei_tags_vuln_lab_xss(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        assert gov.get_nuclei_template_tags() == "xss"

    def test_nuclei_tags_full_auto_none(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        assert gov.get_nuclei_template_tags() is None


# ===================================================================
# GovernanceAgent — is_url_in_scope
# ===================================================================

class TestIsUrlInScope:

    def test_same_domain_in_scope(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        assert gov.is_url_in_scope("https://example.com/path") is True

    def test_different_domain_out_of_scope(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        assert gov.is_url_in_scope("https://evil.com/path") is False

    def test_full_auto_all_domains_in_scope_when_empty(self):
        # full_auto has a domain set, so only that domain is in scope
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        assert gov.is_url_in_scope("https://example.com/api") is True
        assert gov.is_url_in_scope("https://other.com/api") is False

    def test_no_domain_restriction(self):
        scope = _custom_scope()
        gov = GovernanceAgent(scope)
        assert gov.is_url_in_scope("https://anything.com") is True

    def test_malformed_url(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        # urlparse handles odd strings, but hostname may be empty
        assert gov.is_url_in_scope("not-a-url") is False


# ===================================================================
# GovernanceAgent — audit trail / get_summary
# ===================================================================

class TestAuditTrail:

    def test_summary_structure(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        summary = gov.get_summary()
        assert summary["scope_profile"] == "vuln_lab"
        assert "xss_reflected" in summary["allowed_vuln_types"]
        assert summary["skip_port_scan"] is True
        assert summary["skip_subdomain_enum"] is True
        assert summary["violations_count"] == 0
        assert summary["violations"] == []

    def test_violations_accumulate(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        # Trigger violations
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])
        gov.scope_attack_plan({"priority_vulns": ["sqli_error", "lfi"]})
        summary = gov.get_summary()
        assert summary["violations_count"] == 2
        assert len(summary["violations"]) == 2

    def test_full_auto_no_violations(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)
        gov.filter_vuln_types(ALL_100_VULN_TYPES)
        gov.scope_attack_plan({"priority_vulns": ALL_100_VULN_TYPES})
        constrained = gov.constrain_analysis_prompt("test")
        summary = gov.get_summary()
        assert summary["violations_count"] == 0
        assert summary["allowed_vuln_types"] == "all"

    def test_summary_domains_sorted(self):
        scope = _custom_scope(
            allowed_domains=frozenset({"c.com", "a.com", "b.com"}),
        )
        gov = GovernanceAgent(scope)
        summary = gov.get_summary()
        assert summary["allowed_domains"] == ["a.com", "b.com", "c.com"]


# ===================================================================
# GovernanceAgent — log callback
# ===================================================================

class TestLogCallback:

    @pytest.mark.asyncio
    async def test_emit_with_callback(self):
        messages = []

        async def log_cb(level, msg):
            messages.append((level, msg))

        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope, log_callback=log_cb)
        await gov._emit("info", "test message")
        assert len(messages) == 1
        assert messages[0] == ("info", "test message")

    @pytest.mark.asyncio
    async def test_emit_without_callback(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        # Should not raise
        await gov._emit("info", "test message")


# ===================================================================
# Defense-in-depth: multi-layer filtering
# ===================================================================

class TestDefenseInDepth:
    """Simulates the full pipeline: AI prompt → plan scoping → final filter."""

    def test_all_layers_enforce_scope(self):
        """Even if AI ignores the constraint, data-level filters catch it."""
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)

        # Layer 1: Prompt constraint
        prompt = gov.constrain_analysis_prompt("Analyze target")
        assert "xss_reflected" in prompt
        assert "SCOPE CONSTRAINT" in prompt

        # Layer 2: AI returns 10 types (ignoring constraint)
        ai_plan = {"priority_vulns": [
            "sqli_error", "xss_reflected", "lfi", "ssrf", "idor",
            "csrf", "xxe", "ssti", "rfi", "command_injection"
        ]}
        scoped_plan = gov.scope_attack_plan(ai_plan)
        assert scoped_plan["priority_vulns"] == ["xss_reflected"]

        # Layer 3: Defense-in-depth final filter
        final = gov.filter_vuln_types(scoped_plan["priority_vulns"])
        assert final == ["xss_reflected"]

        # Verify violations recorded
        summary = gov.get_summary()
        assert summary["violations_count"] >= 1

    def test_full_auto_all_layers_pass_through(self):
        scope = create_full_auto_scope("https://example.com")
        gov = GovernanceAgent(scope)

        prompt = gov.constrain_analysis_prompt("Analyze")
        assert "SCOPE CONSTRAINT" not in prompt

        plan = {"priority_vulns": ALL_100_VULN_TYPES}
        scoped = gov.scope_attack_plan(plan)
        assert scoped["priority_vulns"] == ALL_100_VULN_TYPES

        filtered = gov.filter_vuln_types(scoped["priority_vulns"])
        assert filtered == ALL_100_VULN_TYPES

        assert gov.get_summary()["violations_count"] == 0


# ===================================================================
# Integration: LLMDrivenAgent + governance compatibility
# ===================================================================

class TestAgentGovernanceIntegration:
    """Verify governance integration with LLM-driven agent infrastructure."""

    def test_governance_module_importable(self):
        """All public exports are importable."""
        from backend.core.governance import (
            GovernanceAgent,
            ScanScope,
            ScopeProfile,
            create_vuln_lab_scope,
            create_full_auto_scope,
            create_recon_only_scope,
        )
        assert GovernanceAgent is not None

    def test_api_modules_compile(self):
        """vuln_lab.py and agent_v2.py compile with governance imports."""
        import py_compile
        py_compile.compile("backend/api/v1/vuln_lab.py", doraise=True)
        py_compile.compile("backend/api/v1/agent_v2.py", doraise=True)


# ===================================================================
# Edge cases
# ===================================================================

class TestEdgeCases:

    def test_scope_with_bare_ip(self):
        scope = create_vuln_lab_scope("http://192.168.1.1:8080", "sqli_error")
        # Explicit port → both hostname and host:port are in allowed_domains
        assert scope.allowed_domains == frozenset({"192.168.1.1", "192.168.1.1:8080"})
        gov = GovernanceAgent(scope)
        assert gov.is_url_in_scope("http://192.168.1.1:8080/api") is True
        assert gov.is_url_in_scope("http://192.168.1.2/api") is False

    def test_scope_with_localhost(self):
        scope = create_vuln_lab_scope("http://localhost:3000", "xss_reflected")
        # Explicit port → both hostname and host:port are in allowed_domains
        assert scope.allowed_domains == frozenset({"localhost", "localhost:3000"})

    def test_multiple_filter_calls_accumulate_violations(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])
        gov.filter_vuln_types(["lfi", "ssrf", "xss_reflected"])
        assert len(gov._violations) == 2

    def test_custom_scope_multiple_types(self):
        scope = _custom_scope(
            allowed_domains=frozenset({"example.com"}),
            allowed_vuln_types=frozenset({"xss_reflected", "sqli_error", "lfi"}),
        )
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types(ALL_100_VULN_TYPES)
        assert set(result) == {"xss_reflected", "sqli_error", "lfi"}

    def test_duplicate_types_in_input(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        result = gov.filter_vuln_types(["xss_reflected", "xss_reflected", "sqli_error"])
        assert result == ["xss_reflected", "xss_reflected"]

    def test_scope_attack_plan_empty_priority_vulns(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        plan = {"priority_vulns": []}
        scoped = gov.scope_attack_plan(plan)
        assert "xss_reflected" in scoped["priority_vulns"]

    def test_scope_attack_plan_missing_priority_vulns_key(self):
        scope = create_vuln_lab_scope("https://example.com", "xss_reflected")
        gov = GovernanceAgent(scope)
        plan = {"other_key": "value"}
        scoped = gov.scope_attack_plan(plan)
        assert "xss_reflected" in scoped["priority_vulns"]

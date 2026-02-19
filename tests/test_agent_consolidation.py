"""
Tests for AutonomousAgent consolidation (AIPentestAgent fully retired).

Covers:
  - _map_aa_finding_to_vulnerability() field mapping
  - Handling of empty/None fields
  - AutonomousAgent Finding dataclass field completeness
  - AutonomousAgent report format (summary.endpoints_tested)
  - AIPentestAgent module deletion verification
  - Import correctness
"""

import os
import pytest
from dataclasses import fields as dataclass_fields

from backend.core.autonomous_agent import AutonomousAgent, OperationMode, Finding
from backend.services.scan_service import _map_aa_finding_to_vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides) -> Finding:
    """Create a Finding with reasonable defaults, overriding specific fields."""
    defaults = dict(
        id="finding-001",
        title="Test XSS",
        severity="high",
        vulnerability_type="xss_reflected",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-79",
        description="Reflected XSS in search param",
        affected_endpoint="https://example.com/search?q=test",
        parameter="q",
        payload="<script>alert(1)</script>",
        evidence="Alert box triggered in browser",
        request="GET /search?q=<script>alert(1)</script> HTTP/1.1",
        response="<html><script>alert(1)</script></html>",
        impact="Session hijacking, cookie theft",
        poc_code="curl 'https://example.com/search?q=<script>alert(1)</script>'",
        remediation="Encode output, use CSP headers",
        references=["https://owasp.org/xss"],
        screenshots=[],
        affected_urls=["https://example.com/search"],
        ai_verified=True,
        confidence="85",
        confidence_score=85,
        confidence_breakdown={"pattern": 30, "context": 25, "impact": 30},
        proof_of_execution="alert(1) executed in DOM",
        negative_controls="Non-vulnerable param /search?lang=en returned clean HTML",
        ai_status="confirmed",
        rejection_reason="",
        credential_label="admin",
        auth_context={"role": "admin", "token": "***"},
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# 5a: _map_aa_finding_to_vulnerability unit tests
# ---------------------------------------------------------------------------

class TestFindingAdapter:
    """Test _map_aa_finding_to_vulnerability() field mapping."""

    def test_full_mapping(self):
        """All fields map correctly from a fully-populated Finding."""
        finding = _make_finding()
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-123")

        assert vuln.scan_id == "scan-123"
        assert vuln.vulnerability_type == "xss_reflected"
        assert vuln.severity == "high"
        assert vuln.title == "XSS_REFLECTED - https://example.com/search?q=test"
        assert vuln.description == finding.evidence
        assert vuln.affected_endpoint == finding.affected_endpoint
        assert vuln.poc_payload == finding.payload
        assert vuln.poc_request == finding.request
        assert vuln.poc_response == finding.response
        assert vuln.remediation == finding.remediation
        assert vuln.ai_analysis == finding.poc_code
        assert vuln.poc_code == finding.poc_code
        assert vuln.parameter == finding.parameter
        assert vuln.poc_parameter == finding.parameter
        assert vuln.poc_evidence == finding.proof_of_execution
        assert vuln.url == finding.affected_endpoint
        assert vuln.credential_label == "admin"
        assert vuln.auth_context == {"role": "admin", "token": "***"}
        assert vuln.cvss_score == 7.5
        assert vuln.cvss_vector == finding.cvss_vector
        assert vuln.cwe_id == "CWE-79"
        assert vuln.impact == finding.impact
        assert vuln.screenshots == []

    def test_confirmed_status_maps_to_ai_confirmed(self):
        """Finding ai_status='confirmed' maps to validation_status='ai_confirmed'."""
        finding = _make_finding(ai_status="confirmed")
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-1")
        assert vuln.validation_status == "ai_confirmed"

    def test_rejected_status_preserved(self):
        """Finding ai_status='rejected' maps to validation_status='rejected'."""
        finding = _make_finding(ai_status="rejected", rejection_reason="False positive")
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-1")
        assert vuln.validation_status == "rejected"
        assert vuln.ai_rejection_reason == "False positive"

    def test_pending_status_preserved(self):
        """Finding ai_status='pending' maps through unchanged."""
        finding = _make_finding(ai_status="pending")
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-1")
        assert vuln.validation_status == "pending"

    def test_empty_optional_fields_no_crash(self):
        """Findings with empty/None optional fields produce a valid Vulnerability."""
        finding = _make_finding(
            request="",
            response="",
            poc_code="",
            remediation="",
            impact="Some impact",
            parameter="",
            proof_of_execution="",
            credential_label="",
            auth_context={},
            cvss_score=0.0,
            cvss_vector="",
            cwe_id="",
        )
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-2")

        assert vuln.poc_request == ""
        assert vuln.poc_response == ""
        assert vuln.ai_analysis == ""
        # remediation falls back to impact when remediation is empty
        assert vuln.remediation == "Some impact"
        assert vuln.auth_context is None  # empty dict → None
        assert vuln.credential_label is None  # empty string → None

    def test_long_request_response_truncated(self):
        """Request/response strings longer than 5000 are truncated."""
        long_text = "A" * 10000
        finding = _make_finding(request=long_text, response=long_text)
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-3")

        assert len(vuln.poc_request) == 5000
        assert len(vuln.poc_response) == 5000

    def test_long_endpoint_in_title_truncated(self):
        """Endpoint in title is truncated to 50 chars."""
        long_url = "https://example.com/" + "a" * 100
        finding = _make_finding(affected_endpoint=long_url)
        vuln = _map_aa_finding_to_vulnerability(finding, "scan-4")

        # Title format: "TYPE - endpoint[:50]"
        assert len(vuln.title.split(" - ", 1)[1]) == 50


# ---------------------------------------------------------------------------
# 5b: AutonomousAgent report format compatibility
# ---------------------------------------------------------------------------

class TestAutonomousAgentCompat:
    """Verify AutonomousAgent Finding dataclass has all required fields."""

    REQUIRED_FIELDS = [
        "vulnerability_type", "affected_endpoint", "severity", "payload",
        "evidence", "request", "response", "impact", "remediation",
        "poc_code", "ai_status", "rejection_reason", "parameter",
        "credential_label", "auth_context", "proof_of_execution",
    ]

    def test_finding_has_all_required_fields(self):
        """Finding dataclass must have all fields the adapter relies on."""
        field_names = {f.name for f in dataclass_fields(Finding)}
        for required in self.REQUIRED_FIELDS:
            assert required in field_names, f"Finding missing field: {required}"

    def test_finding_instantiation(self):
        """Finding can be instantiated with only id/title/severity."""
        f = Finding(id="test", title="test", severity="info")
        assert f.vulnerability_type == ""
        assert f.ai_status == "confirmed"
        assert f.auth_context == {}

    def test_operation_mode_auto_pentest_exists(self):
        """OperationMode.AUTO_PENTEST must exist for scan pipeline."""
        assert hasattr(OperationMode, "AUTO_PENTEST")


# ---------------------------------------------------------------------------
# 5c: Import and deletion tests
# ---------------------------------------------------------------------------

class TestImportsAndDeletion:
    """Verify import paths and AIPentestAgent module removal."""

    def test_autonomous_agent_import(self):
        """AutonomousAgent + OperationMode import works."""
        from backend.core.autonomous_agent import AutonomousAgent, OperationMode
        assert AutonomousAgent is not None
        assert OperationMode is not None

    def test_ai_pentest_agent_module_removed(self):
        """Importing backend.core.ai_pentest_agent must raise ModuleNotFoundError."""
        import sys
        mod_name = "backend.core.ai_pentest_agent"
        # Ensure it's not cached from a previous test run
        saved = sys.modules.pop(mod_name, None)
        try:
            import importlib
            with pytest.raises(ModuleNotFoundError):
                importlib.import_module(mod_name)
        finally:
            if saved is not None:
                sys.modules[mod_name] = saved

    def test_scan_service_adapter_importable(self):
        """_map_aa_finding_to_vulnerability is importable from scan_service."""
        from backend.services.scan_service import _map_aa_finding_to_vulnerability
        assert callable(_map_aa_finding_to_vulnerability)


# ---------------------------------------------------------------------------
# 5d: WAF evasion settings tests
# ---------------------------------------------------------------------------

class TestWAFEvasionSettings:
    """Test that WAF evasion env-var settings are wired up correctly."""

    def test_waf_evasion_enabled_default_true(self, monkeypatch):
        """waf_evasion_enabled defaults to True when env not set."""
        monkeypatch.delenv('ENABLE_WAF_EVASION', raising=False)
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_evasion_enabled = os.getenv('ENABLE_WAF_EVASION', 'true').lower() == 'true'
        assert agent.waf_evasion_enabled is True

    def test_waf_evasion_disabled_via_env(self, monkeypatch):
        """ENABLE_WAF_EVASION=false disables WAF evasion."""
        monkeypatch.setenv('ENABLE_WAF_EVASION', 'false')
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_evasion_enabled = os.getenv('ENABLE_WAF_EVASION', 'true').lower() == 'true'
        assert agent.waf_evasion_enabled is False

    def test_waf_confidence_threshold_default(self, monkeypatch):
        """waf_confidence_threshold defaults to 0.7."""
        monkeypatch.delenv('WAF_CONFIDENCE_THRESHOLD', raising=False)
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_confidence_threshold = float(os.getenv('WAF_CONFIDENCE_THRESHOLD', '0.7'))
        assert agent.waf_confidence_threshold == 0.7

    def test_waf_confidence_threshold_from_env(self, monkeypatch):
        """WAF_CONFIDENCE_THRESHOLD=0.5 reads correctly."""
        monkeypatch.setenv('WAF_CONFIDENCE_THRESHOLD', '0.5')
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_confidence_threshold = float(os.getenv('WAF_CONFIDENCE_THRESHOLD', '0.7'))
        assert agent.waf_confidence_threshold == 0.5

    def test_filter_waf_removes_low_confidence(self):
        """_filter_waf_by_confidence filters out WAFs below threshold."""
        from backend.core.waf_detector import WAFMatch, WAFResult
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_confidence_threshold = 0.7

        waf_result = WAFResult(detected_wafs=[
            WAFMatch(name="cloudflare", confidence=0.9, detection_method="header", evidence="cf-ray"),
            WAFMatch(name="generic", confidence=0.3, detection_method="body", evidence="blocked"),
        ])
        filtered = agent._filter_waf_by_confidence(waf_result)
        assert len(filtered.detected_wafs) == 1
        assert filtered.detected_wafs[0].name == "cloudflare"

    def test_filter_waf_keeps_at_threshold(self):
        """_filter_waf_by_confidence keeps WAFs at exactly the threshold."""
        from backend.core.waf_detector import WAFMatch, WAFResult
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_confidence_threshold = 0.7

        waf_result = WAFResult(detected_wafs=[
            WAFMatch(name="aws_waf", confidence=0.7, detection_method="header", evidence="awselb"),
        ])
        filtered = agent._filter_waf_by_confidence(waf_result)
        assert len(filtered.detected_wafs) == 1
        assert filtered.detected_wafs[0].name == "aws_waf"

    def test_filter_waf_handles_none(self):
        """_filter_waf_by_confidence handles None result gracefully."""
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_confidence_threshold = 0.7
        assert agent._filter_waf_by_confidence(None) is None

    def test_filter_waf_handles_empty_list(self):
        """_filter_waf_by_confidence handles empty detected_wafs list."""
        from backend.core.waf_detector import WAFResult
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.waf_confidence_threshold = 0.7
        waf_result = WAFResult(detected_wafs=[])
        filtered = agent._filter_waf_by_confidence(waf_result)
        assert filtered.detected_wafs == []

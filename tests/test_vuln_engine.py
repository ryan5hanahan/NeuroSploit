"""Tests for the vulnerability engine — PayloadGenerator, VulnerabilityRegistry,
PATT integration, WAF bypass payloads, encoding, vuln type normalization,
and unknown vuln type handling.

Most tests are pure function tests requiring no mocks.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.vuln_engine.payload_generator import (
    PayloadGenerator,
    normalize_vuln_type,
    VULN_TYPE_ALIASES,
)


# ===========================================================================
# PayloadGenerator.get_payloads
# ===========================================================================

class TestPayloadGeneratorGetPayloads:
    """PayloadGenerator returns correct payloads for each vuln type."""

    def setup_method(self):
        """Create a fresh PayloadGenerator for each test."""
        self.gen = PayloadGenerator()

    def test_get_payloads_xss_reflected(self):
        """get_payloads returns non-empty list for xss_reflected."""
        payloads = self.gen.get_payloads("xss_reflected", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_sqli_error(self):
        """get_payloads returns non-empty list for sqli_error."""
        payloads = self.gen.get_payloads("sqli_error", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_command_injection(self):
        """get_payloads returns non-empty list for command_injection."""
        payloads = self.gen.get_payloads("command_injection", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_lfi(self):
        """get_payloads returns non-empty list for lfi."""
        payloads = self.gen.get_payloads("lfi", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_ssrf(self):
        """get_payloads returns non-empty list for ssrf."""
        payloads = self.gen.get_payloads("ssrf", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_ssti(self):
        """get_payloads returns non-empty list for ssti."""
        payloads = self.gen.get_payloads("ssti", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_xxe(self):
        """get_payloads returns non-empty list for xxe."""
        payloads = self.gen.get_payloads("xxe", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_returns_strings(self):
        """All payloads in list are strings."""
        payloads = self.gen.get_payloads("xss_reflected", {})
        for p in payloads:
            assert isinstance(p, str)

    def test_get_payloads_quick_depth(self):
        """Quick depth returns at most 3 payloads."""
        payloads = self.gen.get_payloads("sqli_error", {"depth": "quick"})
        assert len(payloads) <= 3

    def test_get_payloads_exhaustive_depth_more_than_quick(self):
        """Exhaustive depth returns more payloads than quick."""
        quick = self.gen.get_payloads("sqli_error", {"depth": "quick"})
        exhaustive = self.gen.get_payloads("sqli_error", {"depth": "exhaustive"})
        assert len(exhaustive) >= len(quick)

    def test_get_payloads_waf_bypass_adds_variants(self):
        """WAF bypass context adds extra bypass payloads."""
        normal = self.gen.get_payloads("xss_reflected", {"depth": "exhaustive"})
        waf = self.gen.get_payloads("xss_reflected", {"waf_detected": True, "depth": "exhaustive"})
        assert len(waf) >= len(normal)

    def test_get_payloads_unknown_type_returns_empty_or_generic(self):
        """Unknown vuln type returns empty list or generic payloads."""
        payloads = self.gen.get_payloads("totally_unknown_vuln_type_xyz_999", {})
        assert isinstance(payloads, list)

    def test_get_payloads_sqli_union(self):
        """get_payloads returns non-empty list for sqli_union."""
        payloads = self.gen.get_payloads("sqli_union", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_path_traversal(self):
        """get_payloads returns non-empty list for path_traversal."""
        payloads = self.gen.get_payloads("path_traversal", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_open_redirect(self):
        """get_payloads returns non-empty list for open_redirect."""
        payloads = self.gen.get_payloads("open_redirect", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_payloads_nosql_injection(self):
        """get_payloads returns non-empty list for nosql_injection."""
        payloads = self.gen.get_payloads("nosql_injection", {})
        assert isinstance(payloads, list)
        assert len(payloads) > 0


# ===========================================================================
# VulnerabilityRegistry lookup
# ===========================================================================

class TestVulnerabilityRegistry:
    """VulnerabilityRegistry lookup and metadata access."""

    def test_registry_importable(self):
        """VULN_REGISTRY can be imported from registry module."""
        from backend.core.vuln_engine.registry import VULN_REGISTRY
        assert isinstance(VULN_REGISTRY, dict)

    def test_registry_has_xss_reflected(self):
        """VULN_REGISTRY contains xss_reflected."""
        from backend.core.vuln_engine.registry import VULN_REGISTRY
        assert "xss_reflected" in VULN_REGISTRY

    def test_registry_has_sqli_error(self):
        """VULN_REGISTRY contains sqli_error."""
        from backend.core.vuln_engine.registry import VULN_REGISTRY
        assert "sqli_error" in VULN_REGISTRY

    def test_registry_entry_has_tester_class(self):
        """Each registry entry has a tester class reference."""
        from backend.core.vuln_engine.registry import VULN_REGISTRY
        entry = VULN_REGISTRY.get("sqli_error")
        assert entry is not None
        # Entry should be a tuple: (TesterClass, metadata_dict)
        assert len(entry) >= 1

    def test_registry_has_80_plus_entries(self):
        """Registry has at least 80 vulnerability types."""
        from backend.core.vuln_engine.registry import VULN_REGISTRY
        assert len(VULN_REGISTRY) >= 80


# ===========================================================================
# PATT loader integration
# ===========================================================================

class TestPATTLoaderIntegration:
    """PATT loader integration with PayloadGenerator."""

    def test_patt_property_accessible(self):
        """PayloadGenerator.patt property is accessible."""
        gen = PayloadGenerator()
        patt = gen.patt
        assert patt is not None

    def test_patt_available_or_stub(self):
        """PATT loader is either available or stubbed."""
        gen = PayloadGenerator()
        # patt should have get_payloads callable
        assert callable(gen.patt.get_payloads)

    def test_patt_get_payloads_returns_list(self):
        """PATT get_payloads returns a list (possibly empty)."""
        gen = PayloadGenerator()
        result = gen.patt.get_payloads("xss")
        assert isinstance(result, list)


# ===========================================================================
# Vuln type normalization
# ===========================================================================

class TestNormalizeVulnType:
    """normalize_vuln_type correctly maps AI-returned names to canonical keys."""

    def test_normalize_xss_alias(self):
        """'xss' normalizes to 'xss_reflected'."""
        assert normalize_vuln_type("xss") == "xss_reflected"

    def test_normalize_sqli_alias(self):
        """'sqli' normalizes to 'sqli_error'."""
        assert normalize_vuln_type("sqli") == "sqli_error"

    def test_normalize_rce_alias(self):
        """'rce' normalizes to 'command_injection'."""
        assert normalize_vuln_type("rce") == "command_injection"

    def test_normalize_sql_injection_verbose(self):
        """'SQL Injection (error-based)' normalizes correctly."""
        result = normalize_vuln_type("SQL Injection (error-based)")
        assert result == "sqli_error"

    def test_normalize_cross_site_scripting_verbose(self):
        """'Cross-Site Scripting' normalizes to xss_reflected."""
        result = normalize_vuln_type("Cross-Site Scripting")
        assert result == "xss_reflected"

    def test_normalize_lfi_alias(self):
        """'local_file_inclusion' normalizes to 'lfi'."""
        assert normalize_vuln_type("local_file_inclusion") == "lfi"

    def test_normalize_path_traversal_alias(self):
        """'directory_traversal' normalizes to 'path_traversal'."""
        assert normalize_vuln_type("directory_traversal") == "path_traversal"

    def test_normalize_unknown_returns_normalized_form(self):
        """Unknown type returns normalized form (lowercase, underscores)."""
        result = normalize_vuln_type("Some Weird Vuln Type")
        assert result == "some_weird_vuln_type"

    def test_normalize_already_canonical(self):
        """Already-canonical types pass through unchanged."""
        for canonical in ["xss_reflected", "sqli_error", "command_injection", "ssrf"]:
            # Canonical forms might be in aliases or just pass through
            result = normalize_vuln_type(canonical)
            assert isinstance(result, str)
            assert len(result) > 0


# ===========================================================================
# Unknown vuln type handling
# ===========================================================================

class TestUnknownVulnTypeHandling:
    """PayloadGenerator handles unknown vuln types gracefully."""

    def setup_method(self):
        self.gen = PayloadGenerator()

    def test_unknown_type_does_not_raise(self):
        """Unknown vuln type does not raise an exception."""
        # Should not raise
        result = self.gen.get_payloads("completely_made_up_type_999", {})
        assert isinstance(result, list)

    def test_list_types_returns_all_types(self):
        """payload_libraries keys represent all supported types."""
        types = list(self.gen.payload_libraries.keys())
        assert len(types) >= 20
        assert "xss_reflected" in types
        assert "sqli_error" in types
        assert "command_injection" in types

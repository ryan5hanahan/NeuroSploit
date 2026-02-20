"""
Phase 1 Tests — Polyglot Payload Expansion

Tests expanded polyglot payloads and get_polyglot_payloads() method.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.vuln_engine.payload_generator import PayloadGenerator


@pytest.fixture
def pg():
    return PayloadGenerator()


class TestPolyglotExpansion:
    """Tests for expanded polyglot payloads."""

    def test_polyglot_count_expanded(self, pg):
        """Polyglot list should have ~30 payloads (up from 8)."""
        polyglots = pg.payload_libraries.get("polyglot", [])
        assert len(polyglots) >= 25, f"Expected 25+ polyglots, got {len(polyglots)}"

    def test_polyglot_sqli_xss_combos(self, pg):
        """Should contain SQLi+XSS combination payloads."""
        polyglots = pg.payload_libraries["polyglot"]
        sqli_xss = [p for p in polyglots if "OR" in p and "script" in p.lower()]
        assert len(sqli_xss) >= 1, "Should have at least one SQLi+XSS combo"

    def test_polyglot_ssti_xss_combos(self, pg):
        """Should contain SSTI+XSS combination payloads."""
        polyglots = pg.payload_libraries["polyglot"]
        ssti_xss = [p for p in polyglots if "{{" in p and ("script" in p.lower() or "onerror" in p.lower() or "onload" in p.lower())]
        assert len(ssti_xss) >= 1, "Should have at least one SSTI+XSS combo"

    def test_polyglot_cmdi_sqli_combos(self, pg):
        """Should contain command injection+SQLi combos."""
        polyglots = pg.payload_libraries["polyglot"]
        cmdi_sqli = [p for p in polyglots if ("ls" in p or "cat" in p or "id" in p or "whoami" in p) and ("SELECT" in p or "OR" in p)]
        assert len(cmdi_sqli) >= 1, "Should have at least one CMDi+SQLi combo"

    def test_polyglot_path_traversal_ssti(self, pg):
        """Should contain path traversal+SSTI combos."""
        polyglots = pg.payload_libraries["polyglot"]
        pt_ssti = [p for p in polyglots if ".." in p and ("{{" in p or "${" in p or "<%" in p)]
        assert len(pt_ssti) >= 1, "Should have at least one path traversal+SSTI combo"

    def test_polyglot_xxe_ssrf_combos(self, pg):
        """Should contain XXE+SSRF combos."""
        polyglots = pg.payload_libraries["polyglot"]
        xxe_ssrf = [p for p in polyglots if "<!DOCTYPE" in p or "<!ENTITY" in p]
        assert len(xxe_ssrf) >= 1, "Should have at least one XXE+SSRF combo"

    def test_polyglot_encoding_variants(self, pg):
        """Should contain URL-encoded and double-encoded variants."""
        polyglots = pg.payload_libraries["polyglot"]
        encoded = [p for p in polyglots if "%27" in p or "%2527" in p or "\\u" in p]
        assert len(encoded) >= 2, "Should have at least 2 encoding variants"

    def test_polyglot_no_duplicates(self, pg):
        """All polyglot payloads should be unique."""
        polyglots = pg.payload_libraries["polyglot"]
        assert len(polyglots) == len(set(polyglots)), "Polyglot payloads contain duplicates"


class TestGetPolyglotPayloads:
    """Tests for the get_polyglot_payloads() method."""

    def test_method_exists(self, pg):
        assert hasattr(pg, "get_polyglot_payloads")
        assert callable(pg.get_polyglot_payloads)

    def test_default_max_count(self, pg):
        """Default returns up to 10 payloads."""
        result = pg.get_polyglot_payloads()
        assert len(result) <= 10
        assert len(result) > 0

    def test_custom_max_count(self, pg):
        result = pg.get_polyglot_payloads(max_count=5)
        assert len(result) <= 5

    def test_zero_max_returns_all(self, pg):
        """max_count=0 should return all payloads."""
        result = pg.get_polyglot_payloads(max_count=0)
        all_polyglots = pg.payload_libraries["polyglot"]
        assert len(result) == len(all_polyglots)

    def test_returns_list_of_strings(self, pg):
        result = pg.get_polyglot_payloads()
        assert isinstance(result, list)
        for p in result:
            assert isinstance(p, str)


class TestToolSchemaIncludePolyglot:
    """Tests that the get_payloads tool schema includes include_polyglot."""

    def test_schema_has_include_polyglot(self):
        from backend.core.llm_agent_tools import GET_PAYLOADS
        props = GET_PAYLOADS["inputSchema"]["properties"]
        assert "include_polyglot" in props
        assert props["include_polyglot"]["type"] == "boolean"

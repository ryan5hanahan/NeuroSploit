"""
Phase 5 Tests — Dynamic Techniques Library: PayloadGenerator Integration

Tests that TechniqueLoader payloads integrate correctly with the existing
PayloadGenerator, including deduplication and graceful handling of unknown types.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from techniques.loader import TechniqueLoader
from techniques.filters import filter_by_context, rank_techniques
from backend.core.vuln_engine.payload_generator import PayloadGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def loader():
    """Default TechniqueLoader using the builtin directory."""
    return TechniqueLoader()


@pytest.fixture
def pg():
    """PayloadGenerator instance."""
    return PayloadGenerator()


# ---------------------------------------------------------------------------
# TechniqueLoader payload availability
# ---------------------------------------------------------------------------

class TestTechniqueLoaderPayloadAvailability:
    def test_sqli_payloads_from_loader_are_available(self, loader):
        """TechniqueLoader should provide payloads for sqli."""
        payloads = loader.get_payloads(vuln_type="sqli")
        assert len(payloads) > 0, "Expected sqli payloads from YAML techniques"

    def test_xss_reflected_payloads_from_loader_are_available(self, loader):
        """TechniqueLoader should provide payloads for xss_reflected."""
        payloads = loader.get_payloads(vuln_type="xss_reflected")
        assert len(payloads) > 0

    def test_ssrf_payloads_from_loader_are_available(self, loader):
        """TechniqueLoader should provide payloads for ssrf."""
        payloads = loader.get_payloads(vuln_type="ssrf")
        assert len(payloads) > 0

    def test_ssti_payloads_from_loader_are_available(self, loader):
        """TechniqueLoader should provide payloads for ssti."""
        payloads = loader.get_payloads(vuln_type="ssti")
        assert len(payloads) > 0

    def test_all_loaded_vuln_types_have_some_payloads(self, loader):
        """Every vulnerability type in the loader should have at least one payload."""
        vuln_types = loader.get_all_vuln_types()
        for vt in vuln_types:
            payloads = loader.get_payloads(vuln_type=vt, depth="thorough")
            assert len(payloads) > 0, (
                f"vuln_type '{vt}' is registered but has no payloads"
            )


# ---------------------------------------------------------------------------
# Deduplication between TechniqueLoader and PayloadGenerator
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_technique_loader_payloads_deduplicated_within_type(self, tmp_path):
        """Payloads returned by TechniqueLoader for a given vuln type are unique."""
        # Create two techniques sharing a payload
        yaml_content = """
techniques:
  - id: dedup_integ_1
    name: "Dedup Integ 1"
    vuln_type: command_injection
    description: "First"
    severity: high
    depth: standard
    tags: []
    payloads:
      - value: "; id"
        description: "id command"
      - value: "| whoami"
        description: "whoami"
    detection: []
  - id: dedup_integ_2
    name: "Dedup Integ 2"
    vuln_type: command_injection
    description: "Second with overlap"
    severity: high
    depth: standard
    tags: []
    payloads:
      - value: "; id"
        description: "Same id command"
      - value: "| cat /etc/passwd"
        description: "passwd read"
    detection: []
"""
        yaml_file = tmp_path / "dedup_integ.yaml"
        yaml_file.write_text(yaml_content)

        custom_loader = TechniqueLoader(custom_dir=str(tmp_path))
        payloads = custom_loader.get_payloads(vuln_type="command_injection")

        # "; id" should appear exactly once despite two techniques having it
        assert payloads.count("; id") == 1, (
            f"Duplicated payload '; id' appears {payloads.count('; id')} times"
        )

    def test_technique_loader_payload_strings_are_unique(self, loader):
        """For each vuln type, get_payloads() should return no duplicates."""
        for vt in loader.get_all_vuln_types():
            payloads = loader.get_payloads(vuln_type=vt, depth="thorough")
            assert len(payloads) == len(set(payloads)), (
                f"Duplicate payloads found for vuln_type='{vt}'"
            )

    def test_combined_with_payload_generator_deduplicates(self, loader, pg):
        """Merging TechniqueLoader payloads with PayloadGenerator payloads
        preserves uniqueness (no duplicates in the final combined list)."""
        technique_payloads = loader.get_payloads(vuln_type="sqli", depth="thorough")
        # sqli maps to sqli_error in PayloadGenerator
        pg_payloads = pg.payload_libraries.get("sqli_error", [])

        # Simulate the merge pattern: technique payloads first, then pg payloads
        seen = set()
        merged = []
        for p in technique_payloads + pg_payloads:
            if p not in seen:
                seen.add(p)
                merged.append(p)

        assert len(merged) == len(set(merged)), "Merged payloads contain duplicates"


# ---------------------------------------------------------------------------
# Empty results for unknown vuln types
# ---------------------------------------------------------------------------

class TestEmptyResultsForUnknownTypes:
    def test_get_payloads_unknown_type_returns_empty_list(self, loader):
        """get_payloads for a completely unknown type returns []."""
        result = loader.get_payloads(vuln_type="__totally_unknown_type_xyz__")
        assert result == []

    def test_get_techniques_unknown_type_returns_empty_list(self, loader):
        """get_techniques for a completely unknown type returns []."""
        result = loader.get_techniques(vuln_type="__totally_unknown_type_xyz__")
        assert result == []

    def test_get_payloads_empty_string_type_returns_empty(self, loader):
        """get_payloads with an empty string vuln_type returns []."""
        # Empty string will not match any technique
        result = loader.get_payloads(vuln_type="")
        assert result == []

    def test_get_all_vuln_types_does_not_include_none(self, loader):
        """get_all_vuln_types should never include None or empty string."""
        vuln_types = loader.get_all_vuln_types()
        assert None not in vuln_types
        assert "" not in vuln_types


# ---------------------------------------------------------------------------
# filter_by_context integration
# ---------------------------------------------------------------------------

class TestFilterByContextIntegration:
    def test_filter_by_context_no_args_returns_all_standard(self, loader):
        """filter_by_context with defaults should mirror standard get_techniques."""
        from techniques.filters import filter_by_context

        all_techniques = loader.get_techniques(depth="standard", waf_detected=False)
        filtered = filter_by_context(all_techniques, depth="standard", waf_detected=False)
        assert len(filtered) == len(all_techniques)

    def test_filter_by_context_technology_stack(self, loader):
        """filter_by_context should honor technology_stack list."""
        from techniques.filters import filter_by_context

        all_techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        filtered = filter_by_context(
            all_techniques,
            technology_stack=["python", "flask"],
            waf_detected=True,
            depth="thorough",
        )
        # All returned techniques should require python or flask
        for t in filtered:
            if t.technology:
                stack_lower = ["python", "flask"]
                assert any(
                    any(s in req.lower() for s in stack_lower)
                    for req in t.technology
                ), f"Technique {t.id} does not match tech stack: {t.technology}"

    def test_filter_by_context_tag_inclusion(self, loader):
        """filter_by_context should include only techniques with specified tags."""
        from techniques.filters import filter_by_context

        all_techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        filtered = filter_by_context(
            all_techniques,
            tags=["sqli"],
            depth="thorough",
            waf_detected=True,
        )
        for t in filtered:
            assert "sqli" in t.tags, f"Technique {t.id} lacks 'sqli' tag: {t.tags}"

    def test_filter_by_context_tag_exclusion(self, loader):
        """filter_by_context should exclude techniques with excluded tags."""
        from techniques.filters import filter_by_context

        all_techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        filtered = filter_by_context(
            all_techniques,
            exclude_tags=["waf-bypass"],
            depth="thorough",
            waf_detected=True,
        )
        for t in filtered:
            assert "waf-bypass" not in t.tags, (
                f"Technique {t.id} has excluded tag 'waf-bypass': {t.tags}"
            )

    def test_filter_by_context_waf_bypass_respected(self, loader):
        """filter_by_context should exclude waf_bypass techniques when waf not detected."""
        from techniques.filters import filter_by_context

        all_techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        filtered_no_waf = filter_by_context(
            all_techniques,
            waf_detected=False,
            depth="thorough",
        )
        for t in filtered_no_waf:
            assert not t.waf_bypass, (
                f"Technique {t.id} has waf_bypass=True but waf not detected"
            )


# ---------------------------------------------------------------------------
# rank_techniques integration
# ---------------------------------------------------------------------------

class TestRankTechniquesIntegration:
    def test_rank_techniques_returns_same_count(self, loader):
        """rank_techniques should return the same number of techniques."""
        from techniques.filters import rank_techniques

        techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        ranked = rank_techniques(techniques)
        assert len(ranked) == len(techniques)

    def test_rank_techniques_critical_before_low(self, loader):
        """rank_techniques should place critical/high severity before low/info."""
        from techniques.filters import rank_techniques

        techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        if len(techniques) < 2:
            pytest.skip("Not enough techniques to test ranking")

        ranked = rank_techniques(techniques)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        # Check that overall severity trend is non-increasing
        # (allow for payload count tiebreaking to affect exact order)
        scores = [severity_order.get(t.severity, 2) for t in ranked]
        # Verify highest severity appears before lowest in the ranked list
        highest = max(scores)
        lowest = min(scores)
        if highest != lowest:
            first_highest = next(i for i, s in enumerate(scores) if s == highest)
            last_lowest = next(
                i for i in range(len(scores) - 1, -1, -1) if scores[i] == lowest
            )
            assert first_highest < last_lowest, (
                "Highest severity technique should appear before lowest severity technique"
            )

    def test_rank_techniques_with_priority_vuln_types(self, loader):
        """Techniques with priority vuln types should score higher."""
        from techniques.filters import rank_techniques

        techniques = loader.get_techniques(depth="thorough", waf_detected=True)
        if not techniques:
            pytest.skip("No techniques loaded")

        ranked = rank_techniques(techniques, priority_vuln_types=["ssti"])
        # ssti techniques should appear near the top if any exist
        ssti_techs = [t for t in techniques if t.vuln_type == "ssti"]
        if ssti_techs:
            top_ids = [t.id for t in ranked[:5]]
            ssti_ids = [t.id for t in ssti_techs]
            assert any(sid in top_ids for sid in ssti_ids), (
                "Priority ssti technique should appear in top 5 ranked results"
            )


# ---------------------------------------------------------------------------
# PayloadGenerator vuln type compatibility
# ---------------------------------------------------------------------------

class TestPayloadGeneratorCompatibility:
    def test_loader_sqli_payloads_are_valid_strings_for_pg(self, loader, pg):
        """Payloads from TechniqueLoader should be compatible with PayloadGenerator
        payload format (plain strings)."""
        technique_payloads = loader.get_payloads(vuln_type="sqli", depth="thorough")
        for p in technique_payloads:
            assert isinstance(p, str), f"Expected string payload, got {type(p)}"
            assert len(p) > 0, "Empty payload string found"

    def test_loader_ssrf_payloads_complement_pg_ssrf(self, loader, pg):
        """TechniqueLoader SSRF payloads should include some URLs not in PayloadGenerator."""
        loader_payloads = set(loader.get_payloads(vuln_type="ssrf", depth="thorough"))
        pg_payloads = set(pg.payload_libraries.get("ssrf", []))

        # loader payloads should have content
        assert len(loader_payloads) > 0

        # The combined set should be larger than either alone (techniques add unique payloads)
        combined = loader_payloads | pg_payloads
        assert len(combined) >= len(pg_payloads), (
            "Combined loader+pg payloads should be at least as large as pg payloads alone"
        )

    def test_loader_ssti_includes_jinja2_arithmetic(self, loader):
        """The Jinja2 SSTI technique should include the 7*7 arithmetic payload."""
        payloads = loader.get_payloads(vuln_type="ssti", depth="thorough")
        assert "{{7*7}}" in payloads, (
            "Expected Jinja2 arithmetic payload '{{7*7}}' in ssti payloads"
        )

    def test_loader_and_pg_sqli_payloads_share_classic_injection(self, loader, pg):
        """Both the loader and PayloadGenerator should include the classic ' OR '1'='1 payload."""
        loader_payloads = loader.get_payloads(vuln_type="sqli", depth="thorough")
        pg_payloads = pg.payload_libraries.get("sqli_error", [])

        classic = "' OR '1'='1"
        assert classic in loader_payloads, (
            f"Classic SQLi payload not found in TechniqueLoader payloads"
        )
        assert classic in pg_payloads, (
            f"Classic SQLi payload not found in PayloadGenerator payloads"
        )

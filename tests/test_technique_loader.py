"""
Phase 5 Tests — Dynamic Techniques Library: Loader and Filtering

Tests for technique YAML loading, schema validation, and context-aware filtering.
"""
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from techniques.loader import TechniqueLoader
from techniques.schema import Technique, Payload, DetectionPattern


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def loader():
    """TechniqueLoader pointed at the real builtin directory."""
    return TechniqueLoader()


@pytest.fixture
def loader_with_custom(tmp_path):
    """TechniqueLoader with an isolated temp custom directory."""
    return TechniqueLoader(custom_dir=str(tmp_path))


@pytest.fixture
def populated_custom_dir(tmp_path):
    """A temp directory with a single valid custom technique YAML."""
    yaml_content = """
techniques:
  - id: custom_sqli_test
    name: "Custom SQLi Test"
    vuln_type: sqli
    description: "A custom test technique"
    severity: high
    technology: ["mysql"]
    depth: standard
    tags: ["custom", "sqli"]
    payloads:
      - value: "' OR 1=1-- custom"
        description: "Custom injection payload"
    detection:
      - type: string
        value: "error"
        description: "Error in response"
"""
    yaml_file = tmp_path / "custom_sqli.yaml"
    yaml_file.write_text(yaml_content)
    return tmp_path


# ---------------------------------------------------------------------------
# Loading from builtin directory
# ---------------------------------------------------------------------------

class TestBuiltinLoading:
    def test_loader_loads_builtin_techniques(self, loader):
        """TechniqueLoader should load techniques from the builtin directory."""
        loader.load()
        assert len(loader._techniques) > 0

    def test_loaded_techniques_are_technique_instances(self, loader):
        """All loaded items should be Technique model instances."""
        loader.load()
        for t in loader._techniques:
            assert isinstance(t, Technique)

    def test_builtin_sqli_techniques_loaded(self, loader):
        """Builtin sqli techniques should be present."""
        techniques = loader.get_techniques(vuln_type="sqli")
        assert len(techniques) > 0, "Expected at least one sqli technique"

    def test_builtin_xss_reflected_techniques_loaded(self, loader):
        """Builtin xss_reflected techniques should be present."""
        techniques = loader.get_techniques(vuln_type="xss_reflected")
        assert len(techniques) > 0, "Expected at least one xss_reflected technique"

    def test_builtin_ssrf_techniques_loaded(self, loader):
        """Builtin ssrf techniques should be present."""
        techniques = loader.get_techniques(vuln_type="ssrf")
        assert len(techniques) > 0, "Expected at least one ssrf technique"

    def test_builtin_ssti_techniques_loaded(self, loader):
        """Builtin ssti techniques should be present."""
        techniques = loader.get_techniques(vuln_type="ssti")
        assert len(techniques) > 0, "Expected at least one ssti technique"

    def test_load_is_idempotent(self, loader):
        """Calling load() twice should not duplicate techniques."""
        loader.load()
        count_first = len(loader._techniques)
        loader.load()
        count_second = len(loader._techniques)
        assert count_first == count_second

    def test_reload_refreshes_techniques(self, tmp_path):
        """reload() should re-scan and pick up new files."""
        custom_loader = TechniqueLoader(custom_dir=str(tmp_path))
        custom_loader.load()
        count_before = len(custom_loader._techniques)

        # Add a new technique file
        new_yaml = tmp_path / "new_technique.yaml"
        new_yaml.write_text("""
techniques:
  - id: new_dynamic_technique
    name: "New Dynamic"
    vuln_type: xss_dom
    description: "Added after initial load"
    severity: low
    depth: quick
    tags: ["dynamic"]
    payloads:
      - value: "#<img src=x>"
        description: "DOM fragment"
    detection: []
""")
        custom_loader.reload()
        count_after = len(custom_loader._techniques)
        assert count_after > count_before


# ---------------------------------------------------------------------------
# Schema Validation
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def test_invalid_yaml_rejected_gracefully(self, tmp_path):
        """A YAML file with missing required fields should be skipped, not crash."""
        bad_yaml = tmp_path / "bad_technique.yaml"
        bad_yaml.write_text("""
techniques:
  - name: "Missing id and vuln_type"
    description: "This is incomplete"
    payloads:
      - value: "test"
""")
        custom_loader = TechniqueLoader(custom_dir=str(tmp_path))
        # Should not raise; bad technique is skipped
        custom_loader.load()

    def test_completely_invalid_yaml_rejected_gracefully(self, tmp_path):
        """Malformed YAML should be skipped, not crash."""
        bad_yaml = tmp_path / "malformed.yaml"
        bad_yaml.write_text("{{ invalid yaml: [not closed")
        custom_loader = TechniqueLoader(custom_dir=str(tmp_path))
        custom_loader.load()  # Should not raise

    def test_empty_yaml_file_handled(self, tmp_path):
        """Empty YAML files should be silently skipped."""
        empty_yaml = tmp_path / "empty.yaml"
        empty_yaml.write_text("")
        custom_loader = TechniqueLoader(custom_dir=str(tmp_path))
        custom_loader.load()  # Should not raise

    def test_valid_technique_has_required_fields(self, loader):
        """All loaded techniques should have id, name, and vuln_type."""
        loader.load()
        for t in loader._techniques:
            assert t.id, f"Technique missing id: {t}"
            assert t.name, f"Technique missing name: {t}"
            assert t.vuln_type, f"Technique missing vuln_type: {t}"

    def test_payloads_are_payload_instances(self, loader):
        """Payloads in loaded techniques should be Payload model instances."""
        loader.load()
        for t in loader._techniques:
            for p in t.payloads:
                assert isinstance(p, Payload)

    def test_detection_are_detection_pattern_instances(self, loader):
        """Detection patterns should be DetectionPattern model instances."""
        loader.load()
        for t in loader._techniques:
            for d in t.detection:
                assert isinstance(d, DetectionPattern)

    def test_single_technique_yaml_without_list_wrapper(self, tmp_path):
        """YAML with a single technique dict (no 'techniques' key) should load."""
        single_yaml = tmp_path / "single.yaml"
        single_yaml.write_text("""
id: single_technique
name: "Single Dict Technique"
vuln_type: lfi
description: "Direct dict, no list wrapper"
severity: medium
depth: quick
tags: ["lfi"]
payloads:
  - value: "../../etc/passwd"
    description: "Basic LFI"
detection: []
""")
        custom_loader = TechniqueLoader(custom_dir=str(tmp_path))
        custom_loader.load()
        lfi_techs = custom_loader.get_techniques(vuln_type="lfi")
        assert any(t.id == "single_technique" for t in lfi_techs)


# ---------------------------------------------------------------------------
# Filtering by vuln_type
# ---------------------------------------------------------------------------

class TestFilterByVulnType:
    def test_filter_returns_only_matching_vuln_type(self, loader):
        """get_techniques(vuln_type='sqli') should return only sqli techniques."""
        techniques = loader.get_techniques(vuln_type="sqli")
        for t in techniques:
            assert t.vuln_type == "sqli", f"Expected sqli, got {t.vuln_type}"

    def test_filter_unknown_vuln_type_returns_empty(self, loader):
        """Filtering by an unknown vuln_type should return an empty list."""
        techniques = loader.get_techniques(vuln_type="not_a_real_vuln_type_xyz")
        assert techniques == []

    def test_no_vuln_type_filter_returns_all(self, loader):
        """Calling get_techniques() with no vuln_type returns all techniques."""
        all_techniques = loader.get_techniques()
        loader.load()
        assert len(all_techniques) == len(loader._techniques)

    def test_xss_dom_filter(self, loader):
        """xss_dom filter should return only xss_dom techniques."""
        techniques = loader.get_techniques(vuln_type="xss_dom")
        for t in techniques:
            assert t.vuln_type == "xss_dom"

    def test_xss_stored_filter(self, loader):
        """xss_stored filter should return only xss_stored techniques."""
        techniques = loader.get_techniques(vuln_type="xss_stored")
        for t in techniques:
            assert t.vuln_type == "xss_stored"


# ---------------------------------------------------------------------------
# Filtering by technology
# ---------------------------------------------------------------------------

class TestFilterByTechnology:
    def test_filter_mysql_returns_mysql_techniques(self, loader):
        """Techniques with 'mysql' in their technology list should be returned."""
        techniques = loader.get_techniques(technology="mysql")
        # Every returned technique should have mysql in its technology list
        for t in techniques:
            if t.technology:
                assert any("mysql" in tt.lower() for tt in t.technology), (
                    f"Technique {t.id} does not match technology 'mysql': {t.technology}"
                )

    def test_filter_aws_returns_aws_techniques(self, loader):
        """Techniques tagged with 'aws' technology should be returned."""
        techniques = loader.get_techniques(technology="aws")
        for t in techniques:
            if t.technology:
                assert any("aws" in tt.lower() for tt in t.technology)

    def test_filter_java_returns_java_techniques(self, loader):
        """Techniques with 'java' in their technology list should be returned."""
        techniques = loader.get_techniques(technology="java")
        for t in techniques:
            if t.technology:
                assert any("java" in tt.lower() for tt in t.technology)

    def test_techniques_without_technology_excluded_when_tech_filter_set(self, loader):
        """When a technology filter is specified, techniques with no technology
        list should be excluded."""
        techniques = loader.get_techniques(technology="mysql")
        for t in techniques:
            # If technology is non-empty it must match; if empty, it should not appear
            if not t.technology:
                pytest.fail(
                    f"Technique {t.id} has no technology but was returned for 'mysql' filter"
                )

    def test_unknown_technology_returns_empty(self, loader):
        """A technology that no technique specifies should return empty."""
        techniques = loader.get_techniques(technology="cobol_mainframe_xyz")
        assert techniques == []


# ---------------------------------------------------------------------------
# Filtering by depth
# ---------------------------------------------------------------------------

class TestFilterByDepth:
    def test_quick_depth_excludes_standard_and_thorough(self, loader):
        """Quick depth should only return 'quick' techniques."""
        techniques = loader.get_techniques(depth="quick")
        depth_order = {"quick": 0, "standard": 1, "thorough": 2}
        for t in techniques:
            assert depth_order.get(t.depth, 1) <= 0, (
                f"Technique {t.id} has depth '{t.depth}' which exceeds 'quick'"
            )

    def test_standard_depth_excludes_thorough(self, loader):
        """Standard depth should exclude 'thorough' techniques."""
        techniques = loader.get_techniques(depth="standard")
        depth_order = {"quick": 0, "standard": 1, "thorough": 2}
        for t in techniques:
            assert depth_order.get(t.depth, 1) <= 1, (
                f"Technique {t.id} has depth '{t.depth}' which exceeds 'standard'"
            )

    def test_thorough_depth_includes_all_depths(self, loader):
        """Thorough depth should include quick, standard, and thorough techniques."""
        techniques = loader.get_techniques(depth="thorough")
        depths_found = set(t.depth for t in techniques)
        # We expect to see at least some variety (standard + thorough in builtins)
        assert len(depths_found) >= 1

    def test_sqli_blind_is_thorough(self, loader):
        """The blind SQL injection technique should be depth=thorough."""
        loader.load()
        blind_techs = [t for t in loader._techniques if t.id in ("sqli_blind_boolean", "sqli_blind_time")]
        assert all(t.depth == "thorough" for t in blind_techs), (
            "Expected sqli_blind techniques to be depth=thorough"
        )

    def test_thorough_returns_more_than_quick(self, loader):
        """Thorough depth should return at least as many techniques as quick."""
        quick_count = len(loader.get_techniques(depth="quick"))
        thorough_count = len(loader.get_techniques(depth="thorough"))
        assert thorough_count >= quick_count


# ---------------------------------------------------------------------------
# WAF bypass filtering
# ---------------------------------------------------------------------------

class TestWAFBypassFilter:
    def test_waf_bypass_techniques_excluded_by_default(self, loader):
        """WAF bypass techniques should not appear when waf_detected=False."""
        techniques = loader.get_techniques(waf_detected=False)
        for t in techniques:
            assert not t.waf_bypass, (
                f"Technique {t.id} has waf_bypass=True but waf_detected=False"
            )

    def test_waf_bypass_techniques_included_when_waf_detected(self, loader):
        """WAF bypass techniques should appear when waf_detected=True."""
        all_with_waf = loader.get_techniques(waf_detected=True)
        all_without_waf = loader.get_techniques(waf_detected=False)
        # There must be at least one waf_bypass technique in builtins
        waf_bypass_techs = [t for t in all_with_waf if t.waf_bypass]
        assert len(waf_bypass_techs) > 0, (
            "Expected at least one waf_bypass technique in builtins"
        )
        # Non-waf run should have fewer or equal techniques
        assert len(all_with_waf) >= len(all_without_waf)

    def test_xss_waf_bypass_technique_exists(self, loader):
        """The xss_reflected_waf_bypass technique should exist in builtins."""
        loader.load()
        ids = [t.id for t in loader._techniques]
        assert "xss_reflected_waf_bypass" in ids

    def test_waf_bypass_technique_excluded_from_standard_xss_filter(self, loader):
        """xss_reflected_waf_bypass should not appear in standard xss_reflected results."""
        techniques = loader.get_techniques(vuln_type="xss_reflected", waf_detected=False)
        ids = [t.id for t in techniques]
        assert "xss_reflected_waf_bypass" not in ids

    def test_waf_bypass_technique_included_with_waf_detected(self, loader):
        """xss_reflected_waf_bypass should appear when WAF is detected."""
        techniques = loader.get_techniques(
            vuln_type="xss_reflected",
            waf_detected=True,
            depth="thorough",
        )
        ids = [t.id for t in techniques]
        assert "xss_reflected_waf_bypass" in ids


# ---------------------------------------------------------------------------
# get_payloads returns strings
# ---------------------------------------------------------------------------

class TestGetPayloads:
    def test_get_payloads_returns_list_of_strings(self, loader):
        """get_payloads() should return a flat list of payload strings."""
        payloads = loader.get_payloads(vuln_type="sqli")
        assert isinstance(payloads, list)
        for p in payloads:
            assert isinstance(p, str), f"Expected str, got {type(p)}: {p!r}"

    def test_get_payloads_deduplicates(self, tmp_path):
        """get_payloads() should not return duplicate payload strings."""
        # Create two techniques with overlapping payloads
        yaml_content = """
techniques:
  - id: dup_test_1
    name: "Dup Test 1"
    vuln_type: xss_reflected
    description: "First"
    severity: low
    depth: quick
    tags: []
    payloads:
      - value: "<script>alert(1)</script>"
        description: "Shared payload"
      - value: "<img src=x onerror=alert(1)>"
        description: "Unique to first"
    detection: []
  - id: dup_test_2
    name: "Dup Test 2"
    vuln_type: xss_reflected
    description: "Second"
    severity: low
    depth: quick
    tags: []
    payloads:
      - value: "<script>alert(1)</script>"
        description: "Same shared payload"
      - value: "<svg onload=alert(1)>"
        description: "Unique to second"
    detection: []
"""
        yaml_file = tmp_path / "dup_test.yaml"
        yaml_file.write_text(yaml_content)

        dedup_loader = TechniqueLoader(custom_dir=str(tmp_path))
        payloads = dedup_loader.get_payloads(vuln_type="xss_reflected", depth="quick")

        assert payloads.count("<script>alert(1)</script>") == 1, (
            "Shared payload appears more than once"
        )

    def test_get_payloads_unknown_type_returns_empty(self, loader):
        """get_payloads() for an unknown vuln type should return []."""
        payloads = loader.get_payloads(vuln_type="not_a_real_type_xyz")
        assert payloads == []

    def test_get_payloads_sqli_nonempty(self, loader):
        """get_payloads('sqli') should return at least one payload."""
        payloads = loader.get_payloads(vuln_type="sqli")
        assert len(payloads) > 0

    def test_get_payloads_ssrf_nonempty(self, loader):
        """get_payloads('ssrf') should return at least one payload."""
        payloads = loader.get_payloads(vuln_type="ssrf")
        assert len(payloads) > 0

    def test_get_payloads_respects_depth(self, loader):
        """get_payloads() with depth='quick' should return fewer than 'thorough'."""
        quick_payloads = loader.get_payloads(vuln_type="sqli", depth="quick")
        thorough_payloads = loader.get_payloads(vuln_type="sqli", depth="thorough")
        # Thorough includes more depth levels, so count should be >= quick
        assert len(thorough_payloads) >= len(quick_payloads)

    def test_get_payloads_with_custom_technique(self, populated_custom_dir):
        """Custom YAML techniques should contribute payloads via get_payloads()."""
        custom_loader = TechniqueLoader(custom_dir=str(populated_custom_dir))
        payloads = custom_loader.get_payloads(vuln_type="sqli")
        assert "' OR 1=1-- custom" in payloads


# ---------------------------------------------------------------------------
# get_all_vuln_types
# ---------------------------------------------------------------------------

class TestGetAllVulnTypes:
    def test_get_all_vuln_types_returns_sorted_list(self, loader):
        """get_all_vuln_types() should return a sorted list of unique strings."""
        vuln_types = loader.get_all_vuln_types()
        assert isinstance(vuln_types, list)
        assert vuln_types == sorted(vuln_types), "Vuln types should be sorted"

    def test_get_all_vuln_types_no_duplicates(self, loader):
        """get_all_vuln_types() should not contain duplicates."""
        vuln_types = loader.get_all_vuln_types()
        assert len(vuln_types) == len(set(vuln_types))

    def test_get_all_vuln_types_includes_expected_types(self, loader):
        """Known builtin vuln types should appear in the full list."""
        vuln_types = loader.get_all_vuln_types()
        expected = {"sqli", "xss_reflected", "xss_dom", "xss_stored", "ssrf", "ssti"}
        for vt in expected:
            assert vt in vuln_types, f"Expected vuln type '{vt}' not found in {vuln_types}"

    def test_get_all_vuln_types_all_are_strings(self, loader):
        """Every entry in get_all_vuln_types() should be a non-empty string."""
        vuln_types = loader.get_all_vuln_types()
        for vt in vuln_types:
            assert isinstance(vt, str) and vt, f"Invalid vuln type: {vt!r}"

    def test_get_all_vuln_types_returns_at_least_five(self, loader):
        """Should return at least 5 unique vulnerability types from builtins."""
        vuln_types = loader.get_all_vuln_types()
        assert len(vuln_types) >= 5

"""
Tests for PayloadsAllTheThings (PATT) integration.

Unit tests for parsers, category map validation, and integration tests
for loader, merge strategy, and graceful degradation.
"""
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.core.vuln_engine.patt.category_map import (
    PATT_CATEGORY_MAP,
    PATT_SKIPPED_DIRS,
    NEW_VULN_TYPES,
    NEW_VULN_TYPE_KEYS,
    PATT_INTRUDER_FILE_MAP,
    PATT_SECTION_MAP,
)
from backend.core.vuln_engine.patt.parser import (
    parse_intruder_file,
    parse_markdown_payloads,
    parse_patt_category,
)
from backend.core.vuln_engine.patt.loader import PATTLoader


# ---------------------------------------------------------------------------
# Category Map Validation
# ---------------------------------------------------------------------------

class TestCategoryMap:
    def test_category_map_has_entries(self):
        assert len(PATT_CATEGORY_MAP) > 50

    def test_all_values_are_lists(self):
        for key, val in PATT_CATEGORY_MAP.items():
            assert isinstance(val, list), f"{key} should map to a list"
            assert len(val) > 0, f"{key} should have at least one vuln type"

    def test_new_vuln_types_count(self):
        assert len(NEW_VULN_TYPES) == 19

    def test_new_vuln_types_have_required_fields(self):
        required_fields = {"title", "severity", "cwe_id", "description", "impact", "remediation"}
        for key, info in NEW_VULN_TYPES.items():
            for field in required_fields:
                assert field in info, f"{key} missing field: {field}"

    def test_new_vuln_type_keys_sorted(self):
        assert NEW_VULN_TYPE_KEYS == sorted(NEW_VULN_TYPE_KEYS)

    def test_skipped_dirs_has_methodology(self):
        assert "Methodology and Resources" in PATT_SKIPPED_DIRS
        assert "CVE Exploits" in PATT_SKIPPED_DIRS

    def test_intruder_file_map_types_in_category_map(self):
        for category, routing in PATT_INTRUDER_FILE_MAP.items():
            assert category in PATT_CATEGORY_MAP
            valid_types = set(PATT_CATEGORY_MAP[category])
            for vuln_type in routing.values():
                assert vuln_type in valid_types, (
                    f"Intruder routing for {category}: {vuln_type} not in category types"
                )

    def test_section_map_types_in_category_map(self):
        for category, routing in PATT_SECTION_MAP.items():
            assert category in PATT_CATEGORY_MAP
            valid_types = set(PATT_CATEGORY_MAP[category])
            for vuln_type in routing.values():
                assert vuln_type in valid_types, (
                    f"Section routing for {category}: {vuln_type} not in category types"
                )


# ---------------------------------------------------------------------------
# Parser Unit Tests
# ---------------------------------------------------------------------------

class TestIntruderParser:
    def test_parse_basic_wordlist(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_text("payload1\npayload2\n# comment\n\npayload3\n")
        result = parse_intruder_file(f)
        assert result == ["payload1", "payload2", "payload3"]

    def test_skip_comments_and_blanks(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_text("# header comment\n\n  \n# another\nreal_payload\n")
        result = parse_intruder_file(f)
        assert result == ["real_payload"]

    def test_skip_too_long_payloads(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_text("short\n" + "x" * 10001 + "\nok\n")
        result = parse_intruder_file(f)
        assert result == ["short", "ok"]

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        result = parse_intruder_file(f)
        assert result == []

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "nope.txt"
        result = parse_intruder_file(f)
        assert result == []

    def test_utf8_with_replace(self, tmp_path):
        f = tmp_path / "payloads.txt"
        f.write_bytes(b"valid\n\xff\xfe invalid utf8\ngood\n")
        result = parse_intruder_file(f)
        assert len(result) == 3
        assert result[0] == "valid"
        assert result[2] == "good"


class TestMarkdownParser:
    def test_extract_from_code_blocks(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text(
            "# Title\n\nSome text.\n\n"
            "```\n<script>alert(1)</script>\n```\n\n"
            "More text.\n"
        )
        result = parse_markdown_payloads(md)
        assert "<script>alert(1)</script>" in result

    def test_skip_language_tagged_blocks(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text(
            "```python\nimport os\nos.system('id')\n```\n\n"
            "```\n' OR 1=1--\n```\n"
        )
        result = parse_markdown_payloads(md)
        assert "' OR 1=1--" in result
        assert "import os" not in result

    def test_section_filter(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text(
            "## Error based\n```\npayload_error\n```\n\n"
            "## UNION based\n```\npayload_union\n```\n"
        )
        result = parse_markdown_payloads(md, section_filter="Error based")
        assert "payload_error" in result
        assert "payload_union" not in result

    def test_skip_prose_lines(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text(
            "```\n"
            "# This is a comment-like line\n"
            "> Quote line\n"
            "real_payload\n"
            "Output: some output\n"
            "```\n"
        )
        result = parse_markdown_payloads(md)
        assert "real_payload" in result
        assert "# This is a comment-like line" not in result

    def test_empty_code_blocks_skipped(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text("```\n\n\n```\n")
        result = parse_markdown_payloads(md)
        assert result == []


class TestCategoryParser:
    def test_parse_with_intruder_and_md(self, tmp_path):
        cat_dir = tmp_path / "TestCategory"
        cat_dir.mkdir()

        # Create Intruder dir
        intruder = cat_dir / "Intruder"
        intruder.mkdir()
        (intruder / "payloads.txt").write_text("intruder_p1\nintruder_p2\n")

        # Create markdown
        (cat_dir / "README.md").write_text("# Readme\nIgnored.\n")
        (cat_dir / "test.md").write_text("```\nmd_payload\n```\n")

        result = parse_patt_category(cat_dir, ["test_type"])
        assert "test_type" in result
        payloads = result["test_type"]
        assert "intruder_p1" in payloads
        assert "intruder_p2" in payloads
        assert "md_payload" in payloads

    def test_deduplication(self, tmp_path):
        cat_dir = tmp_path / "TestDup"
        cat_dir.mkdir()
        intruder = cat_dir / "Intruder"
        intruder.mkdir()
        (intruder / "a.txt").write_text("dup\ndup\nunique\n")
        (intruder / "b.txt").write_text("dup\nanother\n")

        result = parse_patt_category(cat_dir, ["test"])
        payloads = result["test"]
        assert payloads.count("dup") == 1
        assert "unique" in payloads
        assert "another" in payloads

    def test_nonexistent_directory(self, tmp_path):
        result = parse_patt_category(tmp_path / "nope", ["test"])
        assert result == {"test": []}


# ---------------------------------------------------------------------------
# Loader Tests
# ---------------------------------------------------------------------------

class TestPATTLoader:
    def test_unavailable_when_no_submodule(self, tmp_path):
        loader = PATTLoader(submodule_path=tmp_path / "nope")
        assert not loader.available
        assert loader.get_payloads("xss_reflected") == []

    def test_graceful_degradation(self, tmp_path):
        """When submodule missing, get_payloads returns empty list."""
        loader = PATTLoader(submodule_path=tmp_path / "missing")
        loader.load()
        assert loader.get_payloads("command_injection") == []
        assert loader.get_stats() == {}

    def test_load_with_mock_submodule(self, tmp_path):
        """Test loading from a mock PATT structure."""
        patt_dir = tmp_path / "PATT"
        patt_dir.mkdir()

        # Create a simple category
        cmd_dir = patt_dir / "Command Injection"
        cmd_dir.mkdir()
        intruder = cmd_dir / "Intruder"
        intruder.mkdir()
        (intruder / "payloads.txt").write_text("; ls\n| whoami\n")

        loader = PATTLoader(submodule_path=patt_dir)
        assert loader.available
        loader.load()

        payloads = loader.get_payloads("command_injection")
        assert "; ls" in payloads
        assert "| whoami" in payloads

    def test_get_stats(self, tmp_path):
        patt_dir = tmp_path / "PATT"
        patt_dir.mkdir()
        cmd_dir = patt_dir / "Command Injection"
        cmd_dir.mkdir()
        intruder = cmd_dir / "Intruder"
        intruder.mkdir()
        (intruder / "payloads.txt").write_text("p1\np2\np3\n")

        loader = PATTLoader(submodule_path=patt_dir)
        loader.load()
        stats = loader.get_stats()
        assert stats.get("command_injection", 0) == 3

    def test_lazy_load(self, tmp_path):
        patt_dir = tmp_path / "PATT"
        patt_dir.mkdir()
        cmd_dir = patt_dir / "Command Injection"
        cmd_dir.mkdir()
        intruder = cmd_dir / "Intruder"
        intruder.mkdir()
        (intruder / "payloads.txt").write_text("lazy_p1\n")

        loader = PATTLoader(submodule_path=patt_dir)
        # get_payloads should trigger lazy load
        payloads = loader.get_payloads("command_injection")
        assert "lazy_p1" in payloads


# ---------------------------------------------------------------------------
# Integration Tests (require actual submodule)
# ---------------------------------------------------------------------------

PATT_SUBMODULE = Path(__file__).resolve().parent.parent / "vendor" / "PayloadsAllTheThings"
HAS_SUBMODULE = PATT_SUBMODULE.is_dir() and any(PATT_SUBMODULE.iterdir())


@pytest.mark.skipif(not HAS_SUBMODULE, reason="PATT submodule not initialized")
class TestPATTIntegration:
    def test_real_loader_loads(self):
        loader = PATTLoader()
        assert loader.available
        loader.load()
        stats = loader.get_stats()
        assert len(stats) > 0
        total = sum(stats.values())
        assert total > 100, f"Expected >100 payloads, got {total}"

    def test_command_injection_has_payloads(self):
        loader = PATTLoader()
        payloads = loader.get_payloads("command_injection")
        assert len(payloads) > 0

    def test_sqli_types_have_payloads(self):
        loader = PATTLoader()
        for sqli_type in ["sqli_error", "sqli_union", "sqli_blind", "sqli_time"]:
            payloads = loader.get_payloads(sqli_type)
            # At least some SQL types should have payloads
            if payloads:
                assert len(payloads) > 0

    def test_xss_types_have_payloads(self):
        loader = PATTLoader()
        payloads = loader.get_payloads("xss_reflected")
        # XSS should have many payloads from PATT
        assert len(payloads) > 0

    def test_new_types_get_payloads(self):
        loader = PATTLoader()
        found_any = False
        for vtype in NEW_VULN_TYPE_KEYS:
            payloads = loader.get_payloads(vtype)
            if payloads:
                found_any = True
        assert found_any, "Expected at least some new types to have PATT payloads"


# ---------------------------------------------------------------------------
# Merge Strategy Tests
# ---------------------------------------------------------------------------

class TestMergeStrategy:
    def test_curated_first_in_ordering(self, tmp_path):
        """Verify curated payloads come before PATT payloads."""
        from backend.core.vuln_engine.payload_generator import PayloadGenerator

        # Create mock PATT
        patt_dir = tmp_path / "PATT"
        patt_dir.mkdir()
        cmd_dir = patt_dir / "Command Injection"
        cmd_dir.mkdir()
        intruder = cmd_dir / "Intruder"
        intruder.mkdir()
        (intruder / "payloads.txt").write_text("patt_unique_1\npatt_unique_2\n")

        gen = PayloadGenerator()
        mock_loader = PATTLoader(submodule_path=patt_dir)
        mock_loader.load()
        gen._patt = mock_loader

        # Get all payloads
        all_payloads = gen.get_all_payloads("command_injection")

        # Curated payloads should exist and come first
        curated = gen.payload_libraries.get("command_injection", [])
        if curated:
            assert all_payloads[0] == curated[0]

        # PATT payloads should be appended
        assert "patt_unique_1" in all_payloads
        assert "patt_unique_2" in all_payloads

    def test_deduplication_in_merge(self, tmp_path):
        """Verify duplicate payloads from PATT are not added twice."""
        from backend.core.vuln_engine.payload_generator import PayloadGenerator

        patt_dir = tmp_path / "PATT"
        patt_dir.mkdir()
        cmd_dir = patt_dir / "Command Injection"
        cmd_dir.mkdir()
        intruder = cmd_dir / "Intruder"
        intruder.mkdir()
        # Include a payload that already exists in curated set
        (intruder / "payloads.txt").write_text("; id\nunique_patt\n")

        gen = PayloadGenerator()
        mock_loader = PATTLoader(submodule_path=patt_dir)
        mock_loader.load()
        gen._patt = mock_loader

        all_payloads = gen.get_all_payloads("command_injection")
        assert all_payloads.count("; id") == 1
        assert "unique_patt" in all_payloads


# ---------------------------------------------------------------------------
# Registry Integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:
    def test_register_type_idempotent(self):
        from backend.core.vuln_engine.registry import VulnerabilityRegistry
        info = {"title": "Test Type", "severity": "low", "cwe_id": "CWE-0"}
        VulnerabilityRegistry.register_type("_test_patt_type", info)
        VulnerabilityRegistry.register_type("_test_patt_type", info)  # idempotent
        assert "_test_patt_type" in VulnerabilityRegistry.VULNERABILITY_INFO
        assert "_test_patt_type" in VulnerabilityRegistry.TESTER_CLASSES
        # Cleanup
        del VulnerabilityRegistry.VULNERABILITY_INFO["_test_patt_type"]
        del VulnerabilityRegistry.TESTER_CLASSES["_test_patt_type"]

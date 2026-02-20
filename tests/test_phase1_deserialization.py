"""
Phase 1 Tests — Insecure Deserialization Tester

Tests deserialization tester signatures for Java, PHP, Python, .NET.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.vuln_engine.testers.deserialization import InsecureDeserializationTester
from backend.core.vuln_engine.testers.base_tester import BaseTester


@pytest.fixture
def tester():
    return InsecureDeserializationTester()


class TestInsecureDeserializationTester:
    """Basic tester tests."""

    def test_inherits_base_tester(self, tester):
        assert isinstance(tester, BaseTester)

    def test_name(self, tester):
        assert tester.name == "insecure_deserialization"

    def test_has_platform_signatures(self, tester):
        assert len(tester._java_signatures) > 0
        assert len(tester._php_signatures) > 0
        assert len(tester._python_signatures) > 0
        assert len(tester._dotnet_signatures) > 0
        assert len(tester._viewstate_signatures) > 0


class TestJavaSignatures:
    """Tests for Java deserialization detection."""

    def test_java_base64_header(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {}, "Response contains rO0ABXNyABF data", {}
        )
        assert is_vuln
        assert "Java serialized object (base64)" in evidence

    def test_java_hex_header(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {}, "hex: aced0005sr", {}
        )
        assert is_vuln
        assert "Java serialized object (hex)" in evidence

    def test_java_commons_collections(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {},
            "Error in org.apache.commons.collections.functors", {}
        )
        assert is_vuln

    def test_java_class_not_found_500(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 500, {},
            "ClassNotFoundException: com.example.Gadget", {}
        )
        assert is_vuln
        assert confidence >= 0.85

    def test_java_content_type(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200,
            {"content-type": "application/x-java-serialized-object"},
            "binary data", {}
        )
        assert is_vuln
        assert confidence >= 0.9


class TestPHPSignatures:
    """Tests for PHP deserialization detection."""

    def test_php_serialized_object(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {},
            'O:8:"stdClass":1:{s:3:"foo";s:3:"bar";}', {}
        )
        assert is_vuln
        assert "PHP serialized" in evidence

    def test_php_serialized_array(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {},
            'a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}', {}
        )
        assert is_vuln

    def test_php_wakeup_failure(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 500, {},
            "Fatal error: __wakeup() failed", {}
        )
        assert is_vuln
        assert confidence >= 0.8


class TestPythonSignatures:
    """Tests for Python deserialization detection."""

    def test_python_pickle_reduce(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {},
            "Found __reduce__ method in data", {}
        )
        assert is_vuln

    def test_python_unpickling_error(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 500, {},
            "Error unpickling data from user input", {}
        )
        assert is_vuln
        assert confidence >= 0.8


class TestDotNetSignatures:
    """Tests for .NET deserialization detection."""

    def test_dotnet_binary_formatter_header(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {},
            "AAEAAAD/////AQAAAAAAAAAMAgAAAE1NaWNyb3Nv", {}
        )
        assert is_vuln

    def test_dotnet_binary_formatter_error(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 500, {},
            "System.Runtime.Serialization.BinaryFormatter failed", {}
        )
        assert is_vuln

    def test_viewstate_detection(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {},
            '<input type="hidden" name="__VIEWSTATE" value="/wEPDw...">', {}
        )
        assert is_vuln

    def test_dotnet_object_state_formatter_error(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 500, {},
            "ObjectStateFormatter deserialization failure", {}
        )
        assert is_vuln
        assert confidence >= 0.8


class TestNonVulnerableResponses:
    """Tests for responses that should NOT be flagged."""

    def test_clean_response(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 200, {"content-type": "text/html"},
            "<html><body>Hello World</body></html>", {}
        )
        assert not is_vuln
        assert confidence == 0.0

    def test_404_response(self, tester):
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 404, {}, "Not Found", {}
        )
        assert not is_vuln

    def test_generic_500_still_flagged(self, tester):
        """A 500 without specific markers still gets low-confidence flag."""
        is_vuln, confidence, evidence = tester.analyze_response(
            "test", 500, {}, "Internal Server Error", {}
        )
        assert is_vuln
        assert confidence == 0.5  # Low confidence for generic 500


class TestGetTestPayloads:
    """Tests for the get_test_payloads() method."""

    def test_returns_dict(self, tester):
        payloads = tester.get_test_payloads()
        assert isinstance(payloads, dict)

    def test_has_all_platforms(self, tester):
        payloads = tester.get_test_payloads()
        for platform in ["java", "php", "python", "dotnet"]:
            assert platform in payloads, f"Missing platform: {platform}"
            assert len(payloads[platform]) > 0, f"No payloads for {platform}"

    def test_java_payloads(self, tester):
        payloads = tester.get_test_payloads()
        java = payloads["java"]
        assert any("rO0AB" in p for p in java), "Missing Java base64 header probe"

    def test_php_payloads(self, tester):
        payloads = tester.get_test_payloads()
        php = payloads["php"]
        assert any("stdClass" in p for p in php), "Missing PHP stdClass probe"

    def test_dotnet_payloads(self, tester):
        payloads = tester.get_test_payloads()
        dotnet = payloads["dotnet"]
        assert any("AAEAAAD" in p for p in dotnet), "Missing .NET BinaryFormatter probe"


class TestRegistryIntegration:
    """Tests that the registry uses InsecureDeserializationTester."""

    def test_registry_maps_to_tester(self):
        from backend.core.vuln_engine.registry import VulnerabilityRegistry
        tester_class = VulnerabilityRegistry.TESTER_CLASSES.get("insecure_deserialization")
        assert tester_class is InsecureDeserializationTester
        assert tester_class is not BaseTester

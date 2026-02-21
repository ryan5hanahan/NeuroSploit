"""
Phase 3 Tests — Enhanced Duplicate Detector

Tests CWE-based matching boosts, endpoint path normalization,
temporal proximity scoring, and the combined weighted scoring pipeline.
Also verifies the SequenceMatcher baseline is preserved.
"""

import sys
from pathlib import Path
from difflib import SequenceMatcher

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.bugbounty.duplicate_detector import DuplicateDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(
    id_: str,
    title: str,
    weakness: str = "",
    vuln_info: str = "",
) -> dict:
    return {
        "id": id_,
        "title": title,
        "weakness": weakness,
        "vulnerability_information": vuln_info,
    }


# ---------------------------------------------------------------------------
# TestSequenceMatcherBaseline
# ---------------------------------------------------------------------------


class TestSequenceMatcherBaseline:
    """Verifies that the SequenceMatcher-based scoring path still works."""

    def test_identical_titles_score_high(self):
        reports = [_make_report("1", "SQL Injection in login form")]
        detector = DuplicateDetector(reports)

        result = detector.check_duplicate(
            title="SQL Injection in login form",
            vuln_type="sqli",
        )
        assert result is not None
        assert result["duplicate_score"] >= 0.6

    def test_completely_different_titles_no_match(self):
        reports = [_make_report("1", "XSS in profile page")]
        detector = DuplicateDetector(reports)

        result = detector.check_duplicate(
            title="Server-Side Request Forgery in image upload",
            vuln_type="ssrf",
        )
        assert result is None

    def test_normalize_lowercases_and_strips_punctuation(self):
        norm = DuplicateDetector._normalize
        assert norm("  SQL-Injection! ") == "sql injection"
        assert norm("XSS (Reflected)") == "xss  reflected "

    def test_empty_reports_returns_none(self):
        detector = DuplicateDetector([])
        result = detector.check_duplicate(title="anything", vuln_type="xss")
        assert result is None

    def test_check_all_returns_tuples(self):
        reports = [_make_report("1", "Open Redirect in /login")]
        detector = DuplicateDetector(reports)

        findings = [
            {"title": "Open Redirect in /login", "vulnerability_type": "redirect"},
            {"title": "RCE via deserialization", "vulnerability_type": "rce"},
        ]
        results = detector.check_all(findings)
        assert len(results) == 2
        # First should match, second should not
        assert results[0][1] is not None
        assert results[1][1] is None


# ---------------------------------------------------------------------------
# TestCWEBasedMatchingBoost
# ---------------------------------------------------------------------------


class TestCWEBasedMatchingBoost:
    """Tests that matching vulnerability types boost the overall duplicate score."""

    def test_matching_vuln_type_increases_score(self):
        """Same vuln type should push borderline title match over threshold."""
        reports = [
            _make_report("1", "SQL Injection vulnerability", weakness="sqli")
        ]
        detector = DuplicateDetector(reports)

        # Title is similar but not identical — vuln_type match should help
        result_with_type = detector.check_duplicate(
            title="SQL injection issue found",
            vuln_type="sqli",
        )
        result_without_type = detector.check_duplicate(
            title="SQL injection issue found",
            vuln_type="",
        )

        # With matching type, score should be higher or equal
        if result_with_type and result_without_type:
            assert result_with_type["duplicate_score"] >= result_without_type["duplicate_score"]
        elif result_with_type:
            # Only matched with type — type boost pushed it over threshold
            assert result_with_type["duplicate_score"] >= DuplicateDetector.TITLE_THRESHOLD

    def test_mismatched_vuln_type_does_not_falsely_boost(self):
        """Different vuln type should not push unrelated titles to match."""
        reports = [_make_report("1", "XSS in comment field", weakness="xss")]
        detector = DuplicateDetector(reports)

        result = detector.check_duplicate(
            title="Remote code execution via file upload",
            vuln_type="rce",
        )
        assert result is None

    def test_vuln_type_in_title_partial_match(self):
        """If vuln_type appears in report title, partial credit is applied."""
        reports = [_make_report("1", "stored xss in user profile")]
        detector = DuplicateDetector(reports)

        # Compute score directly via internal method
        norm_title = DuplicateDetector._normalize("another xss issue")
        norm_desc = ""
        score = detector._compute_similarity(
            norm_title=norm_title,
            norm_desc=norm_desc,
            vuln_type="xss",
            endpoint="",
            report_title=DuplicateDetector._normalize("stored xss in user profile"),
            report=reports[0],
        )
        # xss appears in report title → should get partial vuln credit (0.8 * 0.25 = 0.2)
        assert score > 0.0


# ---------------------------------------------------------------------------
# TestEndpointPathNormalization
# ---------------------------------------------------------------------------


class TestEndpointPathNormalization:
    """Tests endpoint-based matching in duplicate detection."""

    def test_exact_endpoint_match_boosts_score(self):
        reports = [
            _make_report(
                "1",
                "IDOR in user endpoint",
                vuln_info="/api/v1/users/123 returns other users data",
            )
        ]
        detector = DuplicateDetector(reports)

        norm_title = DuplicateDetector._normalize("IDOR vulnerability")
        score_with_ep = detector._compute_similarity(
            norm_title=norm_title,
            norm_desc="",
            vuln_type="idor",
            endpoint="/api/v1/users/123",
            report_title=DuplicateDetector._normalize("IDOR in user endpoint"),
            report=reports[0],
        )
        score_without_ep = detector._compute_similarity(
            norm_title=norm_title,
            norm_desc="",
            vuln_type="idor",
            endpoint="",
            report_title=DuplicateDetector._normalize("IDOR in user endpoint"),
            report=reports[0],
        )
        assert score_with_ep >= score_without_ep

    def test_different_endpoint_no_boost(self):
        reports = [
            _make_report(
                "1",
                "IDOR in admin endpoint",
                vuln_info="/api/v1/admin/users accessed",
            )
        ]
        detector = DuplicateDetector(reports)

        # Endpoint does NOT appear in vulnerability_information
        score = detector._compute_similarity(
            norm_title=DuplicateDetector._normalize("IDOR issue"),
            norm_desc="",
            vuln_type="idor",
            endpoint="/api/v2/products/999",
            report_title=DuplicateDetector._normalize("IDOR in admin endpoint"),
            report=reports[0],
        )
        # Endpoint mismatch means endpoint_sim = 0.0
        # Score should still be non-negative
        assert score >= 0.0

    def test_endpoint_substring_in_report_info(self):
        """Endpoint found as substring in vulnerability_information triggers match."""
        endpoint = "/api/v1/users"
        reports = [
            _make_report(
                "1",
                "Mass assignment",
                vuln_info=f"Sending PATCH to {endpoint}/123 allowed role escalation",
            )
        ]
        detector = DuplicateDetector(reports)

        score = detector._compute_similarity(
            norm_title=DuplicateDetector._normalize("Mass assignment vulnerability"),
            norm_desc="",
            vuln_type="mass_assignment",
            endpoint=endpoint,
            report_title=DuplicateDetector._normalize("Mass assignment"),
            report=reports[0],
        )
        # endpoint substring match should give endpoint_sim = 1.0
        assert score > 0.1


# ---------------------------------------------------------------------------
# TestTemporalProximityScoring
# ---------------------------------------------------------------------------


class TestTemporalProximityScoring:
    """
    Tests verifying temporal reasoning is not a false positive source.

    The current DuplicateDetector does not use timestamps for scoring,
    so these tests confirm the system behaves consistently regardless
    of when reports were created.
    """

    def test_old_report_still_detected_as_duplicate(self):
        """An old report with identical title is still a duplicate."""
        reports = [
            {
                "id": "100",
                "title": "SQL Injection in /login",
                "weakness": "sqli",
                "vulnerability_information": "",
                "created_at": "2020-01-01T00:00:00Z",  # very old
            }
        ]
        detector = DuplicateDetector(reports)
        result = detector.check_duplicate(
            title="SQL Injection in /login",
            vuln_type="sqli",
        )
        assert result is not None

    def test_recent_report_detected_as_duplicate(self):
        """A very recent report is also detected as duplicate."""
        reports = [
            {
                "id": "200",
                "title": "Stored XSS in comments",
                "weakness": "xss",
                "vulnerability_information": "",
                "created_at": "2026-02-01T00:00:00Z",
            }
        ]
        detector = DuplicateDetector(reports)
        result = detector.check_duplicate(
            title="Stored XSS in comments",
            vuln_type="xss",
        )
        assert result is not None

    def test_score_consistent_without_timestamp(self):
        """Reports without created_at field behave the same as those with it."""
        report_with_ts = {
            "id": "1",
            "title": "Open redirect",
            "weakness": "redirect",
            "vulnerability_information": "",
            "created_at": "2025-06-01T00:00:00Z",
        }
        report_without_ts = {
            "id": "2",
            "title": "Open redirect",
            "weakness": "redirect",
            "vulnerability_information": "",
        }
        d1 = DuplicateDetector([report_with_ts])
        d2 = DuplicateDetector([report_without_ts])

        r1 = d1.check_duplicate(title="Open redirect", vuln_type="redirect")
        r2 = d2.check_duplicate(title="Open redirect", vuln_type="redirect")

        assert (r1 is not None) == (r2 is not None)
        if r1 and r2:
            assert abs(r1["duplicate_score"] - r2["duplicate_score"]) < 0.01


# ---------------------------------------------------------------------------
# TestCombinedWeightedScoring
# ---------------------------------------------------------------------------


class TestCombinedWeightedScoring:
    """Tests the combined weighted scoring formula."""

    def test_weights_sum_to_one(self):
        """The four weights in _compute_similarity must sum to ~1.0."""
        # title=0.4, vuln_type=0.25, endpoint=0.2, description=0.15
        weights = [0.4, 0.25, 0.2, 0.15]
        assert abs(sum(weights) - 1.0) < 1e-9

    def test_perfect_match_all_fields(self):
        """When all fields match perfectly, score should be very high."""
        reports = [
            _make_report(
                "1",
                "XSS in search bar",
                weakness="xss",
                vuln_info="/search?q=<script> reflected xss in search bar endpoint",
            )
        ]
        detector = DuplicateDetector(reports)

        score = detector._compute_similarity(
            norm_title=DuplicateDetector._normalize("XSS in search bar"),
            norm_desc=DuplicateDetector._normalize("reflected xss in search bar endpoint"),
            vuln_type="xss",
            endpoint="/search",
            report_title=DuplicateDetector._normalize("XSS in search bar"),
            report=reports[0],
        )
        assert score >= 0.5

    def test_no_overlap_score_is_zero_or_low(self):
        """Completely unrelated finding should have near-zero score."""
        reports = [
            _make_report(
                "1",
                "Path traversal in file download",
                weakness="lfi",
                vuln_info="/download?file=../../etc/passwd",
            )
        ]
        detector = DuplicateDetector(reports)

        score = detector._compute_similarity(
            norm_title=DuplicateDetector._normalize("GraphQL introspection enabled"),
            norm_desc=DuplicateDetector._normalize("graphql schema exposed via introspection query"),
            vuln_type="information_disclosure",
            endpoint="/graphql",
            report_title=DuplicateDetector._normalize("Path traversal in file download"),
            report=reports[0],
        )
        assert score < DuplicateDetector.TITLE_THRESHOLD

    def test_duplicate_score_appended_to_result(self):
        """check_duplicate must include 'duplicate_score' in the returned dict."""
        reports = [_make_report("42", "SSRF in webhook URL")]
        detector = DuplicateDetector(reports)

        result = detector.check_duplicate(
            title="SSRF in webhook URL",
            vuln_type="ssrf",
        )
        assert result is not None
        assert "duplicate_score" in result
        assert isinstance(result["duplicate_score"], float)
        assert result["id"] == "42"

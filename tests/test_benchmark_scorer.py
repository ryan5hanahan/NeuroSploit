"""
Phase 1 Benchmark Tests — Scorer class

Tests the Scorer class with various finding/ground-truth combinations:
  - Perfect matches (all TPs)
  - Partial matches (mixed TP/FN)
  - No matches (all False Negatives)
  - False positives (agent findings with no ground-truth match)
  - F1 calculation edge cases
  - _match_finding with difflib.SequenceMatcher
  - _load_ground_truth_from_yaml static helper
"""

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.scorer import Scorer, MATCH_THRESHOLD


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

GROUND_TRUTH = [
    {
        "id": "sqli_login",
        "vuln_type": "sqli",
        "severity": "critical",
        "endpoint": "/api/login",
        "parameter": "email",
        "match_keywords": ["sql injection", "login bypass", "sqli"],
        "description": "SQL injection on login endpoint",
    },
    {
        "id": "xss_search",
        "vuln_type": "xss",
        "severity": "medium",
        "endpoint": "/search",
        "parameter": "q",
        "match_keywords": ["xss", "cross-site scripting", "reflected"],
        "description": "Reflected XSS in search",
    },
    {
        "id": "idor_users",
        "vuln_type": "idor",
        "severity": "high",
        "endpoint": "/api/users/{id}",
        "parameter": "id",
        "match_keywords": ["idor", "insecure direct object"],
        "description": "IDOR on user API",
    },
]


@pytest.fixture
def ground_truth():
    """Three-entry ground truth list for reuse across test classes."""
    return list(GROUND_TRUTH)


@pytest.fixture
def scorer(ground_truth):
    """Scorer loaded with the three-entry ground truth."""
    return Scorer(ground_truth)


@pytest.fixture
def perfect_findings():
    """Agent findings that closely match every ground-truth entry."""
    return [
        {
            "title": "SQL Injection on Login — sqli login bypass",
            "vulnerability_type": "sqli",
            "affected_endpoint": "/api/login",
            "description": "SQL injection allows login bypass via email field",
        },
        {
            "title": "Reflected XSS in Search",
            "vulnerability_type": "xss",
            "affected_endpoint": "/search",
            "description": "Cross-site scripting reflected xss via search query parameter",
        },
        {
            "title": "IDOR on User API",
            "vulnerability_type": "idor",
            "affected_endpoint": "/api/users/123",
            "description": "Insecure direct object reference allows accessing other users data",
        },
    ]


# ---------------------------------------------------------------------------
# TestScorerPerfectMatch
# ---------------------------------------------------------------------------


class TestScorerPerfectMatch:
    """All agent findings match a ground-truth entry — 3 TPs, 0 FP/FN."""

    def test_true_positives_count(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["true_positives"] == 3

    def test_false_positives_zero(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["false_positives"] == 0

    def test_false_negatives_zero(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["false_negatives"] == 0

    def test_precision_is_one(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["precision"] == pytest.approx(1.0, abs=0.01)

    def test_recall_is_one(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["recall"] == pytest.approx(1.0, abs=0.01)

    def test_f1_is_one(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["f1"] == pytest.approx(1.0, abs=0.01)

    def test_matched_pairs_populated(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert len(result["matched_pairs"]) == 3
        for pair in result["matched_pairs"]:
            assert pair["score"] >= MATCH_THRESHOLD

    def test_unmatched_lists_empty(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert result["unmatched_findings"] == []
        assert result["unmatched_truths"] == []


# ---------------------------------------------------------------------------
# TestScorerPartialMatch
# ---------------------------------------------------------------------------


class TestScorerPartialMatch:
    """Agent finds only the first two vulnerabilities — 2 TP, 0 FP, 1 FN."""

    def test_partial_tp_fn(self, scorer):
        findings = [
            {
                "title": "SQL Injection Login Bypass",
                "vulnerability_type": "sqli",
                "affected_endpoint": "/api/login",
                "description": "SQL injection sqli login bypass",
            },
            {
                "title": "Reflected XSS in Search",
                "vulnerability_type": "xss",
                "affected_endpoint": "/search",
                "description": "Cross-site scripting reflected xss in search",
            },
        ]
        result = scorer.score_findings(findings)
        assert result["true_positives"] == 2
        assert result["false_negatives"] == 1
        assert result["false_positives"] == 0

    def test_partial_recall(self, scorer):
        findings = [
            {
                "title": "SQL Injection on Login",
                "vulnerability_type": "sqli",
                "affected_endpoint": "/api/login",
                "description": "SQL injection login bypass",
            },
        ]
        result = scorer.score_findings(findings)
        assert result["recall"] == pytest.approx(1 / 3, abs=0.01)

    def test_partial_precision_one(self, scorer):
        """Only one finding, and it matches — precision should be 1.0."""
        findings = [
            {
                "title": "SQL Injection on Login",
                "vulnerability_type": "sqli",
                "affected_endpoint": "/api/login",
                "description": "SQL injection login bypass",
            },
        ]
        result = scorer.score_findings(findings)
        assert result["precision"] == pytest.approx(1.0, abs=0.01)

    def test_unmatched_truths_contain_missed(self, scorer):
        findings = [
            {
                "title": "SQL Injection Found",
                "vulnerability_type": "sqli",
                "affected_endpoint": "/api/login",
                "description": "SQL injection login bypass sqli",
            },
        ]
        result = scorer.score_findings(findings)
        missed_ids = [t["id"] for t in result["unmatched_truths"]]
        assert "xss_search" in missed_ids
        assert "idor_users" in missed_ids


# ---------------------------------------------------------------------------
# TestScorerNoMatches — all False Negatives
# ---------------------------------------------------------------------------


class TestScorerNoMatches:
    """Agent returns no findings — 0 TP, 0 FP, 3 FN, all metrics zero."""

    def test_no_findings_tp_zero(self, scorer):
        result = scorer.score_findings([])
        assert result["true_positives"] == 0

    def test_no_findings_fn_equals_ground_truth(self, scorer, ground_truth):
        result = scorer.score_findings([])
        assert result["false_negatives"] == len(ground_truth)

    def test_no_findings_fp_zero(self, scorer):
        result = scorer.score_findings([])
        assert result["false_positives"] == 0

    def test_no_findings_precision_zero(self, scorer):
        result = scorer.score_findings([])
        assert result["precision"] == 0.0

    def test_no_findings_recall_zero(self, scorer):
        result = scorer.score_findings([])
        assert result["recall"] == 0.0

    def test_no_findings_f1_zero(self, scorer):
        result = scorer.score_findings([])
        assert result["f1"] == 0.0

    def test_all_truths_in_unmatched(self, scorer, ground_truth):
        result = scorer.score_findings([])
        assert len(result["unmatched_truths"]) == len(ground_truth)


# ---------------------------------------------------------------------------
# TestScorerFalsePositives
# ---------------------------------------------------------------------------


class TestScorerFalsePositives:
    """Agent returns findings unrelated to ground truth — all FPs, 3 FNs."""

    def test_irrelevant_findings_are_fp(self, scorer):
        findings = [
            {
                "title": "Missing X-Frame-Options header",
                "vulnerability_type": "misconfiguration",
                "affected_endpoint": "/",
                "description": "Security header missing",
            },
            {
                "title": "Outdated jQuery version detected",
                "vulnerability_type": "outdated_component",
                "affected_endpoint": "/",
                "description": "jQuery 2.1.4 has known vulnerabilities",
            },
        ]
        result = scorer.score_findings(findings)
        assert result["false_positives"] == 2
        assert result["true_positives"] == 0
        assert result["false_negatives"] == 3

    def test_fp_precision_is_zero(self, scorer):
        findings = [
            {
                "title": "Missing HSTS header",
                "vulnerability_type": "misconfiguration",
                "affected_endpoint": "/",
                "description": "HTTP Strict Transport Security not set",
            },
        ]
        result = scorer.score_findings(findings)
        assert result["precision"] == 0.0

    def test_fp_appear_in_unmatched_findings(self, scorer):
        findings = [
            {
                "title": "Open port 8080 detected",
                "vulnerability_type": "info_disclosure",
                "affected_endpoint": "/",
                "description": "Port scan revealed unexpected open port",
            },
        ]
        result = scorer.score_findings(findings)
        assert len(result["unmatched_findings"]) == 1
        assert result["unmatched_findings"][0]["title"] == "Open port 8080 detected"


# ---------------------------------------------------------------------------
# TestScorerF1Calculation
# ---------------------------------------------------------------------------


class TestScorerF1Calculation:
    """Verify the F1 harmonic-mean formula in various cases."""

    def test_f1_harmonic_mean_perfect(self, scorer, perfect_findings):
        """F1 = 2*P*R / (P+R).  With P=R=1, F1 = 1."""
        result = scorer.score_findings(perfect_findings)
        p = result["precision"]
        r = result["recall"]
        expected = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        assert result["f1"] == pytest.approx(expected, abs=1e-4)

    def test_f1_mixed_results(self, scorer):
        """2 TP, 1 FN, 1 FP — verify formula holds."""
        findings = [
            {
                "title": "SQL Injection login bypass sqli",
                "vulnerability_type": "sqli",
                "affected_endpoint": "/api/login",
                "description": "SQL injection sqli login bypass",
            },
            {
                "title": "Reflected XSS in search cross-site scripting",
                "vulnerability_type": "xss",
                "affected_endpoint": "/search",
                "description": "xss reflected cross-site scripting search",
            },
            {
                "title": "Completely unrelated finding",
                "vulnerability_type": "misconfiguration",
                "affected_endpoint": "/robots.txt",
                "description": "robots.txt discloses hidden paths",
            },
        ]
        result = scorer.score_findings(findings)
        p = result["precision"]
        r = result["recall"]
        expected = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        assert result["f1"] == pytest.approx(expected, abs=1e-4)

    def test_f1_zero_when_no_tp(self, scorer):
        findings = [
            {
                "title": "Irrelevant issue",
                "vulnerability_type": "info_disclosure",
                "affected_endpoint": "/",
                "description": "Not matching anything",
            }
        ]
        result = scorer.score_findings(findings)
        assert result["f1"] == 0.0

    def test_f1_returns_float(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings)
        assert isinstance(result["f1"], float)


# ---------------------------------------------------------------------------
# TestMatchFinding — _match_finding with SequenceMatcher
# ---------------------------------------------------------------------------


class TestMatchFinding:
    """Unit tests for Scorer._match_finding() using difflib.SequenceMatcher."""

    def test_identical_match_scores_above_threshold(self):
        scorer = Scorer([])
        finding = {
            "title": "SQL Injection on login sqli login bypass",
            "vulnerability_type": "sqli",
            "affected_endpoint": "/api/login",
            "description": "sql injection sqli login bypass authentication",
        }
        score = scorer._match_finding(finding, GROUND_TRUTH[0])
        assert score >= MATCH_THRESHOLD, f"Expected >= {MATCH_THRESHOLD}, got {score}"

    def test_unrelated_finding_scores_below_threshold(self):
        scorer = Scorer([])
        finding = {
            "title": "Server version disclosure via Server header",
            "vulnerability_type": "info_disclosure",
            "affected_endpoint": "/",
            "description": "Apache 2.4.41 exposed in response headers",
        }
        score = scorer._match_finding(finding, GROUND_TRUTH[0])
        assert score < MATCH_THRESHOLD, f"Expected < {MATCH_THRESHOLD}, got {score}"

    def test_returns_float_in_zero_one(self):
        scorer = Scorer([])
        finding = {
            "title": "Test finding",
            "vulnerability_type": "xss",
            "affected_endpoint": "/search",
            "description": "xss reflected",
        }
        for truth in GROUND_TRUTH:
            score = scorer._match_finding(finding, truth)
            assert 0.0 <= score <= 1.0, f"Score {score} out of [0, 1] for truth {truth['id']}"

    def test_empty_finding_scores_zero(self):
        scorer = Scorer([])
        score = scorer._match_finding({}, GROUND_TRUTH[0])
        assert score == 0.0

    def test_keyword_presence_boosts_score(self):
        """A finding containing ground-truth keywords should score higher."""
        scorer = Scorer([])
        truth = GROUND_TRUTH[1]  # xss_search: keywords = ["xss", "cross-site scripting", "reflected"]

        with_keywords = {
            "title": "XSS in search bar",
            "vulnerability_type": "xss",
            "affected_endpoint": "/search",
            "description": "cross-site scripting reflected xss in search query",
        }
        without_keywords = {
            "title": "Something else",
            "vulnerability_type": "xss",
            "affected_endpoint": "/search",
            "description": "a vulnerability was found",
        }

        score_with = scorer._match_finding(with_keywords, truth)
        score_without = scorer._match_finding(without_keywords, truth)
        assert score_with > score_without

    def test_sequencematcher_handles_similar_types(self):
        """Similar (non-identical) vuln_types still score > 0 via SequenceMatcher."""
        scorer = Scorer([])
        finding = {
            "title": "SQL Injection Found",
            "vulnerability_type": "sql_injection",  # differs from "sqli"
            "affected_endpoint": "/api/login",
            "description": "sql injection sqli login bypass authentication",
        }
        score = scorer._match_finding(finding, GROUND_TRUTH[0])
        # SequenceMatcher("sqli", "sql_injection") > 0, so combined > 0
        assert score > 0.0

    def test_endpoint_substring_match_boosts_score(self):
        """Endpoint as substring of finding URL still gets full endpoint credit."""
        scorer = Scorer([])
        finding = {
            "title": "IDOR on user endpoint",
            "vulnerability_type": "idor",
            "affected_endpoint": "/api/users/42",  # truth endpoint is /api/users/{id}
            "description": "insecure direct object reference",
        }
        truth = GROUND_TRUTH[2]  # idor_users
        score = scorer._match_finding(finding, truth)
        assert score > 0.0


# ---------------------------------------------------------------------------
# TestLoadGroundTruthFromYaml
# ---------------------------------------------------------------------------


class TestLoadGroundTruthFromYaml:
    """Tests for Scorer._load_ground_truth_from_yaml static helper."""

    def test_loads_juice_shop_yaml(self):
        path = os.path.join(PROJECT_ROOT, "benchmark", "ground_truth", "juice_shop.yaml")
        vulns = Scorer._load_ground_truth_from_yaml(path)
        assert isinstance(vulns, list)
        assert len(vulns) >= 20, f"Expected >= 20 entries, got {len(vulns)}"

    def test_loaded_entries_have_required_keys(self):
        path = os.path.join(PROJECT_ROOT, "benchmark", "ground_truth", "juice_shop.yaml")
        vulns = Scorer._load_ground_truth_from_yaml(path)
        required = {"id", "vuln_type", "severity", "endpoint", "match_keywords"}
        for vuln in vulns:
            missing = required - set(vuln.keys())
            assert not missing, f"Entry {vuln.get('id', '?')} missing keys: {missing}"

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            Scorer._load_ground_truth_from_yaml("/nonexistent/path/ground_truth.yaml")

    def test_relative_path_resolves(self):
        """Relative path should be resolved against the project root."""
        vulns = Scorer._load_ground_truth_from_yaml("benchmark/ground_truth/juice_shop.yaml")
        assert len(vulns) >= 20

    def test_load_from_tmp_yaml(self, tmp_path):
        """Verify the helper works with an arbitrary YAML file."""
        import yaml

        gt_data = {
            "vulnerabilities": [
                {
                    "id": "test_vuln",
                    "vuln_type": "xss",
                    "severity": "high",
                    "endpoint": "/test",
                    "parameter": "q",
                    "match_keywords": ["xss"],
                    "description": "Test XSS",
                },
            ]
        }
        path = tmp_path / "gt.yaml"
        with open(path, "w") as f:
            yaml.dump(gt_data, f)

        loaded = Scorer._load_ground_truth_from_yaml(str(path))
        assert len(loaded) == 1
        assert loaded[0]["id"] == "test_vuln"


# ---------------------------------------------------------------------------
# TestScorerResultShape — ensure the dict contract is stable
# ---------------------------------------------------------------------------


class TestScorerResultShape:
    """score_findings() must return all expected keys with correct types."""

    def test_all_expected_keys_present(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings, cost_usd=1.5, steps_used=30, duration_seconds=120.5)
        for key in (
            "true_positives", "false_positives", "false_negatives",
            "precision", "recall", "f1", "cost_per_finding", "cost_usd",
            "steps_used", "duration_seconds", "matched_pairs",
            "unmatched_findings", "unmatched_truths",
        ):
            assert key in result, f"Missing key: {key}"

    def test_steps_and_duration_passed_through(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings, steps_used=42, duration_seconds=99.9)
        assert result["steps_used"] == 42
        assert result["duration_seconds"] == pytest.approx(99.9, abs=0.1)

    def test_cost_usd_passed_through(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings, cost_usd=0.42)
        assert result["cost_usd"] == pytest.approx(0.42, abs=0.001)

    def test_cost_per_finding_computed(self, scorer, perfect_findings):
        result = scorer.score_findings(perfect_findings, cost_usd=0.30)
        # 3 TPs → 0.30 / 3 = 0.10
        assert result["cost_per_finding"] == pytest.approx(0.10, abs=0.001)

    def test_cost_per_finding_zero_no_tp(self, scorer):
        result = scorer.score_findings([], cost_usd=5.00)
        assert result["cost_per_finding"] == 0.0

    def test_keyword_matching_identifies_vuln(self, ground_truth):
        """A finding with matching keywords should be matched to the right ground-truth entry."""
        scorer = Scorer(ground_truth)
        findings = [
            {
                "title": "Authentication Bypass via SQL Injection",
                "vulnerability_type": "sql_injection",
                "affected_endpoint": "/login",
                "description": "Login bypass through SQL injection sqli in email field",
            },
        ]
        result = scorer.score_findings(findings)
        matched_ids = [p["truth"]["id"] for p in result["matched_pairs"]]
        assert "sqli_login" in matched_ids

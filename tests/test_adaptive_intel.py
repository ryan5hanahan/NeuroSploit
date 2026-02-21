"""
Phase 3 Tests — Adaptive Intelligence

Tests outcome recording, program insight generation, strategy adjustment
logic, and successful vulnerability type tracking.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.bugbounty.adaptive_intel import AdaptiveIntelligence


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def intel():
    return AdaptiveIntelligence()


# ---------------------------------------------------------------------------
# TestRecordOutcomeUpdatesStats
# ---------------------------------------------------------------------------


class TestRecordOutcomeUpdatesStats:
    def test_record_accepted_increments_count(self, intel):
        intel.record_outcome(
            report_id="r1",
            program_handle="prog-a",
            outcome="accepted",
            vuln_type="xss",
            severity="high",
            payout=500.0,
        )
        stats = intel._program_stats["prog-a"]
        assert stats["total_submissions"] == 1
        assert stats["accepted"] == 1
        assert stats["total_payout"] == 500.0
        assert stats["vuln_type_success"]["xss"] == 1

    def test_record_duplicate_increments_duplicate_count(self, intel):
        intel.record_outcome(
            report_id="r2",
            program_handle="prog-a",
            outcome="duplicate",
            vuln_type="sqli",
        )
        stats = intel._program_stats["prog-a"]
        assert stats["duplicates"] == 1
        assert stats["vuln_type_failure"]["sqli"] == 1

    def test_record_rejected_increments_rejected_count(self, intel):
        intel.record_outcome(
            report_id="r3",
            program_handle="prog-b",
            outcome="rejected",
            vuln_type="info_disclosure",
        )
        stats = intel._program_stats["prog-b"]
        assert stats["rejected"] == 1
        assert stats["vuln_type_failure"]["info_disclosure"] == 1

    def test_record_not_applicable_increments_na_count(self, intel):
        intel.record_outcome(
            report_id="r4",
            program_handle="prog-b",
            outcome="not_applicable",
        )
        stats = intel._program_stats["prog-b"]
        assert stats["not_applicable"] == 1

    def test_multiple_outcomes_accumulate(self, intel):
        for i in range(5):
            intel.record_outcome(
                report_id=f"r{i}",
                program_handle="multi-prog",
                outcome="accepted",
                vuln_type="xss",
                payout=100.0,
            )
        intel.record_outcome(
            report_id="r5",
            program_handle="multi-prog",
            outcome="duplicate",
            vuln_type="xss",
        )
        stats = intel._program_stats["multi-prog"]
        assert stats["total_submissions"] == 6
        assert stats["accepted"] == 5
        assert stats["duplicates"] == 1
        assert stats["total_payout"] == 500.0

    def test_outcome_stored_in_raw_list(self, intel):
        intel.record_outcome(
            report_id="r99",
            program_handle="prog-c",
            outcome="accepted",
        )
        assert len(intel._outcomes) == 1
        assert intel._outcomes[0]["report_id"] == "r99"
        assert intel._outcomes[0]["program_handle"] == "prog-c"
        assert "recorded_at" in intel._outcomes[0]

    def test_accepted_severity_tracked(self, intel):
        intel.record_outcome(
            report_id="r1",
            program_handle="prog-d",
            outcome="accepted",
            severity="critical",
        )
        stats = intel._program_stats["prog-d"]
        assert "critical" in stats["avg_severity_accepted"]


# ---------------------------------------------------------------------------
# TestGetProgramInsightsNoData
# ---------------------------------------------------------------------------


class TestGetProgramInsightsNoData:
    def test_no_data_has_data_is_false(self, intel):
        result = intel.get_program_insights("unknown-program")
        assert result["has_data"] is False

    def test_no_data_includes_recommendation(self, intel):
        result = intel.get_program_insights("unknown-program")
        assert "recommendation" in result
        assert len(result["recommendation"]) > 0

    def test_program_name_preserved(self, intel):
        result = intel.get_program_insights("my-prog")
        assert result["program"] == "my-prog"

    def test_zero_submissions_treated_as_no_data(self, intel):
        # Touch the stats dict without adding submissions
        _ = intel._program_stats["empty-prog"]
        result = intel.get_program_insights("empty-prog")
        assert result["has_data"] is False


# ---------------------------------------------------------------------------
# TestGetProgramInsightsMixedOutcomes
# ---------------------------------------------------------------------------


class TestGetProgramInsightsMixedOutcomes:
    def _populate(self, intel, program="test-prog"):
        intel.record_outcome("r1", program, "accepted", vuln_type="xss", payout=300.0)
        intel.record_outcome("r2", program, "accepted", vuln_type="xss", payout=500.0)
        intel.record_outcome("r3", program, "duplicate", vuln_type="sqli")
        intel.record_outcome("r4", program, "rejected", vuln_type="info_disclosure")
        intel.record_outcome("r5", program, "not_applicable")

    def test_has_data_is_true(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        assert result["has_data"] is True

    def test_total_submissions_correct(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        assert result["total_submissions"] == 5

    def test_acceptance_rate_calculated(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        # 2 accepted out of 5 = 0.4
        assert result["acceptance_rate"] == 0.4

    def test_duplicate_rate_calculated(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        # 1 duplicate out of 5 = 0.2
        assert result["duplicate_rate"] == 0.2

    def test_total_payout_summed(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        assert result["total_payout"] == 800.0

    def test_successful_vuln_types_listed(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        types = [t[0] for t in result["successful_vuln_types"]]
        assert "xss" in types

    def test_avoid_vuln_types_lists_pure_failures(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        # sqli and info_disclosure only have failures, no successes
        avoid = result["avoid_vuln_types"]
        assert "sqli" in avoid or "info_disclosure" in avoid

    def test_recommendations_list_generated(self, intel):
        self._populate(intel)
        result = intel.get_program_insights("test-prog")
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) > 0


# ---------------------------------------------------------------------------
# TestStrategyAdjustmentsHighDuplicateRate
# ---------------------------------------------------------------------------


class TestStrategyAdjustmentsHighDuplicateRate:
    def test_high_duplicate_rate_triggers_novelty_adjustment(self, intel):
        """When duplicate rate > 50%, strategy should include 'increase_novelty'."""
        for i in range(3):
            intel.record_outcome(f"r{i}", "dup-prog", "duplicate", vuln_type="xss")
        intel.record_outcome("r3", "dup-prog", "accepted", vuln_type="xss", payout=100.0)

        # 3 dups out of 4 = 75% dup rate
        adjustments = intel.get_strategy_adjustments("dup-prog")
        assert "increase_novelty" in adjustments["adjustments"]
        assert "deeper_exploitation" in adjustments["adjustments"]

    def test_low_duplicate_rate_no_novelty_adjustment(self, intel):
        """Low duplicate rate should not trigger novelty adjustment."""
        for i in range(5):
            intel.record_outcome(f"r{i}", "clean-prog", "accepted", vuln_type="xss", payout=200.0)
        intel.record_outcome("r5", "clean-prog", "duplicate", vuln_type="xss")

        # 1 dup out of 6 = ~17% dup rate
        adjustments = intel.get_strategy_adjustments("clean-prog")
        assert "increase_novelty" not in adjustments["adjustments"]

    def test_low_acceptance_rate_triggers_quality_improvement(self, intel):
        """Acceptance rate < 20% triggers 'improve_report_quality'."""
        intel.record_outcome("r1", "hard-prog", "accepted", vuln_type="xss", payout=100.0)
        for i in range(9):
            intel.record_outcome(f"r{i+2}", "hard-prog", "rejected", vuln_type="info")

        # 1 accepted out of 10 = 10% acceptance rate
        adjustments = intel.get_strategy_adjustments("hard-prog")
        assert "improve_report_quality" in adjustments["adjustments"]
        assert "focus_on_severity" in adjustments["adjustments"]

    def test_no_data_returns_empty_adjustments(self, intel):
        adjustments = intel.get_strategy_adjustments("brand-new-program")
        assert adjustments["adjustments"] == []
        assert adjustments["priority_vuln_types"] == []
        assert adjustments["skip_vuln_types"] == []


# ---------------------------------------------------------------------------
# TestSuccessfulVulnTypeTracking
# ---------------------------------------------------------------------------


class TestSuccessfulVulnTypeTracking:
    def test_single_accepted_vuln_type_tracked(self, intel):
        intel.record_outcome("r1", "prog", "accepted", vuln_type="ssrf", payout=750.0)
        insights = intel.get_program_insights("prog")

        types = [t[0] for t in insights["successful_vuln_types"]]
        assert "ssrf" in types

    def test_multiple_accepted_same_type_counted(self, intel):
        for i in range(3):
            intel.record_outcome(f"r{i}", "prog", "accepted", vuln_type="idor", payout=200.0)

        insights = intel.get_program_insights("prog")
        type_map = dict(insights["successful_vuln_types"])
        assert type_map.get("idor") == 3

    def test_priority_vuln_type_requires_two_successes(self, intel):
        """get_strategy_adjustments only adds to priority_vuln_types if count >= 2."""
        intel.record_outcome("r1", "prog", "accepted", vuln_type="rce", payout=2000.0)
        # Only 1 success — should NOT be in priority types
        adjustments = intel.get_strategy_adjustments("prog")
        assert "rce" not in adjustments["priority_vuln_types"]

        intel.record_outcome("r2", "prog", "accepted", vuln_type="rce", payout=2000.0)
        # Now 2 successes — SHOULD be in priority types
        adjustments = intel.get_strategy_adjustments("prog")
        assert "rce" in adjustments["priority_vuln_types"]

    def test_failed_vuln_types_not_in_successful_list(self, intel):
        intel.record_outcome("r1", "prog", "rejected", vuln_type="rate_limiting")
        intel.record_outcome("r2", "prog", "accepted", vuln_type="xss", payout=100.0)

        insights = intel.get_program_insights("prog")
        successful_types = [t[0] for t in insights["successful_vuln_types"]]
        assert "rate_limiting" not in successful_types
        assert "xss" in successful_types

    def test_skip_vuln_types_in_strategy(self, intel):
        """Vuln types with only failures should appear in skip_vuln_types."""
        intel.record_outcome("r1", "prog", "rejected", vuln_type="csrf")
        intel.record_outcome("r2", "prog", "rejected", vuln_type="csrf")
        intel.record_outcome("r3", "prog", "accepted", vuln_type="ssrf", payout=300.0)

        adjustments = intel.get_strategy_adjustments("prog")
        assert "csrf" in adjustments["skip_vuln_types"]
        assert "ssrf" not in adjustments["skip_vuln_types"]

    def test_successful_types_sorted_by_count_descending(self, intel):
        intel.record_outcome("r1", "prog", "accepted", vuln_type="xss", payout=100.0)
        intel.record_outcome("r2", "prog", "accepted", vuln_type="xss", payout=100.0)
        intel.record_outcome("r3", "prog", "accepted", vuln_type="sqli", payout=200.0)
        intel.record_outcome("r4", "prog", "accepted", vuln_type="xss", payout=100.0)

        insights = intel.get_program_insights("prog")
        types = insights["successful_vuln_types"]
        # xss has 3 hits, sqli has 1 — xss should come first
        assert types[0][0] == "xss"
        assert types[0][1] == 3

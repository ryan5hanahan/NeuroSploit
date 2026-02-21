"""
Tests for ContextRefresher — dynamic context injection for the LLM-driven agent.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.prompts.context_refresher import ContextRefresher


class TestContextRefresherShouldRefresh:
    def test_should_refresh_returns_false_at_step_zero(self):
        refresher = ContextRefresher(refresh_interval=15)
        assert refresher.should_refresh(0) is False

    def test_should_refresh_returns_false_before_interval(self):
        refresher = ContextRefresher(refresh_interval=15)
        for step in range(1, 15):
            assert refresher.should_refresh(step) is False

    def test_should_refresh_returns_true_at_interval(self):
        refresher = ContextRefresher(refresh_interval=15)
        assert refresher.should_refresh(15) is True

    def test_should_refresh_returns_true_after_interval(self):
        refresher = ContextRefresher(refresh_interval=15)
        assert refresher.should_refresh(20) is True

    def test_should_refresh_resets_after_generate(self):
        refresher = ContextRefresher(refresh_interval=15)
        assert refresher.should_refresh(15) is True
        # Trigger the refresh to record the step
        refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
        )
        # Should not refresh again until another 15 steps pass
        assert refresher.should_refresh(16) is False
        assert refresher.should_refresh(29) is False
        assert refresher.should_refresh(30) is True

    def test_custom_refresh_interval(self):
        refresher = ContextRefresher(refresh_interval=5)
        assert refresher.should_refresh(4) is False
        assert refresher.should_refresh(5) is True

    def test_default_interval_is_15(self):
        refresher = ContextRefresher()
        assert refresher.refresh_interval == 15


class TestContextRefresherGenerateUpdate:
    def test_generate_with_no_findings(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
        )
        assert "Context Refresh (Step 15/100)" in result
        assert "No findings yet" in result

    def test_generate_with_findings_shows_severity_counts(self):
        refresher = ContextRefresher()
        findings = [
            {"title": "SQLi", "severity": "critical"},
            {"title": "XSS", "severity": "high"},
            {"title": "Info Leak", "severity": "high"},
            {"title": "Verbose Error", "severity": "low"},
        ]
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=findings,
        )
        assert "4 total" in result
        assert "critical: 1" in result
        assert "high: 2" in result
        assert "low: 1" in result

    def test_generate_shows_last_three_findings(self):
        refresher = ContextRefresher()
        findings = [
            {"title": f"Finding {i}", "severity": "medium"}
            for i in range(6)
        ]
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=findings,
        )
        # Last 3 findings should appear
        assert "Finding 3" in result
        assert "Finding 4" in result
        assert "Finding 5" in result
        # First finding should NOT appear in recent list
        assert "Finding 0" not in result

    def test_generate_uses_vulnerability_type_as_fallback_title(self):
        refresher = ContextRefresher()
        findings = [
            {"vulnerability_type": "SQL Injection", "severity": "critical"},
        ]
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=findings,
        )
        assert "SQL Injection" in result

    def test_generate_includes_plan_snapshot(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
            plan_snapshot="Phase: Discovery\nObjective: Enumerate endpoints",
        )
        assert "Current Plan State" in result
        assert "Phase: Discovery" in result

    def test_generate_omits_plan_section_when_empty(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
            plan_snapshot="",
        )
        assert "Current Plan State" not in result

    def test_generate_includes_governance_warnings(self):
        refresher = ContextRefresher()
        warnings = ["Out-of-scope host detected", "Rate limit approaching"]
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
            governance_warnings=warnings,
        )
        assert "Governance Warnings" in result
        assert "Out-of-scope host detected" in result
        assert "Rate limit approaching" in result

    def test_generate_omits_governance_section_when_none(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
            governance_warnings=None,
        )
        assert "Governance Warnings" not in result

    def test_generate_omits_governance_section_when_empty_list(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
            governance_warnings=[],
        )
        assert "Governance Warnings" not in result

    def test_generate_shows_budget_percentage(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=50,
            max_steps=100,
            findings=[],
        )
        assert "50%" in result
        assert "50/100" in result

    def test_generate_budget_zero_max_steps(self):
        refresher = ContextRefresher()
        # Should not raise ZeroDivisionError
        result = refresher.generate_context_update(
            current_step=0,
            max_steps=0,
            findings=[],
        )
        assert "0%" in result

    def test_generate_budget_warning_at_80_percent(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=80,
            max_steps=100,
            findings=[],
        )
        assert "80%" in result
        assert "WARNING" in result
        assert "Budget is running low" in result

    def test_generate_budget_warning_at_90_percent(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=90,
            max_steps=100,
            findings=[],
        )
        assert "90%" in result
        assert "WARNING" in result

    def test_generate_no_budget_warning_below_80_percent(self):
        refresher = ContextRefresher()
        result = refresher.generate_context_update(
            current_step=79,
            max_steps=100,
            findings=[],
        )
        assert "79%" in result
        assert "WARNING" not in result

    def test_generate_updates_last_refresh_step(self):
        refresher = ContextRefresher()
        assert refresher._last_refresh_step == 0
        refresher.generate_context_update(
            current_step=30,
            max_steps=100,
            findings=[],
        )
        assert refresher._last_refresh_step == 30


class TestContextRefresherReset:
    def test_reset_clears_last_refresh_step(self):
        refresher = ContextRefresher()
        refresher.generate_context_update(
            current_step=30,
            max_steps=100,
            findings=[],
        )
        assert refresher._last_refresh_step == 30
        refresher.reset()
        assert refresher._last_refresh_step == 0

    def test_reset_allows_refresh_again_from_zero(self):
        refresher = ContextRefresher(refresh_interval=15)
        refresher.generate_context_update(
            current_step=15,
            max_steps=100,
            findings=[],
        )
        # Not yet due for another refresh
        assert refresher.should_refresh(20) is False
        # After reset, interval is measured from 0 again
        refresher.reset()
        assert refresher.should_refresh(15) is True

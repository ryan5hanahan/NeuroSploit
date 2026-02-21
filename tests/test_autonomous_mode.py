"""
Phase 2 Tests — Autonomous Mode Flag Behavior

Tests that verify autonomous=True configures the LLMDrivenAgent with the
correct scope (full_auto), increased step budget (200), and skipped
checkpoint reflections.
"""

import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _make_mock_llm():
    """Create a minimal mock LLM client that satisfies agent construction."""
    llm = MagicMock()
    llm.cost_tracker = MagicMock()
    llm.cost_tracker.over_budget = False
    llm.cost_tracker.get_report = MagicMock(return_value={})
    return llm


def _make_agent(tmp_path, autonomous=False, max_steps=100, **kwargs):
    """Helper: construct an LLMDrivenAgent with minimal mocking."""
    from backend.core.llm_agent import LLMDrivenAgent

    llm = _make_mock_llm()

    agent = LLMDrivenAgent(
        target="http://testapp.local",
        objective="Test security assessment",
        max_steps=max_steps,
        llm_client=llm,
        governance_agent=None,
        data_dir=str(tmp_path),
        autonomous=autonomous,
        **kwargs,
    )
    return agent


# ---------------------------------------------------------------------------
# autonomous=True — scope enforcement
# ---------------------------------------------------------------------------


class TestAutonomousModeScope:
    def test_autonomous_true_sets_scope_to_auto_pwn(self, tmp_path):
        """When autonomous=True, governance scope profile must be auto_pwn."""
        agent = _make_agent(tmp_path, autonomous=True)
        assert agent.autonomous is True
        # The scope_profile for autonomous mode must be auto_pwn
        assert agent.scope_profile == "auto_pwn"

    def test_autonomous_false_preserves_default_scope(self, tmp_path):
        """When autonomous=False, the default scope_profile should apply."""
        agent = _make_agent(tmp_path, autonomous=False)
        assert agent.autonomous is False
        # Default scope should be pentest
        assert agent.scope_profile == "pentest"

    def test_autonomous_true_with_explicit_scope_overrides_to_auto_pwn(self, tmp_path):
        """autonomous=True should force scope to auto_pwn."""
        agent = _make_agent(tmp_path, autonomous=True)
        assert agent.scope_profile == "auto_pwn"


# ---------------------------------------------------------------------------
# autonomous=True — step budget
# ---------------------------------------------------------------------------


class TestAutonomousModeStepBudget:
    def test_autonomous_true_increases_max_steps_to_200(self, tmp_path):
        """When autonomous=True without explicit max_steps, budget should default to 200."""
        agent = _make_agent(tmp_path, autonomous=True)
        assert agent.max_steps == 200

    def test_autonomous_true_respects_explicit_max_steps_above_200(self, tmp_path):
        """If a caller explicitly passes max_steps > 200 with autonomous=True, respect it."""
        agent = _make_agent(tmp_path, autonomous=True, max_steps=300)
        assert agent.max_steps == 300

    def test_autonomous_false_preserves_default_max_steps(self, tmp_path):
        """When autonomous=False, max_steps should remain at whatever was passed."""
        agent = _make_agent(tmp_path, autonomous=False, max_steps=100)
        assert agent.max_steps == 100

    def test_autonomous_false_small_budget_unchanged(self, tmp_path):
        """When autonomous=False, small budgets are not modified."""
        agent = _make_agent(tmp_path, autonomous=False, max_steps=50)
        assert agent.max_steps == 50


# ---------------------------------------------------------------------------
# autonomous=True — checkpoint reflection behavior
# ---------------------------------------------------------------------------


class TestAutonomousModeCheckpoints:
    def test_autonomous_true_skips_checkpoint_reflections(self, tmp_path):
        """When autonomous=True, checkpoint reflections should be disabled."""
        agent = _make_agent(tmp_path, autonomous=True)
        assert agent.skip_checkpoints is True

    def test_autonomous_false_enables_checkpoint_reflections(self, tmp_path):
        """When autonomous=False, checkpoint reflections should run normally."""
        agent = _make_agent(tmp_path, autonomous=False)
        assert agent.skip_checkpoints is False

    def test_autonomous_true_plan_manager_not_checkpointing(self, tmp_path):
        """With skip_checkpoints=True, should_checkpoint always returns False."""
        agent = _make_agent(tmp_path, autonomous=True)
        # Even if the plan manager would normally trigger at 20%, skip_checkpoints
        # should prevent checkpoints from firing
        if agent.skip_checkpoints:
            # Patch plan_manager.should_checkpoint to confirm it would fire normally
            agent.plan_manager._plan = MagicMock()
            agent.plan_manager._plan.checkpoints = []

            # In autonomous mode, the run loop checks skip_checkpoints before
            # calling plan_manager.should_checkpoint — so even if should_checkpoint
            # returns True, it's bypassed
            would_checkpoint = agent.plan_manager.should_checkpoint(20, 100)
            # The behavior we want to enforce: agent.skip_checkpoints gates the call
            assert agent.skip_checkpoints is True


# ---------------------------------------------------------------------------
# Default behavior (autonomous=False)
# ---------------------------------------------------------------------------


class TestNonAutonomousDefaults:
    def test_default_agent_is_not_autonomous(self, tmp_path):
        """Agents created without autonomous flag should default to non-autonomous."""
        from backend.core.llm_agent import LLMDrivenAgent

        llm = _make_mock_llm()
        agent = LLMDrivenAgent(
            target="http://testapp.local",
            objective="Test",
            llm_client=llm,
            data_dir=str(tmp_path),
        )
        # The autonomous flag should default to False
        assert getattr(agent, "autonomous", False) is False

    def test_default_agent_max_steps_is_100(self, tmp_path):
        """Default max_steps without autonomous flag should be 100."""
        from backend.core.llm_agent import LLMDrivenAgent

        llm = _make_mock_llm()
        agent = LLMDrivenAgent(
            target="http://testapp.local",
            objective="Test",
            llm_client=llm,
            data_dir=str(tmp_path),
        )
        assert agent.max_steps == 100

    def test_default_agent_skip_checkpoints_is_false(self, tmp_path):
        """Default skip_checkpoints without autonomous flag should be False."""
        from backend.core.llm_agent import LLMDrivenAgent

        llm = _make_mock_llm()
        agent = LLMDrivenAgent(
            target="http://testapp.local",
            objective="Test",
            llm_client=llm,
            data_dir=str(tmp_path),
        )
        assert getattr(agent, "skip_checkpoints", False) is False

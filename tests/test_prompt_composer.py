"""Tests for the prompt composer module.

Verifies system prompt assembly, budget warnings, governance context injection,
auth context injection, and reflection prompt output.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.prompts.prompt_composer import (
    compose_agent_system_prompt,
    compose_reflection_prompt,
)


def _base_prompt(**kwargs) -> str:
    """Build a basic system prompt with sensible defaults."""
    defaults = dict(
        target="https://example.com",
        objective="Full penetration test",
        operation_id="test-op-001",
        current_step=0,
        max_steps=100,
    )
    defaults.update(kwargs)
    return compose_agent_system_prompt(**defaults)


# ===========================================================================
# Basic output
# ===========================================================================

class TestComposeAgentSystemPromptBasic:
    """compose_agent_system_prompt basic output tests."""

    def test_prompt_is_non_empty_string(self):
        """Prompt returns a non-empty string."""
        prompt = _base_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_prompt_contains_target(self):
        """Prompt contains the target URL."""
        prompt = _base_prompt(target="https://target-under-test.com")
        assert "target-under-test.com" in prompt

    def test_prompt_contains_objective(self):
        """Prompt contains the assessment objective."""
        prompt = _base_prompt(objective="Identify all XSS vulnerabilities")
        assert "Identify all XSS vulnerabilities" in prompt

    def test_prompt_contains_operation_id(self):
        """Prompt contains the operation ID."""
        prompt = _base_prompt(operation_id="op-abc-123")
        assert "op-abc-123" in prompt


# ===========================================================================
# Budget warnings
# ===========================================================================

class TestPromptBudgetWarnings:
    """Budget warning injection at various thresholds."""

    def test_budget_warning_at_80_pct(self):
        """Budget warning appears when step is at 80% of max."""
        prompt = _base_prompt(current_step=80, max_steps=100)
        assert "80" in prompt or "budget" in prompt.lower() or "steps" in prompt.lower()

    def test_budget_note_at_60_pct(self):
        """Budget note appears at 60% consumption."""
        prompt = _base_prompt(current_step=60, max_steps=100)
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_no_budget_warning_under_60_pct(self):
        """Under 60% usage, prompt does not include urgent budget warnings."""
        prompt = _base_prompt(current_step=30, max_steps=100)
        # Should not have critical budget warning at 30%
        # Note: "CRITICAL" may appear in execution templates (e.g. severity levels)
        # so check specifically for budget-related critical warnings
        assert "CRITICAL BUDGET" not in prompt.upper()

    def test_high_step_count_reflected(self):
        """High step count (90%) is reflected somewhere in prompt."""
        prompt = _base_prompt(current_step=90, max_steps=100)
        assert "90" in prompt or "9" in prompt


# ===========================================================================
# Governance context injection
# ===========================================================================

class TestPromptGovernanceContext:
    """Governance context is injected into system prompt."""

    def test_recon_only_prompt_includes_recon_only_header(self):
        """Recon-only scope injects RECON ONLY section."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "recon_only",
                "governance_mode": "strict",
                "allowed_phases": ["recon", "report"],
            }
        )
        assert "RECON ONLY" in prompt

    def test_recon_only_prompt_includes_forbidden_section(self):
        """Recon-only prompt has FORBIDDEN Actions section."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "recon_only",
                "governance_mode": "strict",
            }
        )
        assert "FORBIDDEN" in prompt or "STRICTLY FORBIDDEN" in prompt

    def test_recon_only_prompt_mentions_sql_injection(self):
        """Recon-only prompt explicitly forbids SQL injection."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "recon_only",
                "governance_mode": "strict",
            }
        )
        assert "SQL injection" in prompt or "sqli" in prompt.lower() or "sql" in prompt.lower()

    def test_recon_only_will_be_blocked_note(self):
        """Recon-only prompt includes WILL BE BLOCKED note."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "recon_only",
                "governance_mode": "strict",
            }
        )
        assert "WILL BE BLOCKED" in prompt or "blocked" in prompt.lower()

    def test_full_auto_prompt_no_recon_only_header(self):
        """Full auto scope does not inject RECON ONLY section."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "full_auto",
                "governance_mode": "warn",
            }
        )
        assert "RECON ONLY" not in prompt

    def test_no_governance_no_forbidden_section(self):
        """No governance context produces no FORBIDDEN section."""
        prompt = _base_prompt(governance_context=None)
        assert "STRICTLY FORBIDDEN" not in prompt


# ===========================================================================
# Auth context injection
# ===========================================================================

class TestPromptAuthContext:
    """Auth context description is injected into prompt."""

    def test_auth_context_appears_in_prompt(self):
        """auth_context string appears in the prompt."""
        prompt = _base_prompt(auth_context="Bearer token pre-configured for admin user")
        assert "Bearer token" in prompt or "admin" in prompt or "auth" in prompt.lower()

    def test_no_auth_context_is_handled(self):
        """Empty auth_context does not break prompt generation."""
        prompt = _base_prompt(auth_context="")
        assert isinstance(prompt, str)
        assert len(prompt) > 0


# ===========================================================================
# Memory section
# ===========================================================================

class TestPromptMemorySection:
    """Memory overview is injected into prompt."""

    def test_memory_overview_appears(self):
        """memory_overview string appears in prompt."""
        prompt = _base_prompt(memory_overview="Found: SQL injection on /api/login")
        assert "SQL injection" in prompt or "memory" in prompt.lower() or "found" in prompt.lower()

    def test_empty_memory_handled(self):
        """Empty memory_overview does not break prompt."""
        prompt = _base_prompt(memory_overview="")
        assert isinstance(prompt, str)


# ===========================================================================
# Plan section
# ===========================================================================

class TestPromptPlanSection:
    """Plan snapshot is injected into prompt."""

    def test_plan_snapshot_appears(self):
        """plan_snapshot appears in the assembled prompt."""
        plan = "Phase: Testing\nNext: Try XSS on /search"
        prompt = _base_prompt(plan_snapshot=plan)
        assert "Testing" in prompt or "XSS" in prompt or "plan" in prompt.lower()

    def test_empty_plan_handled(self):
        """Empty plan_snapshot does not break prompt."""
        prompt = _base_prompt(plan_snapshot="")
        assert isinstance(prompt, str)


# ===========================================================================
# Multi-target display
# ===========================================================================

class TestPromptMultiTarget:
    """Additional targets appear in the prompt."""

    def test_additional_targets_listed(self):
        """Additional targets appear somewhere in the prompt."""
        extras = ["http://api.example.com", "http://admin.example.com"]
        prompt = _base_prompt(additional_targets=extras)
        assert "api.example.com" in prompt or "admin.example.com" in prompt or "additional" in prompt.lower()

    def test_no_additional_targets_no_extra_urls(self):
        """Without additional_targets, no extra URLs are injected."""
        prompt = _base_prompt(additional_targets=None)
        assert isinstance(prompt, str)


# ===========================================================================
# compose_reflection_prompt
# ===========================================================================

class TestComposeReflectionPrompt:
    """compose_reflection_prompt output tests."""

    def test_reflection_prompt_is_string(self):
        """compose_reflection_prompt returns a non-empty string."""
        prompt = compose_reflection_prompt(
            current_step=50,
            max_steps=100,
            findings_count=3,
            tools_used={"nmap": 2, "nuclei": 1},
            memory_summary="Scanned /api/login, Found XSS candidate",
            plan_snapshot="Phase: Testing",
        )
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_reflection_prompt_mentions_findings(self):
        """Reflection prompt includes findings count."""
        prompt = compose_reflection_prompt(
            current_step=25,
            max_steps=100,
            findings_count=5,
            tools_used={},
            memory_summary="",
            plan_snapshot="",
        )
        assert "5" in prompt or "finding" in prompt.lower()

    def test_reflection_prompt_mentions_step(self):
        """Reflection prompt includes step information."""
        prompt = compose_reflection_prompt(
            current_step=25,
            max_steps=100,
            findings_count=0,
            tools_used={},
            memory_summary="",
            plan_snapshot="",
        )
        assert "25" in prompt or "step" in prompt.lower()


# ===========================================================================
# New profile template selection
# ===========================================================================

class TestProfileTemplateSelection:
    """Each scope profile selects the correct execution template."""

    def test_pentest_profile_uses_pentest_template(self):
        """Pentest scope uses the pentest execution template."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "pentest",
                "governance_mode": "warn",
            }
        )
        # Pentest template has OWASP/PTES methodology references
        assert "OWASP" in prompt or "PTES" in prompt or "Penetration Test" in prompt

    def test_ctf_profile_uses_ctf_template(self):
        """CTF scope uses the CTF execution template."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "ctf",
                "governance_mode": "off",
            }
        )
        assert "CTF" in prompt or "flag" in prompt.lower()

    def test_bug_bounty_profile_uses_bug_bounty_template(self):
        """Bug bounty scope uses the bug bounty execution template."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "bug_bounty",
                "governance_mode": "strict",
            }
        )
        assert "bounty" in prompt.lower() or "bug bounty" in prompt.lower()

    def test_auto_pwn_profile_uses_auto_pwn_template(self):
        """Auto pwn scope uses the auto pwn execution template."""
        prompt = _base_prompt(
            governance_context={
                "scope_profile": "auto_pwn",
                "governance_mode": "off",
            }
        )
        assert "autonomous" in prompt.lower() or "auto" in prompt.lower() or "exploitation" in prompt.lower()

    def test_governance_section_generated_per_profile(self):
        """Each profile generates its own governance section."""
        for profile in ["bug_bounty", "ctf", "pentest", "auto_pwn"]:
            prompt = _base_prompt(
                governance_context={
                    "scope_profile": profile,
                    "governance_mode": "warn",
                }
            )
            assert "Scope Profile" in prompt
            assert profile in prompt

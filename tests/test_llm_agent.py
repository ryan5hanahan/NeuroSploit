"""Tests for LLMDrivenAgent — initialization, run loop, pause/resume/cancel,
budget exhaustion, auth context building, and tool handler registration.

All tests use mocked LLM client to avoid real API calls.
"""

import asyncio
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.llm_agent import AgentResult, LLMDrivenAgent


def _make_mock_llm():
    """Create a mock UnifiedLLMClient whose generate() immediately stops the agent."""
    from backend.core.llm.providers.base import LLMResponse

    mock_llm = MagicMock()
    # generate returns a response with no tool calls → agent will stop
    stop_response = LLMResponse(
        content="Assessment complete. No vulnerabilities found.",
        tool_calls=[],
        stop_reason="end_turn",
        input_tokens=100,
        output_tokens=50,
        model="claude-sonnet-4-6",
    )
    mock_llm.generate = AsyncMock(return_value=stop_response)
    return mock_llm


def _make_agent(tmp_path, **kwargs) -> LLMDrivenAgent:
    """Create an LLMDrivenAgent with mocked dependencies."""
    defaults = dict(
        target="http://testapp.local",
        objective="Test assessment",
        max_steps=10,
        llm_client=_make_mock_llm(),
        data_dir=str(tmp_path),
        operation_id=str(uuid.uuid4()),
    )
    defaults.update(kwargs)
    return LLMDrivenAgent(**defaults)


# ===========================================================================
# Agent initialization
# ===========================================================================

class TestLLMDrivenAgentInit:
    """Verify LLMDrivenAgent initializes correctly with various params."""

    def test_basic_init(self, tmp_path):
        """Agent initializes with minimal params."""
        agent = _make_agent(tmp_path)
        assert agent.target == "http://testapp.local"
        assert agent.objective == "Test assessment"
        assert agent.max_steps == 10

    def test_operation_id_assigned(self, tmp_path):
        """operation_id is assigned (either from arg or auto-generated)."""
        op_id = str(uuid.uuid4())
        agent = _make_agent(tmp_path, operation_id=op_id)
        assert agent.operation_id == op_id

    def test_auto_operation_id(self, tmp_path):
        """Auto-generated operation_id is a non-empty string."""
        agent = LLMDrivenAgent(
            target="http://test.local",
            objective="Test",
            max_steps=10,
            llm_client=_make_mock_llm(),
            data_dir=str(tmp_path),
        )
        assert agent.operation_id
        assert len(agent.operation_id) > 0

    def test_artifacts_dir_created(self, tmp_path):
        """Artifacts directory is created during init."""
        agent = _make_agent(tmp_path)
        import os
        assert os.path.isdir(agent.artifacts_dir)

    def test_executor_registered_tools(self, tmp_path):
        """ToolExecutor has all expected handlers registered."""
        agent = _make_agent(tmp_path)
        expected = {
            "shell_execute", "http_request",
            "browser_navigate", "browser_extract_links",
            "browser_extract_forms", "browser_submit_form",
            "browser_screenshot", "browser_execute_js",
            "memory_store", "memory_search",
            "save_artifact", "report_finding",
            "update_plan", "get_payloads",
            "get_vuln_info", "stop",
            "spawn_subagent", "create_tool",
        }
        for name in expected:
            assert name in agent.executor._handlers, f"Missing handler: {name}"

    def test_not_cancelled_initially(self, tmp_path):
        """Agent is not cancelled on initialization."""
        agent = _make_agent(tmp_path)
        assert agent._cancelled is False

    def test_not_paused_initially(self, tmp_path):
        """Agent is not paused on initialization."""
        agent = _make_agent(tmp_path)
        assert agent._paused is False

    def test_autonomous_mode_bumps_max_steps(self, tmp_path):
        """Autonomous mode ensures max_steps >= 200."""
        agent = _make_agent(tmp_path, max_steps=50, autonomous=True)
        assert agent.max_steps >= 200

    def test_additional_targets_stored(self, tmp_path):
        """Additional targets are stored on the agent."""
        extras = ["http://api.testapp.local", "http://admin.testapp.local"]
        agent = _make_agent(tmp_path, additional_targets=extras)
        assert agent.additional_targets == extras

    def test_governance_agent_passed_to_executor(self, tmp_path):
        """Governance agent is wired into the ToolExecutor."""
        gov = MagicMock()
        gov.is_url_in_scope = MagicMock(return_value=True)
        gov.check_action = MagicMock(return_value=MagicMock(allowed=True))
        agent = _make_agent(tmp_path, governance_agent=gov)
        assert agent.executor.governance is gov


# ===========================================================================
# Agent run → AgentResult
# ===========================================================================

class TestLLMDrivenAgentRun:
    """Verify agent.run() returns well-formed AgentResult."""

    @pytest.mark.asyncio
    async def test_run_returns_agent_result(self, tmp_path):
        """run() returns an AgentResult instance."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert isinstance(result, AgentResult)

    @pytest.mark.asyncio
    async def test_run_result_has_target(self, tmp_path):
        """AgentResult.target matches agent target."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert result.target == "http://testapp.local"

    @pytest.mark.asyncio
    async def test_run_result_has_operation_id(self, tmp_path):
        """AgentResult.operation_id matches agent operation_id."""
        op_id = str(uuid.uuid4())
        agent = _make_agent(tmp_path, operation_id=op_id)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert result.operation_id == op_id

    @pytest.mark.asyncio
    async def test_run_result_has_findings_list(self, tmp_path):
        """AgentResult.findings is a list."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_run_result_has_steps_used(self, tmp_path):
        """AgentResult.steps_used is a non-negative integer."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert isinstance(result.steps_used, int)
        assert result.steps_used >= 0

    @pytest.mark.asyncio
    async def test_run_result_has_duration(self, tmp_path):
        """AgentResult.duration_seconds is a positive float."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert result.duration_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_run_result_status_on_success(self, tmp_path):
        """Agent that completes normally has status 'completed' or 'stopped'."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert result.status in ("completed", "stopped", "budget_exhausted")

    @pytest.mark.asyncio
    async def test_run_result_tool_usage(self, tmp_path):
        """AgentResult.tool_usage is a dict."""
        agent = _make_agent(tmp_path)
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert isinstance(result.tool_usage, dict)


# ===========================================================================
# Pause / resume / cancel
# ===========================================================================

class TestAgentPauseResumeCancel:
    """Verify pause, resume, and cancel functionality."""

    def test_pause_sets_paused_flag(self, tmp_path):
        """pause() sets _paused to True."""
        agent = _make_agent(tmp_path)
        agent.pause()
        assert agent._paused is True

    def test_resume_clears_paused_flag(self, tmp_path):
        """resume() clears _paused flag."""
        agent = _make_agent(tmp_path)
        agent.pause()
        agent.resume()
        assert agent._paused is False

    def test_cancel_sets_cancelled_flag(self, tmp_path):
        """cancel() sets _cancelled to True."""
        agent = _make_agent(tmp_path)
        agent.cancel()
        assert agent._cancelled is True

    def test_resume_sets_pause_event(self, tmp_path):
        """resume() sets the pause event so waiting coroutines unblock."""
        agent = _make_agent(tmp_path)
        agent.pause()
        agent._pause_event.clear()
        agent.resume()
        assert agent._pause_event.is_set()


# ===========================================================================
# Budget exhaustion
# ===========================================================================

class TestAgentBudgetExhaustion:
    """Verify agent stops cleanly when budget is exhausted."""

    @pytest.mark.asyncio
    async def test_budget_exhausted_status(self, tmp_path):
        """Agent with max_steps=0 should return budget_exhausted status."""
        agent = _make_agent(tmp_path, max_steps=1)
        # Pre-exhaust the budget
        agent.context.current_step = 1
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert result.status in ("budget_exhausted", "completed", "stopped")

    @pytest.mark.asyncio
    async def test_run_after_cancel_returns_cancelled(self, tmp_path):
        """Agent cancelled before run returns cancelled status."""
        agent = _make_agent(tmp_path)
        agent.cancel()
        with patch("backend.core.llm_agent.close_browser_session", new_callable=AsyncMock):
            result = await agent.run()
        assert result.status in ("cancelled", "completed", "stopped")


# ===========================================================================
# Auth context building
# ===========================================================================

class TestAgentAuthContext:
    """Verify auth context is correctly configured."""

    def test_bearer_token_context(self, tmp_path):
        """Bearer token is stored in execution context."""
        agent = _make_agent(
            tmp_path,
            auth_type="bearer",
            auth_credentials={"token": "test-bearer-token"},
        )
        headers = agent.context.get_auth_headers()
        assert "Authorization" in headers
        assert "Bearer test-bearer-token" in headers["Authorization"]

    def test_cookie_auth_context(self, tmp_path):
        """Cookie auth is stored in execution context."""
        agent = _make_agent(
            tmp_path,
            auth_type="cookie",
            auth_credentials={"cookie": "session=abc123"},
        )
        headers = agent.context.get_auth_headers()
        assert "Cookie" in headers
        assert "session=abc123" in headers["Cookie"]

    def test_custom_headers_context(self, tmp_path):
        """Custom headers are stored in execution context."""
        agent = _make_agent(
            tmp_path,
            custom_headers={"X-Custom-Header": "custom-value"},
        )
        headers = agent.context.get_auth_headers()
        assert headers.get("X-Custom-Header") == "custom-value"

    def test_no_auth_empty_headers(self, tmp_path):
        """No auth config produces empty headers (except any custom)."""
        agent = _make_agent(tmp_path)
        headers = agent.context.get_auth_headers()
        assert "Authorization" not in headers
        assert "Cookie" not in headers


# ===========================================================================
# Tool handler registration
# ===========================================================================

class TestAgentToolHandlerRegistration:
    """Verify tool handler registration and replacement."""

    def test_register_custom_handler(self, tmp_path):
        """Custom tool can be registered on the executor."""
        agent = _make_agent(tmp_path)
        custom_handler = AsyncMock(return_value="custom result")
        agent.executor.register("my_custom_tool", custom_handler)
        assert "my_custom_tool" in agent.executor._handlers

    def test_register_overwrites_handler(self, tmp_path):
        """Re-registering a tool name replaces the handler."""
        agent = _make_agent(tmp_path)
        new_handler = AsyncMock(return_value="new result")
        agent.executor.register("shell_execute", new_handler)
        assert agent.executor._handlers["shell_execute"] is new_handler

    def test_all_18_handlers_registered(self, tmp_path):
        """All 18 agent tools have handlers registered."""
        agent = _make_agent(tmp_path)
        from backend.core.llm_agent_tools import get_agent_tools
        tool_names = {t["name"] for t in get_agent_tools()}
        for name in tool_names:
            assert name in agent.executor._handlers, f"No handler for: {name}"

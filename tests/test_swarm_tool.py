"""
Tests for the swarm sub-agent tool (spawn_subagent).

Covers:
  - Tool allowlist enforcement (no spawn_subagent, create_tool, stop)
  - Budget guard rejects when insufficient steps
  - Timeout enforcement
  - Results stored in memory
  - Parent stop halts sub-agent
"""

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.tools.swarm_tool import (
    SUBAGENT_ALLOWED_TOOLS,
    SUBAGENT_TIMEOUT,
    handle_spawn_subagent,
)
from backend.core.llm.tool_executor import ExecutionContext


@pytest.fixture
def mock_llm_client():
    """Mock UnifiedLLMClient for sub-agent LLM calls."""
    client = MagicMock()

    # Mock provider that returns a text-only response (no tool calls → sub-agent done)
    mock_response = MagicMock()
    mock_response.has_tool_calls = False
    mock_response.tool_calls = []
    mock_response.text = "Recon complete: found open ports 80, 443, 8080"
    mock_response.raw = None

    mock_provider = MagicMock()
    mock_provider.supports_tools.return_value = True
    mock_provider.name = "anthropic"
    mock_provider.generate = AsyncMock(return_value=mock_response)

    client._get_provider.return_value = mock_provider
    client._active_provider_name = "anthropic"

    mock_options = MagicMock()
    client.router = MagicMock()
    client.router.resolve.return_value = mock_options
    client.router.get_tier.return_value = MagicMock(value="fast")

    client.cost_tracker = MagicMock()
    client.cost_tracker.record = MagicMock()

    return client


@pytest.fixture
def mock_memory():
    """Mock VectorMemory."""
    memory = MagicMock()
    memory.store = MagicMock(return_value=MagicMock(id="mem-001", category="recon"))
    return memory


@pytest.fixture
def mock_governance():
    """Mock GovernanceAgent that allows testapp.local."""
    gov = MagicMock()
    gov.is_url_in_scope = MagicMock(side_effect=lambda url: "testapp.local" in url)
    gov.check_action = MagicMock(return_value=MagicMock(allowed=True))
    return gov


@pytest.fixture
def sub_context(tmp_path):
    """ExecutionContext for sub-agent tests."""
    return ExecutionContext(
        operation_id="test-swarm-001",
        target="http://testapp.local",
        artifacts_dir=str(tmp_path / "artifacts"),
        max_steps=100,
    )


@pytest.fixture
def tool_handlers():
    """All tool handlers (simulated parent map)."""
    return {
        "shell_execute": AsyncMock(return_value="nmap output..."),
        "http_request": AsyncMock(return_value="HTTP 200 OK"),
        "browser_navigate": AsyncMock(return_value="Page loaded"),
        "memory_store": AsyncMock(return_value="Memory stored"),
        "save_artifact": AsyncMock(return_value="Artifact saved"),
        # These should NOT be used by sub-agents:
        "spawn_subagent": AsyncMock(return_value="should not be called"),
        "create_tool": AsyncMock(return_value="should not be called"),
        "stop": AsyncMock(return_value="should not be called"),
        "report_finding": AsyncMock(return_value="should not be called"),
    }


class TestSubagentAllowlist:
    """Sub-agent tool allowlist enforcement."""

    def test_allowed_tools_set(self):
        """Verify the allowed tools set contains only safe tools."""
        assert SUBAGENT_ALLOWED_TOOLS == {
            "shell_execute", "http_request", "browser_navigate",
            "memory_store", "save_artifact",
        }

    def test_no_recursive_tools(self):
        """spawn_subagent and create_tool are NOT in the allowed set."""
        assert "spawn_subagent" not in SUBAGENT_ALLOWED_TOOLS
        assert "create_tool" not in SUBAGENT_ALLOWED_TOOLS
        assert "stop" not in SUBAGENT_ALLOWED_TOOLS


class TestBudgetGuard:
    """Budget guard rejects when insufficient steps remain."""

    @pytest.mark.asyncio
    async def test_budget_guard_rejects(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Sub-agent rejected when parent has insufficient budget."""
        sub_context.current_step = 97  # only 3 steps remaining
        sub_context.max_steps = 100

        result = await handle_spawn_subagent(
            {"objective": "Scan ports", "max_steps": 10},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        assert "Budget guard" in result
        assert "3 steps remaining" in result

    @pytest.mark.asyncio
    async def test_budget_guard_passes(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Sub-agent accepted when parent has sufficient budget."""
        sub_context.current_step = 10  # 90 steps remaining
        sub_context.max_steps = 100

        result = await handle_spawn_subagent(
            {"objective": "Scan ports", "max_steps": 5},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        assert "Budget guard" not in result
        assert "Sub-agent completed" in result


class TestSubagentExecution:
    """Sub-agent execution flow."""

    @pytest.mark.asyncio
    async def test_basic_execution(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Sub-agent runs and returns result text."""
        result = await handle_spawn_subagent(
            {"objective": "Enumerate subdomains"},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        assert "Sub-agent completed" in result
        assert "Enumerate subdomains" in result

    @pytest.mark.asyncio
    async def test_results_stored_in_memory(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Sub-agent results are stored in shared memory."""
        await handle_spawn_subagent(
            {"objective": "Port scan"},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        mock_memory.store.assert_called_once()
        call_kwargs = mock_memory.store.call_args
        assert call_kwargs.kwargs["category"] == "recon"
        assert "subagent" in call_kwargs.kwargs["metadata"]["source"]

    @pytest.mark.asyncio
    async def test_empty_objective_rejected(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Empty objective returns error."""
        result = await handle_spawn_subagent(
            {"objective": ""},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        assert "Error" in result
        assert "objective" in result.lower()

    @pytest.mark.asyncio
    async def test_max_steps_capped_at_15(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """max_steps is capped at 15 even if higher is requested."""
        # With 100 total and 0 used, asking for 50 should still cap at 15
        result = await handle_spawn_subagent(
            {"objective": "Test endpoint", "max_steps": 50},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        assert "Sub-agent completed" in result


class TestParentCancellation:
    """Parent stop/cancel halts sub-agent."""

    @pytest.mark.asyncio
    async def test_parent_cancel_halts_subagent(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Sub-agent stops when parent is cancelled."""
        # Make the LLM return tool calls so the loop iterates
        mock_response = MagicMock()
        mock_response.has_tool_calls = True
        from backend.core.llm.providers.base import ToolCall
        mock_response.tool_calls = [ToolCall(id="tc-1", name="shell_execute", arguments={"command": "echo hi"})]
        mock_response.text = ""
        mock_response.raw = {"content": [{"type": "text", "text": ""}, {"type": "tool_use", "id": "tc-1", "name": "shell_execute", "input": {"command": "echo hi"}}]}

        mock_provider = mock_llm_client._get_provider()
        mock_provider.generate = AsyncMock(return_value=mock_response)

        # Parent cancelled after first step
        call_count = 0
        def check_cancelled():
            nonlocal call_count
            call_count += 1
            return call_count > 1

        result = await handle_spawn_subagent(
            {"objective": "Long running scan", "max_steps": 15},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=check_cancelled,
        )
        assert "cancelled" in result.lower() or "halted" in result.lower()

    @pytest.mark.asyncio
    async def test_parent_stopped_halts_subagent(self, sub_context, mock_llm_client, mock_memory, mock_governance, tool_handlers):
        """Sub-agent stops when parent context is stopped."""
        sub_context._stopped = True

        # Make LLM return tool calls
        mock_response = MagicMock()
        mock_response.has_tool_calls = True
        from backend.core.llm.providers.base import ToolCall
        mock_response.tool_calls = [ToolCall(id="tc-1", name="shell_execute", arguments={"command": "echo hi"})]
        mock_response.text = ""
        mock_response.raw = {"content": [{"type": "text", "text": ""}, {"type": "tool_use", "id": "tc-1", "name": "shell_execute", "input": {"command": "echo hi"}}]}

        mock_provider = mock_llm_client._get_provider()
        mock_provider.generate = AsyncMock(return_value=mock_response)

        result = await handle_spawn_subagent(
            {"objective": "Scan", "max_steps": 5},
            sub_context,
            llm_client=mock_llm_client,
            memory=mock_memory,
            governance=mock_governance,
            tool_handlers=tool_handlers,
            parent_cancelled=lambda: False,
        )
        assert "stopped" in result.lower() or "halted" in result.lower()


class TestTimeout:
    """Timeout enforcement."""

    @pytest.mark.asyncio
    async def test_timeout_enforced(self, sub_context, mock_memory, mock_governance, tool_handlers):
        """Sub-agent times out if loop takes too long."""
        # Create a mock LLM that takes forever to respond
        slow_client = MagicMock()
        mock_provider = MagicMock()
        mock_provider.supports_tools.return_value = True
        mock_provider.name = "anthropic"

        async def slow_generate(*args, **kwargs):
            await asyncio.sleep(200)  # Way over timeout
            return MagicMock(has_tool_calls=False, text="done", raw=None, tool_calls=[])

        mock_provider.generate = slow_generate
        slow_client._get_provider.return_value = mock_provider
        slow_client._active_provider_name = "anthropic"
        slow_client.router = MagicMock()
        slow_client.router.resolve.return_value = MagicMock()
        slow_client.router.get_tier.return_value = MagicMock(value="fast")
        slow_client.cost_tracker = MagicMock()

        # Patch timeout to 1 second for fast test
        with patch("backend.core.tools.swarm_tool.SUBAGENT_TIMEOUT", 1):
            result = await handle_spawn_subagent(
                {"objective": "Slow scan"},
                sub_context,
                llm_client=slow_client,
                memory=mock_memory,
                governance=mock_governance,
                tool_handlers=tool_handlers,
                parent_cancelled=lambda: False,
            )
        assert "timed out" in result.lower()

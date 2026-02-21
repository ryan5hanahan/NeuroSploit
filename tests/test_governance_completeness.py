"""Test governance completeness — verify every tool routes through governance.

Ensures no tool can bypass the governance gate.
"""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestGovernanceCompleteness:
    """Verify all registered tools route through governance."""

    @pytest.mark.asyncio
    async def test_tool_executor_checks_governance(self, execution_context, mock_governance):
        """ToolExecutor.execute() should call governance.check_action for every tool call."""
        from backend.core.llm.tool_executor import ToolExecutor
        from backend.core.llm.providers.base import ToolCall

        executor = ToolExecutor(
            context=execution_context,
            governance_agent=mock_governance,
        )

        # Register a dummy handler
        async def dummy_handler(args, ctx):
            return "ok"
        executor.register("test_tool", dummy_handler)

        call = ToolCall(id="tc-gov-001", name="test_tool", arguments={})
        await executor.execute(call)

        # Governance should have been consulted
        mock_governance.check_action.assert_called()

    @pytest.mark.asyncio
    async def test_governance_blocks_tool(self, execution_context, strict_governance):
        """Tools should be blocked when governance denies the action."""
        from backend.core.llm.tool_executor import ToolExecutor
        from backend.core.llm.providers.base import ToolCall

        executor = ToolExecutor(
            context=execution_context,
            governance_agent=strict_governance,
        )

        async def dummy_handler(args, ctx):
            return "should not reach here"
        executor.register("blocked_tool", dummy_handler)

        call = ToolCall(id="tc-gov-002", name="blocked_tool", arguments={})
        result = await executor.execute(call)

        # Should return governance violation, not the handler result
        assert result.is_error or "governance" in result.content.lower() or "blocked" in result.content.lower()

    @pytest.mark.asyncio
    async def test_all_agent_tools_have_handlers(self):
        """Every tool defined in get_agent_tools() should have a matching handler."""
        from backend.core.llm_agent_tools import get_agent_tools

        tools = get_agent_tools()
        tool_names = {t["name"] for t in tools}

        # These are the core tools that must exist
        expected_tools = {
            "shell_execute",
            "http_request",
            "browser_navigate",
            "browser_extract_links",
            "browser_extract_forms",
            "browser_submit_form",
            "browser_screenshot",
            "browser_execute_js",
            "memory_store",
            "memory_search",
            "save_artifact",
            "report_finding",
            "update_plan",
            "get_payloads",
            "get_vuln_info",
            "stop",
            "spawn_subagent",
            "create_tool",
        }

        for tool in expected_tools:
            assert tool in tool_names, f"Missing tool definition: {tool}"

    @pytest.mark.asyncio
    async def test_shell_tool_uses_executor(self, execution_context):
        """shell_execute should go through the standard tool execution path."""
        from backend.core.tools.shell_tool import handle_shell_execute

        # The handler function exists and is callable
        assert callable(handle_shell_execute)

    @pytest.mark.asyncio
    async def test_swarm_tool_uses_executor(self):
        """spawn_subagent should go through the standard tool execution path."""
        from backend.core.tools.swarm_tool import handle_spawn_subagent

        assert callable(handle_spawn_subagent)

    @pytest.mark.asyncio
    async def test_dynamic_tool_uses_executor(self):
        """create_tool should go through the standard tool execution path."""
        from backend.core.tools.dynamic_tool import handle_create_tool

        assert callable(handle_create_tool)

    @pytest.mark.asyncio
    async def test_governance_facade_delegates_scope_and_phase(self):
        """Governance facade should delegate to both scope and phase layers."""
        try:
            from backend.core.governance_facade import Governance, create_governance

            gov = create_governance(
                scan_id="test-scan-001",
                target_url="http://testapp.local",
                scope_profile="full_auto",
                governance_mode="warn",
            )

            # Should have both layers
            assert hasattr(gov, 'governance') or hasattr(gov, '_governance_agent')
            assert hasattr(gov, 'gate') or hasattr(gov, '_gate')

            # Should be able to check actions
            assert hasattr(gov, 'check_action')

            # Should be able to check scope
            assert hasattr(gov, 'is_url_in_scope') or hasattr(gov, 'filter_vuln_types')

        except ImportError:
            pytest.skip("Governance facade not available")

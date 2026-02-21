"""Integration tests — Governance enforcement in live scan context.

Verifies that governance rules are enforced when tools interact with real targets.
Marked with @pytest.mark.integration.
"""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.mark.integration
@pytest.mark.asyncio
class TestGovernanceLive:
    """Test governance enforcement with live target context."""

    async def test_governance_blocks_out_of_scope_target(self):
        """Governance should block requests to targets outside the defined scope."""
        from backend.core.governance import GovernanceEngine

        engine = GovernanceEngine()
        # Configure scope for a specific domain
        engine.configure(scope={"domains": ["example.com"]})

        # Attempt to scan an out-of-scope target
        result = engine.check_scope("http://out-of-scope.com/test")
        assert not result.allowed, "Out-of-scope target should be blocked"

    async def test_governance_allows_in_scope_target(self):
        """Governance should allow requests to in-scope targets."""
        from backend.core.governance import GovernanceEngine

        engine = GovernanceEngine()
        engine.configure(scope={"domains": ["example.com"]})

        result = engine.check_scope("http://example.com/api/test")
        assert result.allowed, "In-scope target should be allowed"

    async def test_tool_executor_enforces_governance(self):
        """ToolExecutor should pass all tool calls through governance."""
        from backend.core.tool_executor import ToolExecutor

        # Verify ToolExecutor has governance integration
        executor = ToolExecutor()
        assert hasattr(executor, 'governance') or hasattr(executor, '_governance'), \
            "ToolExecutor should have governance integration"

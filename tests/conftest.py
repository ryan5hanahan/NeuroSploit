"""
sploit.ai - Test Fixtures for Agent Tool Verification

Shared pytest fixtures used across the LLM agent tool test suite.
Provides pre-configured ExecutionContext instances, mock governance
agents, and temporary directory scaffolding.
"""

import os
import sys
import pytest
import time
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure the project root is on sys.path so `backend.*` imports resolve
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Temporary artifact directory
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_artifacts(tmp_path):
    """Temporary directory for artifact tests."""
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    return artifacts_dir


# ---------------------------------------------------------------------------
# ExecutionContext fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def execution_context(tmp_artifacts):
    """Standard ExecutionContext for testing (no auth)."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-001",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        max_duration_seconds=3600,
    )
    return ctx


@pytest.fixture
def execution_context_with_bearer(tmp_artifacts):
    """ExecutionContext with bearer token auth configured."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-bearer",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        auth_type="bearer",
        auth_credentials={"token": "test-token-123"},
    )
    return ctx


@pytest.fixture
def execution_context_with_cookie(tmp_artifacts):
    """ExecutionContext with cookie auth configured."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-cookie",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        auth_type="cookie",
        auth_credentials={"cookie": "session=abc123; token=xyz789"},
    )
    return ctx


@pytest.fixture
def execution_context_with_basic(tmp_artifacts):
    """ExecutionContext with basic auth configured."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-basic",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        auth_type="basic",
        auth_credentials={"username": "admin", "password": "secret"},
    )
    return ctx


@pytest.fixture
def execution_context_with_header(tmp_artifacts):
    """ExecutionContext with custom header auth configured."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-header",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        auth_type="header",
        auth_credentials={"header_name": "X-API-Key", "header_value": "my-api-key-123"},
    )
    return ctx


@pytest.fixture
def execution_context_with_login(tmp_artifacts):
    """ExecutionContext with login-type (form-based) auth configured."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-login",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        auth_type="login",
        auth_credentials={"username": "formuser", "password": "formpass"},
    )
    return ctx


@pytest.fixture
def execution_context_with_credential_sets(tmp_artifacts):
    """ExecutionContext with multiple credential sets for differential testing."""
    from backend.core.llm.tool_executor import ExecutionContext

    ctx = ExecutionContext(
        operation_id="test-op-creds",
        target="http://testapp.local",
        artifacts_dir=str(tmp_artifacts),
        max_steps=100,
        credential_sets=[
            {
                "label": "admin",
                "role": "administrator",
                "auth_type": "bearer",
                "token": "admin-token-aaa",
            },
            {
                "label": "user",
                "role": "regular_user",
                "auth_type": "cookie",
                "cookie": "session=user123",
            },
            {
                "label": "attacker",
                "role": "unauthenticated",
                "auth_type": "basic",
                "username": "attacker",
                "password": "pass123",
            },
            {
                "label": "login_user",
                "role": "form_login",
                "auth_type": "login",
                "username": "loginuser",
                "password": "loginpass",
            },
        ],
    )
    return ctx


# ---------------------------------------------------------------------------
# ToolExecutor fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def tool_executor(execution_context):
    """A ToolExecutor instance with no governance and no callbacks."""
    from backend.core.llm.tool_executor import ToolExecutor

    executor = ToolExecutor(
        context=execution_context,
        governance_agent=None,
        on_step=None,
        cost_tracker=None,
    )
    return executor


# ---------------------------------------------------------------------------
# Mock governance agent
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_governance():
    """A mock governance agent that allows in-scope URLs and blocks out-of-scope."""
    gov = MagicMock()
    gov.is_url_in_scope = MagicMock(side_effect=lambda url: "testapp.local" in url)
    gov.check_action = MagicMock(return_value=MagicMock(allowed=True))
    return gov


@pytest.fixture
def strict_governance():
    """A mock governance agent that blocks everything."""
    gov = MagicMock()
    gov.is_url_in_scope = MagicMock(return_value=False)
    gov.check_action = MagicMock(return_value=MagicMock(allowed=False, reason="Blocked by strict governance"))
    return gov


# ---------------------------------------------------------------------------
# Mock cost tracker
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_cost_tracker():
    """A mock cost tracker for budget enforcement tests."""
    tracker = MagicMock()
    tracker.over_budget = False
    tracker.total_cost = 0.50
    tracker.budget_usd = 10.0
    return tracker


@pytest.fixture
def over_budget_cost_tracker():
    """A mock cost tracker that reports over budget."""
    tracker = MagicMock()
    tracker.over_budget = True
    tracker.total_cost = 10.50
    tracker.budget_usd = 10.0
    return tracker


# ---------------------------------------------------------------------------
# Helper: create ToolCall
# ---------------------------------------------------------------------------

@pytest.fixture
def make_tool_call():
    """Factory fixture that creates ToolCall instances."""
    from backend.core.llm.providers.base import ToolCall

    def _make(name: str, arguments: dict, call_id: str = "tc-001"):
        return ToolCall(id=call_id, name=name, arguments=arguments)

    return _make

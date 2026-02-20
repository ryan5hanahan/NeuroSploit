"""
Tests for the dynamic tool creation system (create_tool).

Covers:
  - Allowed imports pass, blocked imports/builtins rejected
  - Syntax errors caught
  - Tool created and registered on executor
  - Schema appended to tools list
  - Artifact saved to disk
  - Invalid/duplicate name rejected
  - Missing/sync handler rejected
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.core.tools.dynamic_tool import (
    ALLOWED_IMPORTS,
    BLOCKED_BUILTINS,
    BLOCKED_IMPORTS,
    RESERVED_NAMES,
    CodeValidationError,
    handle_create_tool,
    validate_code,
)
from backend.core.llm.tool_executor import ExecutionContext, ToolExecutor


@pytest.fixture
def mock_executor(tmp_path):
    """ToolExecutor for registration tests."""
    ctx = ExecutionContext(
        operation_id="test-dyn-001",
        target="http://testapp.local",
        artifacts_dir=str(tmp_path / "artifacts"),
        max_steps=100,
    )
    executor = ToolExecutor(context=ctx)
    return executor


@pytest.fixture
def execution_context(tmp_path):
    """ExecutionContext for handler tests."""
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    return ExecutionContext(
        operation_id="test-dyn-002",
        target="http://testapp.local",
        artifacts_dir=str(artifacts_dir),
        max_steps=100,
    )


@pytest.fixture
def tools_list():
    """Mutable tools list for schema appending."""
    return []


# ============================================================================
# Code Validation (AST)
# ============================================================================


class TestCodeValidation:
    """AST validation of dynamic tool code."""

    def test_allowed_import_json(self):
        """import json passes validation."""
        validate_code("import json")

    def test_allowed_import_re(self):
        """import re passes validation."""
        validate_code("import re")

    def test_allowed_import_base64(self):
        """import base64 passes validation."""
        validate_code("import base64")

    def test_allowed_import_from(self):
        """from hashlib import sha256 passes validation."""
        validate_code("from hashlib import sha256")

    def test_blocked_import_os(self):
        """import os is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import os")

    def test_blocked_import_subprocess(self):
        """import subprocess is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import subprocess")

    def test_blocked_import_sys(self):
        """import sys is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import sys")

    def test_blocked_import_shutil(self):
        """import shutil is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import shutil")

    def test_blocked_import_socket(self):
        """import socket is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import socket")

    def test_blocked_import_pathlib(self):
        """import pathlib is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import pathlib")

    def test_blocked_import_ctypes(self):
        """import ctypes is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import ctypes")

    def test_blocked_import_importlib(self):
        """import importlib is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("import importlib")

    def test_blocked_from_import(self):
        """from os import path is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked import"):
            validate_code("from os import path")

    def test_unlisted_import_rejected(self):
        """import requests is rejected (not in allowed list)."""
        with pytest.raises(CodeValidationError, match="not in the allowed list"):
            validate_code("import requests")

    def test_blocked_builtin_eval(self):
        """eval() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("result = eval('1+1')")

    def test_blocked_builtin_exec(self):
        """exec() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("exec('print(1)')")

    def test_blocked_builtin_open(self):
        """open() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("f = open('/etc/passwd')")

    def test_blocked_builtin_dunder_import(self):
        """__import__() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("__import__('os')")

    def test_blocked_builtin_compile(self):
        """compile() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("compile('1+1', '<string>', 'eval')")

    def test_blocked_builtin_globals(self):
        """globals() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("g = globals()")

    def test_blocked_builtin_getattr(self):
        """getattr() call is rejected."""
        with pytest.raises(CodeValidationError, match="Blocked builtin"):
            validate_code("x = getattr(obj, 'attr')")

    def test_syntax_error_caught(self):
        """Syntax error in code is caught."""
        with pytest.raises(CodeValidationError, match="Syntax error"):
            validate_code("def broken(:\n  pass")

    def test_valid_handler_code(self):
        """Valid async handler code passes validation."""
        code = """
import json
import re

async def handler(args: dict, context) -> str:
    data = args.get("input", "")
    result = json.dumps({"processed": data})
    return result
"""
        validate_code(code)

    def test_all_allowed_imports(self):
        """All imports in ALLOWED_IMPORTS pass validation."""
        for module in ALLOWED_IMPORTS:
            validate_code(f"import {module}")

    def test_all_blocked_imports(self):
        """All imports in BLOCKED_IMPORTS fail validation."""
        for module in BLOCKED_IMPORTS:
            with pytest.raises(CodeValidationError):
                validate_code(f"import {module}")


# ============================================================================
# Tool Creation (handle_create_tool)
# ============================================================================


class TestCreateTool:
    """Tool creation and registration."""

    @pytest.mark.asyncio
    async def test_create_valid_tool(self, mock_executor, execution_context, tools_list):
        """Valid tool is created and registered."""
        code = """
import json

async def handler(args: dict, context) -> str:
    data = args.get("input", "")
    return json.dumps({"decoded": data})
"""
        result = await handle_create_tool(
            {
                "tool_name": "my_decoder",
                "description": "Decode custom format",
                "code": code,
            },
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "created and registered" in result
        assert "my_decoder" in result

    @pytest.mark.asyncio
    async def test_handler_registered_on_executor(self, mock_executor, execution_context, tools_list):
        """Handler is registered on the ToolExecutor."""
        code = """
async def handler(args: dict, context) -> str:
    return "hello"
"""
        await handle_create_tool(
            {"tool_name": "test_reg", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "test_reg" in mock_executor._handlers

    @pytest.mark.asyncio
    async def test_schema_appended_to_tools_list(self, mock_executor, execution_context, tools_list):
        """MCP schema is appended to the tools list."""
        code = """
async def handler(args: dict, context) -> str:
    return "ok"
"""
        await handle_create_tool(
            {
                "tool_name": "my_tool",
                "description": "My tool",
                "code": code,
                "parameters": {"input": {"type": "string"}},
            },
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert len(tools_list) == 1
        schema = tools_list[0]
        assert schema["name"] == "my_tool"
        assert "[Dynamic]" in schema["description"]
        assert "input" in schema["inputSchema"]["properties"]

    @pytest.mark.asyncio
    async def test_artifact_saved_to_disk(self, mock_executor, execution_context, tools_list):
        """Tool code is saved as artifact."""
        code = """
async def handler(args: dict, context) -> str:
    return "saved"
"""
        await handle_create_tool(
            {"tool_name": "saved_tool", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        artifact_path = os.path.join(
            execution_context.artifacts_dir, "dynamic_tool_saved_tool.py"
        )
        assert os.path.exists(artifact_path)
        with open(artifact_path) as f:
            content = f.read()
        assert "async def handler" in content

    @pytest.mark.asyncio
    async def test_registered_handler_is_callable(self, mock_executor, execution_context, tools_list):
        """Registered handler can be called and returns expected result."""
        code = """
async def handler(args: dict, context) -> str:
    return f"processed: {args.get('value', 'none')}"
"""
        await handle_create_tool(
            {"tool_name": "callable_tool", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        handler = mock_executor._handlers["callable_tool"]
        result = await handler({"value": "test123"}, execution_context)
        assert result == "processed: test123"


# ============================================================================
# Validation Failures
# ============================================================================


class TestCreateToolValidation:
    """Validation failures in tool creation."""

    @pytest.mark.asyncio
    async def test_empty_tool_name(self, mock_executor, execution_context, tools_list):
        """Empty tool name rejected."""
        result = await handle_create_tool(
            {"tool_name": "", "description": "Test", "code": "pass"},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "tool_name" in result

    @pytest.mark.asyncio
    async def test_invalid_identifier(self, mock_executor, execution_context, tools_list):
        """Non-identifier tool name rejected."""
        result = await handle_create_tool(
            {"tool_name": "my-tool", "description": "Test", "code": "pass"},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "identifier" in result

    @pytest.mark.asyncio
    async def test_reserved_name_rejected(self, mock_executor, execution_context, tools_list):
        """Reserved tool name (e.g., shell_execute) rejected."""
        code = 'async def handler(args, context): return "ok"'
        result = await handle_create_tool(
            {"tool_name": "shell_execute", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "reserved" in result.lower()

    @pytest.mark.asyncio
    async def test_duplicate_name_rejected(self, mock_executor, execution_context, tools_list):
        """Duplicate dynamic tool name rejected."""
        code = 'async def handler(args, context): return "ok"'
        await handle_create_tool(
            {"tool_name": "unique_tool", "description": "First", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        result = await handle_create_tool(
            {"tool_name": "unique_tool", "description": "Second", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "already exists" in result

    @pytest.mark.asyncio
    async def test_blocked_import_rejected(self, mock_executor, execution_context, tools_list):
        """Code with blocked import is rejected."""
        code = """
import os
async def handler(args, context):
    return os.getcwd()
"""
        result = await handle_create_tool(
            {"tool_name": "bad_import", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "validation failed" in result.lower()
        assert "Blocked import" in result

    @pytest.mark.asyncio
    async def test_syntax_error_rejected(self, mock_executor, execution_context, tools_list):
        """Code with syntax error is rejected."""
        result = await handle_create_tool(
            {"tool_name": "bad_syntax", "description": "Test", "code": "def broken(:"},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "validation failed" in result.lower()
        assert "Syntax error" in result

    @pytest.mark.asyncio
    async def test_missing_handler_rejected(self, mock_executor, execution_context, tools_list):
        """Code without handler function is rejected."""
        code = """
def not_handler(args, context):
    return "wrong name"
"""
        result = await handle_create_tool(
            {"tool_name": "no_handler", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "handler" in result.lower()

    @pytest.mark.asyncio
    async def test_sync_handler_rejected(self, mock_executor, execution_context, tools_list):
        """Synchronous handler (not async def) is rejected."""
        code = """
def handler(args, context):
    return "sync"
"""
        result = await handle_create_tool(
            {"tool_name": "sync_tool", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "async" in result.lower()

    @pytest.mark.asyncio
    async def test_empty_code_rejected(self, mock_executor, execution_context, tools_list):
        """Empty code string rejected."""
        result = await handle_create_tool(
            {"tool_name": "empty_code", "description": "Test", "code": ""},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "code" in result.lower()

    @pytest.mark.asyncio
    async def test_empty_description_rejected(self, mock_executor, execution_context, tools_list):
        """Empty description rejected."""
        code = 'async def handler(args, context): return "ok"'
        result = await handle_create_tool(
            {"tool_name": "no_desc", "description": "", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "Error" in result
        assert "description" in result.lower()

    @pytest.mark.asyncio
    async def test_runtime_error_caught(self, mock_executor, execution_context, tools_list):
        """Code that raises at exec time is caught."""
        code = """
raise ValueError("boom")
async def handler(args, context):
    return "ok"
"""
        result = await handle_create_tool(
            {"tool_name": "runtime_err", "description": "Test", "code": code},
            execution_context,
            executor=mock_executor,
            tools_list=tools_list,
        )
        assert "execution failed" in result.lower()


# ============================================================================
# Reserved Names
# ============================================================================


class TestReservedNames:
    """All built-in tool names are reserved."""

    def test_all_18_tools_reserved(self):
        """All 18 built-in tool names are in RESERVED_NAMES."""
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
        assert expected == RESERVED_NAMES

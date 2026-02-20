"""Dynamic tool creation — agent writes Python at runtime, validated and registered.

The agent can define new tools by providing Python code that defines an
`async def handler(args: dict, context) -> str` function. The code is
AST-validated (blocked imports/builtins), exec'd in an isolated namespace,
and the handler is registered on the ToolExecutor.

Security: Only a narrow set of imports and builtins are allowed.
"""

import ast
import inspect
import logging
import os
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Allowed imports (safe standard library modules)
ALLOWED_IMPORTS = frozenset({
    "json", "re", "base64", "urllib", "hashlib", "html",
    "math", "collections", "itertools", "string", "binascii", "hmac",
})

# Blocked imports (system access, code execution, file I/O)
BLOCKED_IMPORTS = frozenset({
    "os", "subprocess", "sys", "shutil", "pathlib", "socket",
    "importlib", "ctypes",
})

# Blocked builtins
BLOCKED_BUILTINS = frozenset({
    "__import__", "eval", "exec", "compile", "open",
    "globals", "getattr",
})

# Reserved tool names (cannot be overridden)
RESERVED_NAMES = frozenset({
    "shell_execute", "http_request", "browser_navigate",
    "browser_extract_links", "browser_extract_forms",
    "browser_submit_form", "browser_screenshot", "browser_execute_js",
    "memory_store", "memory_search", "save_artifact", "report_finding",
    "update_plan", "get_payloads", "get_vuln_info", "stop",
    "spawn_subagent", "create_tool",
})


class CodeValidationError(Exception):
    """Raised when dynamic tool code fails validation."""
    pass


def validate_code(code: str) -> None:
    """AST-validate Python code for safety.

    Checks:
    - No blocked imports
    - No blocked builtins
    - Only allowed imports
    - Syntactically valid

    Raises:
        CodeValidationError: If code fails validation.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise CodeValidationError(f"Syntax error: {e}")

    for node in ast.walk(tree):
        # Check import statements
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]
                if module in BLOCKED_IMPORTS:
                    raise CodeValidationError(
                        f"Blocked import: '{module}' is not allowed"
                    )
                if module not in ALLOWED_IMPORTS:
                    raise CodeValidationError(
                        f"Import '{module}' is not in the allowed list: "
                        f"{sorted(ALLOWED_IMPORTS)}"
                    )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module = node.module.split(".")[0]
                if module in BLOCKED_IMPORTS:
                    raise CodeValidationError(
                        f"Blocked import: '{module}' is not allowed"
                    )
                if module not in ALLOWED_IMPORTS:
                    raise CodeValidationError(
                        f"Import '{module}' is not in the allowed list: "
                        f"{sorted(ALLOWED_IMPORTS)}"
                    )

        # Check for blocked builtins used as function calls
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in BLOCKED_BUILTINS:
                raise CodeValidationError(
                    f"Blocked builtin: '{func.id}' is not allowed"
                )
            elif isinstance(func, ast.Attribute) and func.attr in BLOCKED_BUILTINS:
                raise CodeValidationError(
                    f"Blocked builtin: '{func.attr}' is not allowed"
                )

        # Check for blocked builtins in Name nodes (e.g., assigned to variable)
        elif isinstance(node, ast.Name) and node.id in BLOCKED_BUILTINS:
            # Only block if used in a call context (already handled above)
            # or as a direct reference in dangerous patterns
            pass


async def handle_create_tool(
    args: Dict[str, Any],
    context: Any,
    *,
    executor: Any,
    tools_list: List[Dict[str, Any]],
) -> str:
    """Create and register a dynamic tool from agent-provided Python code.

    Args:
        args: {
            "tool_name": str (required),
            "description": str (required),
            "code": str (required — must define `async def handler(args, context) -> str`),
            "parameters": dict (optional — JSON Schema for inputSchema.properties),
        }
        context: ExecutionContext
        executor: ToolExecutor to register the new handler on
        tools_list: Mutable list to append the new MCP schema to

    Returns:
        Success/failure message.
    """
    tool_name = args.get("tool_name", "").strip()
    description = args.get("description", "").strip()
    code = args.get("code", "").strip()
    parameters = args.get("parameters", {})

    # Validate tool name
    if not tool_name:
        return "Error: tool_name is required"
    if not tool_name.isidentifier():
        return f"Error: tool_name '{tool_name}' is not a valid Python identifier"
    if tool_name in RESERVED_NAMES:
        return f"Error: tool_name '{tool_name}' is reserved and cannot be overridden"

    # Check for duplicate dynamic tools
    existing_names = {t["name"] for t in tools_list}
    if tool_name in existing_names:
        return f"Error: dynamic tool '{tool_name}' already exists"

    if not description:
        return "Error: description is required"
    if not code:
        return "Error: code is required"

    # AST validation
    try:
        validate_code(code)
    except CodeValidationError as e:
        return f"Code validation failed: {e}"

    # Execute in isolated namespace
    namespace: Dict[str, Any] = {}
    try:
        exec(code, namespace)  # noqa: S102 — intentional, AST-validated
    except Exception as e:
        return f"Code execution failed: {type(e).__name__}: {e}"

    # Extract handler
    handler_fn = namespace.get("handler")
    if handler_fn is None:
        return "Error: code must define a function named 'handler'"
    if not callable(handler_fn):
        return "Error: 'handler' must be a callable"
    if not inspect.iscoroutinefunction(handler_fn):
        return "Error: 'handler' must be an async function (async def handler(args, context) -> str)"

    # Register handler on executor
    executor.register(tool_name, handler_fn)

    # Build MCP schema
    schema: Dict[str, Any] = {
        "name": tool_name,
        "description": f"[Dynamic] {description}",
        "inputSchema": {
            "type": "object",
            "properties": parameters if isinstance(parameters, dict) else {},
        },
    }
    tools_list.append(schema)

    # Save code as artifact
    try:
        artifacts_dir = context.artifacts_dir
        os.makedirs(artifacts_dir, exist_ok=True)
        artifact_path = os.path.join(artifacts_dir, f"dynamic_tool_{tool_name}.py")
        with open(artifact_path, "w") as f:
            f.write(code)
        logger.info(f"[DynamicTool] Saved code to {artifact_path}")
    except Exception as e:
        logger.warning(f"[DynamicTool] Failed to save artifact: {e}")

    return (
        f"Dynamic tool '{tool_name}' created and registered. "
        f"It is now available for use in subsequent tool calls."
    )

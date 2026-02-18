"""Shell execution tool for the LLM-driven agent.

Wraps Docker container execution to provide shell access with
timeout enforcement, output capture, and security constraints.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Maximum output size to prevent context overflow
MAX_OUTPUT_BYTES = 30 * 1024  # 30KB
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600


async def handle_shell_execute(args: Dict[str, Any], context: Any) -> str:
    """Execute a shell command inside the Docker sandbox.

    Reuses the existing KaliSandbox/SandboxManager infrastructure
    for container execution.

    Args:
        args: {"command": str, "timeout": int}
        context: ExecutionContext with operation metadata.

    Returns:
        Command output (stdout + stderr) as string.
    """
    command = args.get("command", "").strip()
    timeout = min(args.get("timeout", DEFAULT_TIMEOUT), MAX_TIMEOUT)

    if not command:
        return "Error: empty command"

    # Log the command
    logger.info(f"[Shell] Executing: {command} (timeout={timeout}s)")

    try:
        # Try per-operation sandbox first, fall back to shared sandbox
        result = await _execute_in_sandbox(command, timeout, context)
        return result
    except Exception as e:
        logger.error(f"[Shell] Execution failed: {e}")
        return f"Shell execution error: {type(e).__name__}: {str(e)}"


async def _execute_in_sandbox(command: str, timeout: int, context: Any) -> str:
    """Execute command in Docker sandbox."""
    try:
        # Try importing the per-scan KaliSandbox (preferred)
        from core.kali_sandbox import KaliSandbox
        from core.container_pool import ContainerPool

        pool = ContainerPool.get_instance()
        sandbox = await pool.get_or_create(context.operation_id)
        result = await sandbox.execute_raw(command, timeout=timeout)

        output = _format_result(result)
        return output

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"KaliSandbox failed, trying shared sandbox: {e}")

    try:
        # Fall back to shared SandboxManager
        from core.sandbox_manager import get_sandbox

        sandbox = await get_sandbox()
        result = await sandbox.execute_raw(command, timeout=timeout)

        output = _format_result(result)
        return output

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"SandboxManager failed, trying direct Docker: {e}")

    # Last resort: direct Docker exec
    return await _execute_direct_docker(command, timeout)


async def _execute_direct_docker(command: str, timeout: int) -> str:
    """Direct Docker container execution as fallback."""
    try:
        import docker

        client = docker.from_env()

        # Find or create the sandbox container
        container_name = "neurosploit-sandbox"
        try:
            container = client.containers.get(container_name)
            if container.status != "running":
                container.start()
        except docker.errors.NotFound:
            # Create a new sandbox container
            container = client.containers.run(
                "neurosploit-kali:latest",
                command="tail -f /dev/null",
                name=container_name,
                detach=True,
                network="neurosploit-network",
                mem_limit="2g",
                cpu_period=100000,
                cpu_quota=200000,
                labels={"neurosploit.type": "agent-sandbox"},
            )

        # Execute command
        loop = asyncio.get_event_loop()
        exec_result = await loop.run_in_executor(
            None,
            lambda: container.exec_run(
                ["bash", "-c", command],
                demux=True,
                environment={"TERM": "dumb"},
            ),
        )

        exit_code = exec_result.exit_code
        stdout = (exec_result.output[0] or b"").decode("utf-8", errors="replace") if exec_result.output else ""
        stderr = (exec_result.output[1] or b"").decode("utf-8", errors="replace") if exec_result.output else ""

        output = _format_raw_output(exit_code, stdout, stderr)
        return _truncate(output)

    except Exception as e:
        return f"Docker execution failed: {type(e).__name__}: {str(e)}"


def _format_result(result) -> str:
    """Format a SandboxResult into a readable string."""
    parts = []

    if hasattr(result, "exit_code"):
        if result.exit_code != 0:
            parts.append(f"[Exit code: {result.exit_code}]")

    if hasattr(result, "stdout") and result.stdout:
        parts.append(result.stdout)

    if hasattr(result, "stderr") and result.stderr:
        parts.append(f"[STDERR]\n{result.stderr}")

    if hasattr(result, "duration_seconds"):
        parts.append(f"\n[Duration: {result.duration_seconds:.1f}s]")

    output = "\n".join(parts) if parts else "(no output)"
    return _truncate(output)


def _format_raw_output(exit_code: int, stdout: str, stderr: str) -> str:
    """Format raw command output."""
    parts = []

    if exit_code != 0:
        parts.append(f"[Exit code: {exit_code}]")

    if stdout:
        parts.append(stdout)

    if stderr:
        parts.append(f"[STDERR]\n{stderr}")

    return "\n".join(parts) if parts else "(no output)"


def _truncate(text: str) -> str:
    """Truncate output to MAX_OUTPUT_BYTES."""
    if len(text.encode("utf-8")) <= MAX_OUTPUT_BYTES:
        return text

    # Binary-safe truncation
    encoded = text.encode("utf-8")[:MAX_OUTPUT_BYTES]
    truncated = encoded.decode("utf-8", errors="ignore")
    return truncated + "\n\n[OUTPUT TRUNCATED — 30KB limit]"

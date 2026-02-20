"""Shell execution tool for the LLM-driven agent.

Wraps Docker container execution to provide shell access with
timeout enforcement, output capture, and security constraints.

Fallback chain:
  1. Per-operation KaliSandbox via ContainerPool (if kali image exists)
  2. Shared SandboxManager container (if sandbox image exists)
  3. Local subprocess execution — governed by sandbox_fallback_policy:
     "allow" = execute silently (legacy), "warn" = execute + record
     violation, "deny" = block execution entirely.
"""

import asyncio
import logging
import resource
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Maximum output size to prevent context overflow
MAX_OUTPUT_BYTES = 30 * 1024  # 30KB
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600

# Subprocess resource limits
SUBPROCESS_MAX_MEM_MB = 512       # 512MB max memory
SUBPROCESS_MAX_CPU_SECONDS = 300  # 5 min CPU time
SUBPROCESS_MAX_FILE_SIZE_MB = 50  # 50MB max file writes

# Sandbox fallback policy (configurable via governance config)
_sandbox_fallback_policy: str = "warn"  # "allow" | "warn" | "deny"


def set_sandbox_fallback_policy(policy: str):
    """Set the sandbox fallback policy. Called from governance config."""
    global _sandbox_fallback_policy
    if policy in ("allow", "warn", "deny"):
        _sandbox_fallback_policy = policy


async def handle_shell_execute(args: Dict[str, Any], context: Any) -> str:
    """Execute a shell command inside the Docker sandbox.

    Tries per-scan KaliSandbox, shared SandboxManager, and finally
    falls back to local subprocess execution within the backend container.

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

    logger.info(f"[Shell] Executing: {command} (timeout={timeout}s)")

    try:
        result = await _execute_in_sandbox(command, timeout, context)
        return result
    except Exception as e:
        logger.error(f"[Shell] Execution failed: {e}")
        return f"Shell execution error: {type(e).__name__}: {str(e)}"


async def _execute_in_sandbox(command: str, timeout: int, context: Any) -> str:
    """Execute command using available sandbox infrastructure."""

    # --- Attempt 1: Per-operation KaliSandbox via ContainerPool ---
    try:
        from core.container_pool import get_pool

        pool = get_pool()
        sandbox = await pool.get_or_create(context.operation_id)
        result = await sandbox.execute_raw(command, timeout=timeout)
        return _format_result(result)

    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"KaliSandbox unavailable: {e}")

    # --- Attempt 2: Shared SandboxManager container ---
    try:
        from core.sandbox_manager import get_sandbox

        sandbox = await get_sandbox()
        if sandbox and sandbox.is_available:
            result = await sandbox.execute_raw(command, timeout=timeout)
            return _format_result(result)

    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"SandboxManager unavailable: {e}")

    # --- Attempt 3: Local subprocess — governed by fallback policy ---
    policy = _sandbox_fallback_policy

    if policy == "deny":
        logger.warning(
            f"[Shell] Sandbox unavailable and fallback policy is 'deny'. "
            f"Blocking command: {command[:80]}"
        )
        return (
            "Error: No sandbox container available and sandbox_fallback_policy='deny'. "
            "Command execution blocked. Start a sandbox container or change the fallback policy."
        )

    if policy == "warn":
        logger.warning(
            f"[Shell] Falling back to local subprocess (no sandbox). "
            f"Command: {command[:80]}"
        )
        # Record a governance violation if context has a governance reference
        _record_sandbox_fallback_violation(context, command)

    return await _execute_subprocess(command, timeout)


def _record_sandbox_fallback_violation(context: Any, command: str):
    """Record a governance violation for sandbox fallback."""
    try:
        from ..governance_gate import GovernanceViolation
        from datetime import datetime

        violation = GovernanceViolation(
            scan_id=getattr(context, "operation_id", "unknown"),
            phase="unknown",
            action="shell_execute",
            action_category="sandbox_fallback",
            allowed_categories=[],
            context={"command": command[:200], "fallback": "local_subprocess"},
            disposition="warned",
            layer="scope",
            detail="No sandbox available — executing in local subprocess",
        )

        # Try to persist via governance facade if available
        governance = getattr(context, "_governance", None)
        if governance and hasattr(governance, "_on_violation"):
            governance._on_violation(violation)
    except Exception as e:
        logger.debug(f"Failed to record sandbox fallback violation: {e}")


def _set_subprocess_limits():
    """Pre-exec function to set resource limits on child processes."""
    try:
        # Max virtual memory
        mem_bytes = SUBPROCESS_MAX_MEM_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ValueError, resource.error):
        pass  # Not supported on all platforms
    try:
        # Max CPU time
        resource.setrlimit(resource.RLIMIT_CPU, (SUBPROCESS_MAX_CPU_SECONDS, SUBPROCESS_MAX_CPU_SECONDS))
    except (ValueError, resource.error):
        pass
    try:
        # Max file size
        file_bytes = SUBPROCESS_MAX_FILE_SIZE_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    except (ValueError, resource.error):
        pass


async def _execute_subprocess(command: str, timeout: int) -> str:
    """Execute command via local subprocess with resource limits.

    The backend container has nmap, curl, sqlmap, python3, and other
    tools pre-installed, so this works as a reliable fallback when
    dedicated sandbox containers aren't available.
    """
    import os

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "dumb"},
            preexec_fn=_set_subprocess_limits,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"[Exit code: -1]\nCommand timed out after {timeout}s"

        elapsed = time.monotonic() - start
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        exit_code = proc.returncode or 0

        output = _format_raw_output(exit_code, stdout, stderr)
        output += f"\n\n[Duration: {elapsed:.1f}s]"
        return _truncate(output)

    except Exception as e:
        return f"Subprocess execution failed: {type(e).__name__}: {str(e)}"


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

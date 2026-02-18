"""Parallel tool execution for the LLM-driven agent.

Executes multiple independent tool calls concurrently using asyncio.gather().
Used when the LLM returns multiple tool_use blocks in a single response.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Coroutine, Dict, List

from backend.core.llm.providers.base import ToolCall, ToolResult

logger = logging.getLogger(__name__)

# Maximum concurrent tool executions
MAX_PARALLELISM = 8

# Per-tool timeout (seconds)
DEFAULT_TOOL_TIMEOUT = 300


async def execute_parallel(
    tool_calls: List[ToolCall],
    executor: Callable[[ToolCall], Coroutine[Any, Any, ToolResult]],
    max_parallelism: int = MAX_PARALLELISM,
    timeout: float = DEFAULT_TOOL_TIMEOUT,
) -> List[ToolResult]:
    """Execute multiple tool calls in parallel.

    Args:
        tool_calls: List of ToolCall objects to execute.
        executor: The tool executor function (ToolExecutor.execute).
        max_parallelism: Maximum concurrent executions.
        timeout: Per-tool timeout in seconds.

    Returns:
        List of ToolResult objects in the same order as input tool_calls.
    """
    if not tool_calls:
        return []

    # Single tool call — execute directly
    if len(tool_calls) == 1:
        result = await _execute_with_timeout(tool_calls[0], executor, timeout)
        return [result]

    # Multiple tool calls — use semaphore for bounded parallelism
    semaphore = asyncio.Semaphore(max_parallelism)

    async def bounded_execute(tc: ToolCall) -> ToolResult:
        async with semaphore:
            return await _execute_with_timeout(tc, executor, timeout)

    logger.info(f"[Parallel] Executing {len(tool_calls)} tools concurrently (max {max_parallelism})")
    start = time.monotonic()

    results = await asyncio.gather(
        *[bounded_execute(tc) for tc in tool_calls],
        return_exceptions=True,
    )

    elapsed = time.monotonic() - start
    logger.info(f"[Parallel] {len(tool_calls)} tools completed in {elapsed:.1f}s")

    # Convert exceptions to error ToolResults
    final_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            final_results.append(ToolResult(
                tool_call_id=tool_calls[i].id,
                content=f"Parallel execution error: {type(result).__name__}: {str(result)}",
                is_error=True,
            ))
        else:
            final_results.append(result)

    return final_results


async def _execute_with_timeout(
    tool_call: ToolCall,
    executor: Callable,
    timeout: float,
) -> ToolResult:
    """Execute a single tool call with timeout enforcement."""
    try:
        result = await asyncio.wait_for(
            executor(tool_call),
            timeout=timeout,
        )
        return result
    except asyncio.TimeoutError:
        return ToolResult(
            tool_call_id=tool_call.id,
            content=f"Tool '{tool_call.name}' timed out after {timeout}s",
            is_error=True,
        )
    except Exception as e:
        return ToolResult(
            tool_call_id=tool_call.id,
            content=f"Tool '{tool_call.name}' failed: {type(e).__name__}: {str(e)}",
            is_error=True,
        )

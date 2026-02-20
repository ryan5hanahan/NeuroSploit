"""Swarm sub-agent tool — spawns lightweight FAST-tier agent loops.

Each sub-agent gets its own Conversation but shares the parent's
ExecutionContext (step budget), VectorMemory, and GovernanceAgent.
Limited to a safe subset of tools (no recursion, no stop, no create_tool).

Concurrency: max 3 concurrent sub-agents via asyncio.Semaphore.
Timeout: 120s per sub-agent via asyncio.wait_for.
"""

import asyncio
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Max concurrent sub-agents
_semaphore = asyncio.Semaphore(3)

# Sub-agent timeout in seconds
SUBAGENT_TIMEOUT = 120

# Tools available to sub-agents (no recursion, no stop, no create_tool)
SUBAGENT_ALLOWED_TOOLS = {
    "shell_execute",
    "http_request",
    "browser_navigate",
    "memory_store",
    "save_artifact",
}


async def handle_spawn_subagent(
    args: Dict[str, Any],
    context: Any,
    *,
    llm_client: Any,
    memory: Any,
    governance: Any,
    tool_handlers: Dict[str, Callable],
    parent_cancelled: Callable[[], bool],
) -> str:
    """Spawn a lightweight sub-agent for parallel reconnaissance.

    Args:
        args: {"objective": str, "max_steps": int (optional, default 15, max 15)}
        context: Parent ExecutionContext (shared — step increments deduct from parent)
        llm_client: UnifiedLLMClient for LLM calls
        memory: VectorMemory for shared memory
        governance: GovernanceAgent for scope enforcement
        tool_handlers: Dict of tool_name -> handler callable (parent's full map)
        parent_cancelled: Callable that returns True if parent is cancelled

    Returns:
        Sub-agent summary string.
    """
    objective = args.get("objective", "")
    if not objective:
        return "Error: objective is required"

    max_steps = min(args.get("max_steps", 15), 15)

    # Budget guard — parent must have enough steps remaining
    steps_remaining = context.max_steps - context.current_step
    if steps_remaining < max_steps + 2:
        return (
            f"Budget guard: parent has only {steps_remaining} steps remaining, "
            f"need {max_steps + 2} (requested {max_steps} + 2 reserve). "
            f"Reduce max_steps or proceed manually."
        )

    # Filter tool handlers to allowed subset
    sub_handlers = {
        name: handler
        for name, handler in tool_handlers.items()
        if name in SUBAGENT_ALLOWED_TOOLS
    }

    async def _run_subagent() -> str:
        async with _semaphore:
            return await _subagent_loop(
                objective=objective,
                max_steps=max_steps,
                context=context,
                llm_client=llm_client,
                memory=memory,
                governance=governance,
                sub_handlers=sub_handlers,
                parent_cancelled=parent_cancelled,
            )

    try:
        result = await asyncio.wait_for(_run_subagent(), timeout=SUBAGENT_TIMEOUT)
    except asyncio.TimeoutError:
        result = f"Sub-agent timed out after {SUBAGENT_TIMEOUT}s. Partial results may be in memory."
    except Exception as e:
        logger.error(f"[Swarm] Sub-agent error: {e}", exc_info=True)
        result = f"Sub-agent error: {type(e).__name__}: {e}"

    # Store summary in shared memory
    try:
        memory.store(
            content=f"Sub-agent result for '{objective}': {result[:500]}",
            category="recon",
            metadata={"source": "subagent", "objective": objective},
        )
    except Exception as e:
        logger.warning(f"[Swarm] Failed to store sub-agent result in memory: {e}")

    return result


async def _subagent_loop(
    objective: str,
    max_steps: int,
    context: Any,
    llm_client: Any,
    memory: Any,
    governance: Any,
    sub_handlers: Dict[str, Callable],
    parent_cancelled: Callable[[], bool],
) -> str:
    """Inner sub-agent loop — FAST tier, limited tools, shared context."""
    from backend.core.llm.conversation import Conversation
    from backend.core.llm.providers.base import LLMResponse, ModelTier, ToolCall, ToolResult
    from backend.core.llm.tool_adapter import ToolAdapter
    from backend.core.llm_agent_tools import get_agent_tools

    # Build sub-agent tool definitions (filtered)
    all_tools = get_agent_tools()
    sub_tools = [t for t in all_tools if t["name"] in SUBAGENT_ALLOWED_TOOLS]

    # Sub-agent system prompt
    system = (
        f"You are a reconnaissance sub-agent. Your objective:\n{objective}\n\n"
        f"You have {max_steps} steps. Work efficiently — gather information and return.\n"
        f"Target: {context.target}\n\n"
        f"Available tools: {', '.join(SUBAGENT_ALLOWED_TOOLS)}\n"
        f"When done, respond with a text summary of what you found."
    )

    conv = Conversation(max_turns=max_steps * 2)
    conv.add_user(f"Execute this recon objective: {objective}")

    steps_used = 0
    findings_text = []

    while steps_used < max_steps:
        # Check parent cancellation
        if parent_cancelled():
            findings_text.append("[Sub-agent halted: parent cancelled]")
            break

        # Check parent budget
        if context.current_step >= context.max_steps:
            findings_text.append("[Sub-agent halted: parent budget exhausted]")
            break

        # Check if parent stopped
        if context.is_stopped:
            findings_text.append("[Sub-agent halted: parent stopped]")
            break

        # Generate LLM response (FAST tier)
        try:
            provider = llm_client._get_provider()
            options = llm_client.router.resolve("subagent_step", llm_client._active_provider_name)

            if provider.supports_tools():
                native_tools = ToolAdapter.for_provider(provider.name, sub_tools)
                options.tools = native_tools
                options.tool_choice = "auto"

            start = time.monotonic()
            response = await provider.generate(conv.get_messages(), system, options)
            elapsed_ms = (time.monotonic() - start) * 1000

            # Track cost
            tier = llm_client.router.get_tier("subagent_step")
            llm_client.cost_tracker.record(response, "subagent_step", tier, elapsed_ms)

        except Exception as e:
            logger.warning(f"[Swarm] Sub-agent LLM call failed: {e}")
            findings_text.append(f"[LLM error: {e}]")
            break

        conv.add_llm_response(response)

        # No tool calls — sub-agent is done, capture text summary
        if not response.has_tool_calls:
            if response.text:
                findings_text.append(response.text)
            break

        # Execute tool calls
        results: List[ToolResult] = []
        for tc in response.tool_calls:
            handler = sub_handlers.get(tc.name)
            if not handler:
                results.append(ToolResult(
                    tool_call_id=tc.id,
                    content=f"Tool '{tc.name}' not available to sub-agents.",
                    is_error=True,
                ))
                continue

            # Governance check for governed tools
            if governance and tc.name in ("shell_execute", "http_request", "browser_navigate"):
                gov_block = _check_subagent_governance(tc, governance, context)
                if gov_block:
                    results.append(ToolResult(
                        tool_call_id=tc.id,
                        content=f"BLOCKED BY GOVERNANCE: {gov_block}",
                        is_error=True,
                    ))
                    continue

            # Increment parent step counter
            context.current_step += 1
            context.tool_call_counts[tc.name] = (
                context.tool_call_counts.get(tc.name, 0) + 1
            )
            steps_used += 1

            try:
                result_content = await handler(tc.arguments, context)
                # Truncate large outputs
                if result_content and len(result_content) > 3000:
                    result_content = result_content[:1500] + "\n[...truncated...]\n" + result_content[-1500:]
                results.append(ToolResult(
                    tool_call_id=tc.id,
                    content=result_content,
                    is_error=False,
                ))
            except Exception as e:
                results.append(ToolResult(
                    tool_call_id=tc.id,
                    content=f"Tool error: {type(e).__name__}: {e}",
                    is_error=True,
                ))

        # Feed results back
        provider_name = llm_client._active_provider_name or "anthropic"
        conv.add_tool_results(results, provider_name)

    # Build summary
    summary_parts = [f"Sub-agent completed (objective: {objective}, steps: {steps_used}/{max_steps})"]
    if findings_text:
        summary_parts.append("\n".join(findings_text))
    else:
        summary_parts.append("No explicit findings returned.")

    return "\n\n".join(summary_parts)


def _check_subagent_governance(tc: Any, governance: Any, context: Any) -> Optional[str]:
    """Lightweight governance check for sub-agent tool calls."""
    try:
        if tc.name in ("http_request", "browser_navigate"):
            url = tc.arguments.get("url", "")
            if url and not governance.is_url_in_scope(url):
                return f"URL {url} is not in scope"

        if tc.name == "shell_execute":
            from backend.core.command_analyzer import CommandAnalyzer
            command = tc.arguments.get("command", "")
            if command:
                decision = CommandAnalyzer.analyze(command, strict=True)
                if not decision.allowed:
                    return f"Command blocked: {decision.reason}"
                for target in decision.extracted_targets:
                    test_url = f"https://{target}" if "://" not in target else target
                    if not governance.is_url_in_scope(test_url):
                        return f"Shell command targets out-of-scope host: {target}"
    except Exception as e:
        logger.debug(f"Sub-agent governance check error: {e}")

    return None

"""LLM-Driven Agent — autonomous pentesting with full LLM execution control.

Unlike the existing AutonomousAgent (code-driven pipeline with LLM as advisor),
this agent gives the LLM complete control over execution flow. The LLM decides
what tools to use, when to pivot, and how to chain findings.

Runs alongside (not replacing) the existing pipeline. The existing AutonomousAgent
with its 100 vuln type engine remains for structured scans. This agent handles
open-ended assessments where autonomous reasoning is more valuable.

Usage:
    agent = LLMDrivenAgent(
        target="https://target.com",
        objective="Full penetration test",
        max_steps=100,
    )
    result = await agent.run()
"""

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

from backend.core.llm import UnifiedLLMClient
from backend.core.llm.conversation import Conversation
from backend.core.llm.providers.base import LLMResponse, ModelTier, ToolCall, ToolResult
from backend.core.llm.tool_executor import (
    ExecutionContext,
    ToolExecutor,
    handle_report_finding,
    handle_save_artifact,
    handle_stop,
    handle_update_plan,
)
from backend.core.llm_agent_tools import get_agent_tools
from backend.core.memory.plan_manager import PlanManager
from backend.core.memory.vector_memory import VectorMemory
from backend.core.prompts.prompt_composer import (
    compose_agent_system_prompt,
    compose_reflection_prompt,
)
from backend.core.tools.browser_tool import (
    close_browser_session,
    handle_browser_execute_js,
    handle_browser_extract_forms,
    handle_browser_extract_links,
    handle_browser_navigate,
    handle_browser_screenshot,
)
from backend.core.tools.http_tool import handle_http_request
from backend.core.tools.parallel_executor import execute_parallel
from backend.core.tools.shell_tool import handle_shell_execute

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Result of an LLM-driven agent operation."""
    operation_id: str
    target: str
    objective: str
    status: str  # "completed", "stopped", "error", "budget_exhausted"
    findings: List[Dict[str, Any]]
    steps_used: int
    max_steps: int
    stop_reason: str = ""
    stop_summary: str = ""
    cost_report: Optional[Dict[str, Any]] = None
    artifacts_dir: str = ""
    duration_seconds: float = 0.0
    plan_snapshot: str = ""
    tool_usage: Dict[str, int] = field(default_factory=dict)
    error: str = ""


class LLMDrivenAgent:
    """LLM-driven autonomous pentesting agent.

    The LLM controls the entire execution loop:
    1. Receives target + objective + cognitive framework in system prompt
    2. Decides what tool to call next
    3. Gets tool results fed back
    4. Repeats until stop() called or budget exhausted

    This is the architectural equivalent of CAA's Strands-based agent,
    but built on NeuroSploit's existing UnifiedLLMClient infrastructure.
    """

    def __init__(
        self,
        target: str,
        objective: str = "Perform a comprehensive security assessment",
        max_steps: int = 100,
        llm_client: Optional[UnifiedLLMClient] = None,
        governance_agent=None,
        operation_id: Optional[str] = None,
        data_dir: str = "data",
        on_event: Optional[Callable] = None,
        auth_type: Optional[str] = None,
        auth_credentials: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        self.target = target
        self.objective = objective
        self.max_steps = max_steps
        self.operation_id = operation_id or str(uuid.uuid4())
        self.data_dir = data_dir
        self._on_event = on_event  # Callback for WebSocket events

        # LLM client (shared or dedicated)
        self.llm = llm_client or UnifiedLLMClient()

        # Artifacts directory
        self.artifacts_dir = os.path.join(
            data_dir, "agent_operations", self.operation_id
        )
        os.makedirs(self.artifacts_dir, exist_ok=True)

        # Memory system
        memory_dir = os.path.join(data_dir, "memory", _sanitize_target(target))
        self.memory = VectorMemory(
            target=target,
            operation_id=self.operation_id,
            persist_dir=memory_dir,
        )
        self.plan_manager = PlanManager(persist_dir=self.artifacts_dir)

        # Execution context
        self.context = ExecutionContext(
            operation_id=self.operation_id,
            target=target,
            artifacts_dir=self.artifacts_dir,
            max_steps=max_steps,
            auth_type=auth_type,
            auth_credentials=auth_credentials,
            custom_headers=custom_headers,
        )

        # Tool executor with governance
        self.executor = ToolExecutor(
            context=self.context,
            governance_agent=governance_agent,
            on_step=self._handle_step_event,
        )

        # Register all tool handlers
        self.executor.register_many({
            "shell_execute": handle_shell_execute,
            "http_request": handle_http_request,
            "browser_navigate": handle_browser_navigate,
            "browser_extract_links": handle_browser_extract_links,
            "browser_extract_forms": handle_browser_extract_forms,
            "browser_screenshot": handle_browser_screenshot,
            "browser_execute_js": handle_browser_execute_js,
            "memory_store": self._handle_memory_store,
            "memory_search": self._handle_memory_search,
            "save_artifact": handle_save_artifact,
            "report_finding": handle_report_finding,
            "update_plan": self._handle_update_plan,
            "stop": handle_stop,
        })

        # Internal state
        self._cancelled = False
        self._start_time: Optional[float] = None
        self._llm_failures = 0

    async def run(self) -> AgentResult:
        """Run the LLM-driven assessment.

        Main execution loop:
        1. Compose system prompt with cognitive framework
        2. Send initial message to LLM
        3. LLM responds with tool calls
        4. Execute tools, feed results back
        5. Repeat until stop() or budget exhaustion

        Returns:
            AgentResult with findings, cost report, and artifacts.
        """
        self._start_time = time.monotonic()
        logger.info(
            f"[Agent {self.operation_id[:8]}] Starting LLM-driven assessment "
            f"of {self.target} (max {self.max_steps} steps)"
        )

        await self._emit_event("agent_started", {
            "operation_id": self.operation_id,
            "target": self.target,
            "objective": self.objective,
            "max_steps": self.max_steps,
        })

        try:
            result = await self._run_loop()
        except asyncio.CancelledError:
            result = AgentResult(
                operation_id=self.operation_id,
                target=self.target,
                objective=self.objective,
                status="cancelled",
                findings=self.context.findings,
                steps_used=self.context.current_step,
                max_steps=self.max_steps,
                stop_reason="Operation cancelled",
                artifacts_dir=self.artifacts_dir,
                duration_seconds=time.monotonic() - self._start_time,
                tool_usage=self.context.get_tool_usage_summary(),
            )
        except Exception as e:
            logger.error(f"[Agent {self.operation_id[:8]}] Error: {e}", exc_info=True)
            result = AgentResult(
                operation_id=self.operation_id,
                target=self.target,
                objective=self.objective,
                status="error",
                findings=self.context.findings,
                steps_used=self.context.current_step,
                max_steps=self.max_steps,
                error=str(e),
                artifacts_dir=self.artifacts_dir,
                duration_seconds=time.monotonic() - self._start_time,
                tool_usage=self.context.get_tool_usage_summary(),
            )
        finally:
            # Cleanup browser session
            await close_browser_session(self.operation_id)

            # Save final results
            self._save_results(result)

            await self._emit_event("agent_completed", {
                "operation_id": self.operation_id,
                "status": result.status,
                "findings_count": len(result.findings),
                "steps_used": result.steps_used,
            })

        return result

    async def _run_loop(self) -> AgentResult:
        """Core execution loop — LLM decides, tools execute, results feed back."""
        tools = get_agent_tools()

        # Build initial message
        initial_message = (
            f"Begin your security assessment of {self.target}.\n\n"
            f"Objective: {self.objective}\n\n"
            f"You have {self.max_steps} steps. Start with reconnaissance to understand "
            f"the target, then form hypotheses and test them systematically.\n\n"
            f"Begin by creating a plan with `update_plan`, then start discovery."
        )

        # Conversation state — we manage this ourselves instead of using
        # generate_with_tools() so we can inject checkpoints and refresh
        # the system prompt with updated memory/plan state.
        conv = Conversation(max_turns=self.max_steps * 2)
        conv.add_user(initial_message)

        while not self.context.is_stopped and not self._cancelled:
            # Budget check
            if self.context.current_step >= self.max_steps:
                logger.info(f"[Agent {self.operation_id[:8]}] Budget exhausted")
                break

            # Cost budget check
            if self.llm.cost_tracker.over_budget:
                logger.warning(f"[Agent {self.operation_id[:8]}] Cost budget exceeded")
                break

            # Build auth context description for the LLM
            auth_context = ""
            if self.context.auth_type:
                auth_context = (
                    f"Authentication is configured: **{self.context.auth_type}** credentials "
                    f"are automatically injected into `http_request` and `browser_*` tools. "
                    f"You do not need to manually set auth headers — they are merged "
                    f"automatically. If you need to test without auth, explicitly pass "
                    f"empty headers in the tool call."
                )
                if self.context.custom_headers:
                    header_names = ", ".join(self.context.custom_headers.keys())
                    auth_context += f"\nCustom headers also injected: {header_names}"

            # Compose fresh system prompt with current state
            system_prompt = compose_agent_system_prompt(
                target=self.target,
                objective=self.objective,
                operation_id=self.operation_id,
                current_step=self.context.current_step,
                max_steps=self.max_steps,
                memory_overview=self.memory.get_overview(),
                plan_snapshot=self.plan_manager.get_snapshot(),
                auth_context=auth_context,
            )

            # Generate LLM response
            try:
                response = await self._generate(conv, system_prompt, tools)
                consecutive_llm_failures = 0
            except Exception as e:
                consecutive_llm_failures = getattr(self, '_llm_failures', 0) + 1
                self._llm_failures = consecutive_llm_failures
                logger.error(f"[Agent] LLM generation failed ({consecutive_llm_failures}/3): {e}")

                if consecutive_llm_failures >= 3:
                    logger.error(f"[Agent] 3 consecutive LLM failures — aborting")
                    raise RuntimeError(
                        f"Agent aborted: 3 consecutive LLM failures. Last error: {e}"
                    )

                # Add error as user message and retry
                conv.add_user(
                    f"LLM call failed: {e}. "
                    "Try a different approach or call `stop` if you cannot proceed."
                )
                continue

            conv.add_llm_response(response)

            # No tool calls — LLM gave a text response (shouldn't happen often)
            if not response.has_tool_calls:
                logger.info(f"[Agent] LLM text response (no tool calls): {response.text[:200]}")
                # Nudge the LLM to take action
                conv.add_user(
                    "You must use your tools to make progress. "
                    "What is the next tool you want to call? "
                    "If you are done, call `stop`."
                )
                continue

            # Execute tool calls (parallel if multiple)
            if len(response.tool_calls) > 1:
                results = await execute_parallel(
                    response.tool_calls,
                    self.executor.execute,
                )
            else:
                results = [await self.executor.execute(response.tool_calls[0])]

            # Feed results back to conversation
            provider_name = self.llm._active_provider_name or "anthropic"
            conv.add_tool_results(results, provider_name)

            # Check for checkpoint
            if self.plan_manager.should_checkpoint(
                self.context.current_step, self.max_steps
            ):
                reflection = compose_reflection_prompt(
                    current_step=self.context.current_step,
                    max_steps=self.max_steps,
                    findings_count=len(self.context.findings),
                    tools_used=self.context.get_tool_usage_summary(),
                    memory_summary=self.memory.get_overview(max_entries=5),
                    plan_snapshot=self.plan_manager.get_snapshot(),
                )
                conv.add_user(reflection)

                self.plan_manager.add_checkpoint(
                    step=self.context.current_step,
                    max_steps=self.max_steps,
                    findings_count=len(self.context.findings),
                )

            # Check if stop was called
            if self.context.is_stopped:
                break

        # Determine final status
        if self.context.is_stopped:
            status = "completed"
        elif self._cancelled:
            status = "cancelled"
        elif self.context.current_step >= self.max_steps:
            status = "budget_exhausted"
        elif self.llm.cost_tracker.over_budget:
            status = "cost_budget_exhausted"
        else:
            status = "completed"

        return AgentResult(
            operation_id=self.operation_id,
            target=self.target,
            objective=self.objective,
            status=status,
            findings=self.context.findings,
            steps_used=self.context.current_step,
            max_steps=self.max_steps,
            stop_reason=self.context.stop_reason,
            stop_summary=self.context.stop_summary,
            cost_report=self.llm.cost_tracker.report(),
            artifacts_dir=self.artifacts_dir,
            duration_seconds=time.monotonic() - (self._start_time or time.monotonic()),
            plan_snapshot=self.plan_manager.get_snapshot(),
            tool_usage=self.context.get_tool_usage_summary(),
        )

    async def _generate(
        self,
        conv: Conversation,
        system: str,
        tools: List[Dict[str, Any]],
    ) -> LLMResponse:
        """Generate a single LLM response with tool definitions."""
        from backend.core.llm.tool_adapter import ToolAdapter

        provider = self.llm._get_provider()
        options = self.llm.router.resolve("agent_step", self.llm._active_provider_name)

        # Balanced tier for per-step reasoning (cost-efficient)
        options.max_tokens = 8192

        if provider.supports_tools():
            native_tools = ToolAdapter.for_provider(provider.name, tools)
            options.tools = native_tools
            options.tool_choice = "auto"
        else:
            # Fallback: inject tool descriptions into system prompt
            tool_prompt = ToolAdapter.mcp_to_json_prompt(tools)
            system = f"{system}\n\n{tool_prompt}"

        start = time.monotonic()
        response = await provider.generate(conv.get_messages(), system, options)
        elapsed_ms = (time.monotonic() - start) * 1000

        # Track cost
        tier = self.llm.router.get_tier("agent_step")
        self.llm.cost_tracker.record(response, "agent_step", tier, elapsed_ms)

        # Handle fallback tool parsing for non-native providers
        if not provider.supports_tools() and not response.has_tool_calls:
            tool_call = self.llm._parse_fallback_tool_call(response.text)
            if tool_call:
                response.tool_calls = [tool_call]

        return response

    def cancel(self) -> None:
        """Cancel the running operation."""
        self._cancelled = True
        logger.info(f"[Agent {self.operation_id[:8]}] Cancellation requested")

    # ------------------------------------------------------------------
    # Tool handler wrappers (bridge to memory/plan systems)
    # ------------------------------------------------------------------

    async def _handle_memory_store(self, args: Dict[str, Any], context: ExecutionContext) -> str:
        """Handle memory_store tool — stores to VectorMemory."""
        entry = self.memory.store(
            content=args["content"],
            category=args["category"],
            metadata=args.get("metadata", {}),
        )
        return f"Memory stored (id={entry.id}, category={entry.category})"

    async def _handle_memory_search(self, args: Dict[str, Any], context: ExecutionContext) -> str:
        """Handle memory_search tool — searches VectorMemory."""
        results = self.memory.search(
            query=args["query"],
            category=args.get("category"),
            top_k=args.get("top_k", 5),
        )

        if not results:
            return "No matching memories found."

        lines = [f"Found {len(results)} matching memories:"]
        for entry in results:
            lines.append(
                f"\n[{entry.category}] (score={entry.score:.2f}, id={entry.id})\n"
                f"{entry.content}"
            )

        return "\n".join(lines)

    async def _handle_update_plan(self, args: Dict[str, Any], context: ExecutionContext) -> str:
        """Handle update_plan tool — updates PlanManager."""
        self.plan_manager.update_from_agent(
            current_phase=args["current_phase"],
            completed=args.get("completed", []),
            in_progress=args.get("in_progress", []),
            next_steps=args["next_steps"],
            confidence=args["confidence"],
            key_findings_summary=args.get("key_findings_summary", ""),
            current_step=context.current_step,
            max_steps=context.max_steps,
        )

        # Also delegate to the built-in handler for artifact persistence
        return await handle_update_plan(args, context)

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _handle_step_event(self, step: int, tool_name: str, record: Any) -> None:
        """Callback fired after each tool execution."""
        await self._emit_event("agent_step", {
            "operation_id": self.operation_id,
            "step": step,
            "max_steps": self.max_steps,
            "tool": tool_name,
            "is_error": record.is_error,
            "duration_ms": record.duration_ms,
            "findings_count": len(self.context.findings),
        })

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event via the callback (for WebSocket broadcasting)."""
        if self._on_event:
            try:
                await self._on_event(event_type, data)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Results persistence
    # ------------------------------------------------------------------

    def _save_results(self, result: AgentResult) -> None:
        """Save operation results to disk."""
        os.makedirs(self.artifacts_dir, exist_ok=True)

        results_file = os.path.join(self.artifacts_dir, "results.json")
        with open(results_file, "w") as f:
            json.dump({
                "operation_id": result.operation_id,
                "target": result.target,
                "objective": result.objective,
                "status": result.status,
                "findings": result.findings,
                "steps_used": result.steps_used,
                "max_steps": result.max_steps,
                "stop_reason": result.stop_reason,
                "stop_summary": result.stop_summary,
                "cost_report": result.cost_report,
                "duration_seconds": result.duration_seconds,
                "tool_usage": result.tool_usage,
                "error": result.error,
            }, f, indent=2)

        logger.info(f"[Agent {self.operation_id[:8]}] Results saved to {results_file}")


def _sanitize_target(target: str) -> str:
    """Sanitize a target URL for use as a directory name."""
    import re
    # Remove protocol, collapse non-alphanumeric to underscores
    clean = re.sub(r'https?://', '', target)
    clean = re.sub(r'[^a-zA-Z0-9._-]', '_', clean)
    clean = re.sub(r'_+', '_', clean).strip('_')
    return clean[:100]  # Cap length

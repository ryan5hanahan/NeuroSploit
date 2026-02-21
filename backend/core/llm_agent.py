"""LLM-Driven Agent — autonomous pentesting with full LLM execution control.

The LLM controls the entire execution flow — deciding what tools to use,
when to pivot, and how to chain findings. Uses the 100+ vuln type payload
database via get_payloads/get_vuln_info tools.

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
    DecisionRecord,
    ExecutionContext,
    ToolExecutor,
    handle_get_payloads,
    handle_get_vuln_info,
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
from backend.core.agent_interface import AgentInterface
from backend.core.prompts.context_refresher import ContextRefresher
from backend.core.tools.browser_tool import (
    close_browser_session,
    handle_browser_execute_js,
    handle_browser_extract_forms,
    handle_browser_extract_links,
    handle_browser_navigate,
    handle_browser_screenshot,
    handle_browser_submit_form,
)
from backend.core.tools.dynamic_tool import handle_create_tool
from backend.core.tools.http_tool import handle_http_request
from backend.core.tools.parallel_executor import execute_parallel
from backend.core.tools.shell_tool import handle_shell_execute
from backend.core.tools.swarm_tool import handle_spawn_subagent

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


class LLMDrivenAgent(AgentInterface):
    """LLM-driven autonomous pentesting agent.

    The LLM controls the entire execution loop:
    1. Receives target + objective + cognitive framework in system prompt
    2. Decides what tool to call next
    3. Gets tool results fed back
    4. Repeats until stop() called or budget exhausted

    This is the architectural equivalent of CAA's Strands-based agent,
    but built on sploit.ai's existing UnifiedLLMClient infrastructure.
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
        credential_sets: Optional[List[Dict[str, str]]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        additional_targets: Optional[List[str]] = None,
        subdomain_discovery: bool = False,
        bugbounty_context=None,
        autonomous: bool = False,
    ):
        self.target = target
        self.objective = objective
        self.bugbounty_context = bugbounty_context
        self.autonomous = autonomous

        # Autonomous mode overrides
        if autonomous:
            max_steps = max(max_steps, 200)
            self.skip_checkpoints = True
        else:
            self.skip_checkpoints = False

        self.max_steps = max_steps
        self.scope_profile = "full_auto"
        self.additional_targets = additional_targets or []
        self.subdomain_discovery = subdomain_discovery
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
            credential_sets=credential_sets,
            custom_headers=custom_headers,
        )

        # Tool executor with governance
        self.executor = ToolExecutor(
            context=self.context,
            governance_agent=governance_agent,
            on_step=self._handle_step_event,
        )

        # Register all tool handlers
        self._tool_handlers_map = {
            "shell_execute": handle_shell_execute,
            "http_request": handle_http_request,
            "browser_navigate": handle_browser_navigate,
            "browser_extract_links": handle_browser_extract_links,
            "browser_extract_forms": handle_browser_extract_forms,
            "browser_submit_form": handle_browser_submit_form,
            "browser_screenshot": handle_browser_screenshot,
            "browser_execute_js": handle_browser_execute_js,
            "memory_store": self._handle_memory_store,
            "memory_search": self._handle_memory_search,
            "save_artifact": handle_save_artifact,
            "report_finding": handle_report_finding,
            "update_plan": self._handle_update_plan,
            "get_payloads": handle_get_payloads,
            "get_vuln_info": handle_get_vuln_info,
            "stop": handle_stop,
        }
        self.executor.register_many(self._tool_handlers_map)

        # Dynamic tools list (appended to by create_tool)
        self._dynamic_tools_list: List[Dict[str, Any]] = []

        # Swarm sub-agent handler (closure capturing agent state)
        async def _swarm_handler(args, ctx):
            return await handle_spawn_subagent(
                args, ctx,
                llm_client=self.llm,
                memory=self.memory,
                governance=self.executor.governance,
                tool_handlers=self._tool_handlers_map,
                parent_cancelled=lambda: self._cancelled,
            )

        # Dynamic tool creation handler (closure capturing executor + tools list)
        async def _create_tool_handler(args, ctx):
            return await handle_create_tool(
                args, ctx,
                executor=self.executor,
                tools_list=self._dynamic_tools_list,
            )

        self.executor.register("spawn_subagent", _swarm_handler)
        self.executor.register("create_tool", _create_tool_handler)

        # Internal state
        self._cancelled = False
        self._start_time: Optional[float] = None
        self._llm_failures = 0
        self._conversation_messages: List[Dict[str, Any]] = []

        # Pause/resume support
        self._paused = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Starts unpaused (event is set)

        # Context refresher for dynamic prompt updates
        self._context_refresher = ContextRefresher(refresh_interval=15)

        # Custom prompt injection queue
        self._prompt_queue: asyncio.Queue = asyncio.Queue()

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
        # Build initial message
        initial_message = f"Begin your security assessment of {self.target}.\n\n"
        initial_message += f"Objective: {self.objective}\n\n"

        if self.additional_targets:
            targets_list = "\n".join(f"  - {t}" for t in self.additional_targets)
            initial_message += f"**Additional targets** to assess:\n{targets_list}\n\n"

        if self.subdomain_discovery:
            initial_message += (
                "**Subdomain discovery is ENABLED**. Before deep testing, run "
                "`subfinder -d <domain> -silent` via shell_execute to enumerate "
                "subdomains, then include discovered subdomains in your assessment.\n\n"
            )

        initial_message += (
            f"You have {self.max_steps} steps. Start with reconnaissance to understand "
            f"the target, then form hypotheses and test them systematically.\n\n"
            f"Begin by creating a plan with `update_plan`, then start discovery."
        )

        # Conversation state — we manage this ourselves instead of using
        # generate_with_tools() so we can inject checkpoints and refresh
        # the system prompt with updated memory/plan state.
        conv = Conversation(max_turns=self.max_steps * 2)
        conv.add_user(initial_message)

        _summary_generated = False

        while not self.context.is_stopped and not self._cancelled:
            # Pause gate — block here if paused
            await self._wait_if_paused()
            if self._cancelled:
                break

            # Drain custom prompt queue — inject operator instructions
            while not self._prompt_queue.empty():
                try:
                    prompt = self._prompt_queue.get_nowait()
                    conv.add_user(f"[OPERATOR INSTRUCTION]: {prompt}")
                    await self._emit_event("agent_custom_prompt", {
                        "operation_id": self.operation_id,
                        "prompt": prompt,
                        "step": self.context.current_step,
                    })
                except asyncio.QueueEmpty:
                    break

            # Summary check — reserve budget for final LLM summary
            if not _summary_generated and self._should_generate_summary():
                logger.info(f"[Agent {self.operation_id[:8]}] Generating summary before budget exhaustion")
                summary = await self._generate_summary(conv)
                self.context.stop_summary = summary
                self.context.stop_reason = self.context.stop_reason or "budget_exhaustion_with_summary"
                _summary_generated = True
                break

            # Hard budget check (fallback if summary already generated or fails)
            if self.context.current_step >= self.max_steps:
                logger.info(f"[Agent {self.operation_id[:8]}] Budget exhausted")
                if not self.context.stop_summary:
                    self.context.stop_summary = self._build_programmatic_summary()
                break

            # Cost budget check
            if self.llm.cost_tracker.over_budget:
                logger.warning(f"[Agent {self.operation_id[:8]}] Cost budget exceeded")
                if not self.context.stop_summary:
                    self.context.stop_summary = self._build_programmatic_summary()
                break

            # Build auth context description for the LLM
            auth_context = ""
            cred_labels = self.context.get_credential_labels()
            login_creds = self.context.get_login_credentials()

            if len(cred_labels) > 1:
                # Multi-credential mode
                lines = ["Multiple credential contexts available for differential testing:"]
                for cl in cred_labels:
                    lines.append(
                        f"- **{cl['label']}** (role: {cl['role']}, type: {cl['auth_type']})"
                    )
                lines.append("")
                # Separate instructions for header-based vs login-based creds
                header_labels = [cl for cl in cred_labels if cl["auth_type"] != "login"]
                login_labels = [cl for cl in cred_labels if cl["auth_type"] == "login"]
                if header_labels:
                    lines.append(
                        "Use `credential_label` in `http_request` and `browser_navigate` "
                        "to select which identity to use per-request. Omit for default."
                    )
                if login_labels:
                    lines.append("")
                    lines.append("**Form-based login credentials** (use `browser_submit_form` to authenticate):")
                    for cl in login_labels:
                        lc = login_creds.get(cl["label"], {})
                        lines.append(
                            f"- **{cl['label']}**: username=`{lc.get('username', '?')}`, "
                            f"password=`{lc.get('password', '?')}`"
                        )
                    lines.append(
                        "Navigate to the login page, use `browser_extract_forms` to find the "
                        "login form fields, then use `browser_submit_form` with these credentials."
                    )
                lines.append("")
                lines.append(
                    "Compare responses between contexts to detect BOLA/BFLA/IDOR "
                    "and privilege escalation vulnerabilities."
                )
                auth_context = "\n".join(lines)
            elif cred_labels:
                cl = cred_labels[0]
                if cl["auth_type"] == "login" and login_creds:
                    # Form-based login: tell agent the credentials and how to use them
                    lc = login_creds.get("default", {})
                    auth_context = (
                        f"**Form-based login credentials provided:**\n"
                        f"- Username: `{lc.get('username', '?')}`\n"
                        f"- Password: `{lc.get('password', '?')}`\n\n"
                        f"These credentials require form submission — they are NOT automatically "
                        f"injected as HTTP headers. To authenticate:\n"
                        f"1. Navigate to the login page with `browser_navigate`\n"
                        f"2. Extract forms with `browser_extract_forms` to find field names\n"
                        f"3. Submit credentials with `browser_submit_form`\n"
                        f"4. After successful login, the browser session retains cookies/tokens "
                        f"for subsequent requests."
                    )
                else:
                    auth_context = (
                        f"Authentication is configured: **{cl['auth_type']}** credentials "
                        f"are automatically injected into `http_request` and `browser_*` tools. "
                        f"You do not need to manually set auth headers — they are merged "
                        f"automatically. If you need to test without auth, explicitly pass "
                        f"empty headers in the tool call."
                    )
            if self.context.custom_headers:
                header_names = ", ".join(self.context.custom_headers.keys())
                auth_context += f"\nCustom headers also injected: {header_names}"

            # Extract bug bounty testing instructions
            bugbounty_instructions = ""
            if self.bugbounty_context and hasattr(self.bugbounty_context, "testing_instructions"):
                bugbounty_instructions = self.bugbounty_context.testing_instructions

            # Build governance context for prompt injection
            governance_context = self._build_governance_context()

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
                additional_targets=self.additional_targets,
                subdomain_discovery=self.subdomain_discovery,
                bugbounty_instructions=bugbounty_instructions,
                governance_context=governance_context,
            )

            # Snapshot findings count before this step (for decision records)
            findings_before = len(self.context.findings)

            # Refresh tools list (picks up dynamically created tools)
            tools = get_agent_tools() + self._dynamic_tools_list

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

            # Truncate large tool results to bound per-message token usage
            for r in results:
                if r.content and len(r.content) > 5000:
                    original_len = len(r.content)
                    r.content = (
                        r.content[:2000]
                        + f"\n\n[... truncated {original_len - 4000} chars ...]\n\n"
                        + r.content[-2000:]
                    )

            # Feed results back to conversation
            provider_name = self.llm._active_provider_name or "anthropic"
            conv.add_tool_results(results, provider_name)

            # Build decision record
            cost_report = self.llm.cost_tracker.report()
            decision = DecisionRecord(
                step=self.context.current_step,
                timestamp=time.time(),
                reasoning_text=response.text or "",
                tool_calls=[
                    {"name": tc.name, "arguments": tc.arguments}
                    for tc in response.tool_calls
                ],
                results=[
                    {
                        "tool": r.tool_call_id,
                        "preview": r.content[:500] if r.content else "",
                        "is_error": r.is_error,
                    }
                    for r in results
                ],
                findings_count_before=findings_before,
                findings_count_after=len(self.context.findings),
                cost_usd_cumulative=cost_report.get("total_cost_usd", 0),
            )
            self.context.decision_records.append(decision)

            # Check for checkpoint (skip in autonomous mode)
            if not self.autonomous and self.plan_manager.should_checkpoint(
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

            # Context refresher — inject updated findings/state every N steps
            if self._context_refresher.should_refresh(self.context.current_step):
                context_update = self._context_refresher.generate_context_update(
                    current_step=self.context.current_step,
                    max_steps=self.max_steps,
                    findings=self.context.findings,
                    plan_snapshot=self.plan_manager.get_snapshot(),
                    memory_overview=self.memory.get_overview(max_entries=5),
                )
                conv.add_user(context_update)

            # Check if stop was called
            if self.context.is_stopped:
                break

        # Preserve conversation for persistence
        try:
            self._conversation_messages = conv.get_messages()
        except Exception:
            self._conversation_messages = []

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

    def _resolve_step_task_type(self) -> str:
        """Determine the LLM task type for the current step based on plan phase.

        Routes to different model tiers:
        - No plan yet (step 0) → agent_plan (DEEP) for initial planning
        - Discovery phase → agent_step_recon (FAST) for recon tool dispatch
        - Hypothesis phase → agent_step (BALANCED) for standard testing
        - Validation/Reporting → agent_step_analysis (DEEP) for finding confirmation
        """
        plan = self.plan_manager.plan
        if plan is None:
            return "agent_plan"

        phase = plan.current_phase
        if phase is None:
            return "agent_step"

        phase_name = phase.name.lower()
        if phase_name == "discovery":
            return "agent_step_recon"
        elif phase_name in ("validation", "reporting"):
            return "agent_step_analysis"
        else:
            # Hypothesis and any custom phases
            return "agent_step"

    async def _generate(
        self,
        conv: Conversation,
        system: str,
        tools: List[Dict[str, Any]],
    ) -> LLMResponse:
        """Generate a single LLM response with tool definitions."""
        from backend.core.llm.tool_adapter import ToolAdapter

        provider = self.llm._get_provider()
        task_type = self._resolve_step_task_type()
        options = self.llm.router.resolve(task_type, self.llm._active_provider_name)

        # Resolve tier for per-tier logic below
        tier = self.llm.router.get_tier(task_type)

        # Enable prompt caching for Claude on non-fast tiers (90% discount on cached prefix)
        provider_name = self.llm._active_provider_name or "anthropic"
        if provider_name in ("anthropic", "bedrock") and tier != ModelTier.FAST:
            options.cache_system_prompt = True

        # Override max_tokens — tier default may be too small for tool-use steps
        # Only for BALANCED/DEEP; FAST tier stays at configured 1024 to keep responses short
        if tier != ModelTier.FAST:
            options.max_tokens = max(options.max_tokens, 8192)

        if provider.supports_tools():
            native_tools = ToolAdapter.for_provider(provider.name, tools)
            options.tools = native_tools
            options.tool_choice = "auto"
        else:
            # Fallback: inject tool descriptions into system prompt
            tool_prompt = ToolAdapter.mcp_to_json_prompt(tools)
            system = f"{system}\n\n{tool_prompt}"

        # Trim conversation to stay within 200K context window
        # 180K budget leaves 20K headroom for response + tool definitions
        conv.trim_to_token_budget(max_tokens=180_000, system_tokens=len(system) // 4)

        start = time.monotonic()
        response = await provider.generate(conv.get_messages(), system, options)
        elapsed_ms = (time.monotonic() - start) * 1000

        # Track cost under the resolved task type and tier
        self.llm.cost_tracker.record(response, task_type, tier, elapsed_ms)

        # Handle fallback tool parsing for non-native providers
        if not provider.supports_tools() and not response.has_tool_calls:
            tool_call = self.llm._parse_fallback_tool_call(response.text)
            if tool_call:
                response.tool_calls = [tool_call]

        return response

    def _should_generate_summary(self) -> bool:
        """Check if we should reserve budget for a final LLM summary.

        Returns True when within 2 steps of max OR cost >= 90%.
        """
        steps_remaining = self.max_steps - self.context.current_step
        if steps_remaining <= 2:
            return True
        cost_pct = self.llm.cost_tracker.report().get("budget_pct_used", 0)
        if cost_pct >= 90:
            return True
        return False

    async def _generate_summary(self, conv: Conversation) -> str:
        """Generate a structured summary via LLM before budget exhaustion."""
        try:
            # Build findings summary for the prompt
            findings = self.context.findings
            sev_counts = {}
            for f in findings:
                sev = f.get("severity", "info")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            findings_text = "\n".join(
                f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}: "
                f"{f.get('description', '')[:200]}"
                for f in findings
            ) or "No findings reported."

            summary_prompt = (
                f"Your security assessment of {self.target} is ending (budget exhaustion). "
                f"Steps used: {self.context.current_step}/{self.max_steps}.\n\n"
                f"Findings ({len(findings)} total, by severity: {sev_counts}):\n{findings_text}\n\n"
                f"Write a structured summary covering:\n"
                f"1. Assessment scope and what was tested\n"
                f"2. Key findings and their impact\n"
                f"3. Areas that could not be fully tested due to budget constraints\n"
                f"4. Recommended next steps\n\n"
                f"Be concise but thorough."
            )

            system = (
                "You are a security assessment agent writing a final operation summary. "
                "Write a clear, professional summary of your assessment results."
            )

            summary_text = await self._generate_summary_call(conv, system, summary_prompt)
            return summary_text
        except Exception as e:
            logger.warning(f"[Agent] LLM summary generation failed: {e}")
            return self._build_programmatic_summary()

    async def _generate_summary_call(
        self, conv: Conversation, system: str, prompt: str
    ) -> str:
        """LLM call with tools=None forcing text-only response."""
        summary_conv = Conversation(max_turns=2)
        summary_conv.add_user(prompt)

        provider = self.llm._get_provider()
        options = self.llm.router.resolve("agent_summary", self.llm._active_provider_name)
        options.max_tokens = 4096
        options.tools = None
        options.tool_choice = None

        start = time.monotonic()
        response = await provider.generate(summary_conv.get_messages(), system, options)
        elapsed_ms = (time.monotonic() - start) * 1000

        tier = self.llm.router.get_tier("agent_summary")
        self.llm.cost_tracker.record(response, "agent_summary", tier, elapsed_ms)

        return response.text or self._build_programmatic_summary()

    def _build_programmatic_summary(self) -> str:
        """Fallback summary built from tool_records and findings when LLM call fails."""
        findings = self.context.findings
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        tool_usage = self.context.get_tool_usage_summary()
        top_tools = sorted(tool_usage.items(), key=lambda x: -x[1])[:5]
        tools_text = ", ".join(f"{name} ({count}x)" for name, count in top_tools)

        duration = time.monotonic() - (self._start_time or time.monotonic())

        lines = [
            f"Assessment Summary for {self.target}",
            f"Objective: {self.objective}",
            f"Steps: {self.context.current_step}/{self.max_steps}",
            f"Duration: {duration:.0f}s",
            f"",
            f"Findings: {len(findings)} total",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev_counts.get(sev, 0) > 0:
                lines.append(f"  {sev.upper()}: {sev_counts[sev]}")

        if findings:
            lines.append("")
            lines.append("Key findings:")
            for f in findings[:10]:
                lines.append(
                    f"  - [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}"
                )

        if tools_text:
            lines.append(f"\nTop tools used: {tools_text}")

        lines.append(f"\nStop reason: {self.context.stop_reason or 'budget exhaustion'}")
        return "\n".join(lines)

    def cancel(self) -> None:
        """Cancel the running operation."""
        self._cancelled = True
        # If paused, unblock so the loop can exit
        self._pause_event.set()
        logger.info(f"[Agent {self.operation_id[:8]}] Cancellation requested")

    def pause(self) -> None:
        """Pause the agent. It will halt before the next LLM call."""
        self._paused = True
        self._pause_event.clear()
        logger.info(f"[Agent {self.operation_id[:8]}] Pause requested")

    def resume(self) -> None:
        """Resume a paused agent."""
        self._paused = False
        self._pause_event.set()
        logger.info(f"[Agent {self.operation_id[:8]}] Resume requested")

    @property
    def status(self) -> str:
        """Current agent status."""
        if self._cancelled:
            return "cancelled"
        if self._paused:
            return "paused"
        if self.context.is_stopped:
            return "completed"
        if self._start_time is not None:
            return "running"
        return "idle"

    @property
    def findings(self) -> list:
        """Current list of findings."""
        return self.context.findings

    def add_custom_prompt(self, prompt: str) -> None:
        """Queue a custom operator prompt for injection into the conversation."""
        self._prompt_queue.put_nowait(prompt)
        logger.info(f"[Agent {self.operation_id[:8]}] Custom prompt queued: {prompt[:80]}")

    async def _wait_if_paused(self) -> None:
        """If paused, emit event and block until resumed."""
        if self._paused:
            await self._emit_event("agent_paused", {
                "operation_id": self.operation_id,
                "step": self.context.current_step,
            })
            await self._pause_event.wait()
            if not self._cancelled:
                await self._emit_event("agent_resumed", {
                    "operation_id": self.operation_id,
                    "step": self.context.current_step,
                })

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
    # Governance context for prompt injection
    # ------------------------------------------------------------------

    def _build_governance_context(self) -> Optional[Dict[str, Any]]:
        """Build governance context dict for system prompt injection.

        Returns None if no governance restrictions apply (full_auto).
        """
        gov = self.executor.governance
        if not gov:
            return None

        # Extract scope profile
        scope_profile = "full_auto"
        allowed_phases = []
        governance_mode = "off"

        if hasattr(gov, 'scope'):
            scope = gov.scope
            scope_profile = scope.profile.value if hasattr(scope.profile, 'value') else str(scope.profile)
            if scope.allowed_phases:
                allowed_phases = sorted(scope.allowed_phases)

        if hasattr(gov, 'governance_mode'):
            governance_mode = gov.governance_mode

        # Only inject governance section for restricted scopes
        if scope_profile == "full_auto" and governance_mode != "strict":
            return None

        return {
            "scope_profile": scope_profile,
            "governance_mode": governance_mode,
            "allowed_phases": allowed_phases,
        }

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _handle_step_event(self, step: int, tool_name: str, record: Any) -> None:
        """Callback fired after each tool execution."""
        # Include reasoning preview from latest decision record
        reasoning_preview = ""
        if self.context.decision_records:
            latest = self.context.decision_records[-1]
            if latest.reasoning_text:
                reasoning_preview = latest.reasoning_text[:200]

        await self._emit_event("agent_step", {
            "operation_id": self.operation_id,
            "step": step,
            "max_steps": self.max_steps,
            "tool": tool_name,
            "is_error": record.is_error,
            "duration_ms": record.duration_ms,
            "findings_count": len(self.context.findings),
            "reasoning_preview": reasoning_preview,
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
        """Save operation results and artifacts to disk."""
        os.makedirs(self.artifacts_dir, exist_ok=True)

        # Save main results
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

        # Save decision log
        try:
            decision_log_file = os.path.join(self.artifacts_dir, "decision_log.json")
            with open(decision_log_file, "w") as f:
                json.dump(
                    [d.to_dict() for d in self.context.decision_records],
                    f, indent=2, default=str,
                )
        except Exception as e:
            logger.warning(f"Failed to save decision log: {e}")

        # Save conversation history
        try:
            if self._conversation_messages:
                conv_file = os.path.join(self.artifacts_dir, "conversation.json")
                with open(conv_file, "w") as f:
                    json.dump(self._conversation_messages, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to save conversation: {e}")

        # Save tool records
        try:
            tool_records_file = os.path.join(self.artifacts_dir, "tool_records.json")
            with open(tool_records_file, "w") as f:
                json.dump(
                    [
                        {
                            "tool_name": r.tool_name,
                            "arguments": r.arguments,
                            "result_preview": r.result_preview,
                            "is_error": r.is_error,
                            "duration_ms": r.duration_ms,
                            "step_number": r.step_number,
                            "timestamp": r.timestamp,
                        }
                        for r in self.context.tool_records
                    ],
                    f, indent=2, default=str,
                )
        except Exception as e:
            logger.warning(f"Failed to save tool records: {e}")

        logger.info(f"[Agent {self.operation_id[:8]}] Results saved to {self.artifacts_dir}")


def _sanitize_target(target: str) -> str:
    """Sanitize a target URL for use as a directory name."""
    import re
    # Remove protocol, collapse non-alphanumeric to underscores
    clean = re.sub(r'https?://', '', target)
    clean = re.sub(r'[^a-zA-Z0-9._-]', '_', clean)
    clean = re.sub(r'_+', '_', clean).strip('_')
    return clean[:100]  # Cap length

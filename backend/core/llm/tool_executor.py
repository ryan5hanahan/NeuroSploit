"""Tool execution dispatcher for the LLM-driven agent.

Maps tool names to handler functions, enforces governance checks,
collects evidence, and tracks step budget.
"""

import asyncio
import json
import logging
import os
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional

from ..llm.providers.base import ToolCall, ToolResult

logger = logging.getLogger(__name__)


@dataclass
class ToolExecutionRecord:
    """Record of a single tool execution."""
    tool_name: str
    arguments: Dict[str, Any]
    result_preview: str
    is_error: bool
    duration_ms: float
    step_number: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class DecisionRecord:
    """Record of a single LLM decision step (reasoning + tool calls + results)."""
    step: int
    timestamp: float
    reasoning_text: str
    tool_calls: List[Dict[str, Any]]  # [{name, arguments}]
    results: List[Dict[str, Any]]  # [{tool, preview, is_error}]
    findings_count_before: int
    findings_count_after: int
    cost_usd_cumulative: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "timestamp": self.timestamp,
            "reasoning_text": self.reasoning_text,
            "tool_calls": self.tool_calls,
            "results": self.results,
            "findings_count_before": self.findings_count_before,
            "findings_count_after": self.findings_count_after,
            "cost_usd_cumulative": self.cost_usd_cumulative,
        }


@dataclass
class ExecutionContext:
    """Shared state for all tool executions within an operation."""
    operation_id: str
    target: str
    artifacts_dir: str
    current_step: int = 0
    max_steps: int = 100
    findings: List[Dict[str, Any]] = field(default_factory=list)
    plan: Optional[Dict[str, Any]] = None
    tool_records: List[ToolExecutionRecord] = field(default_factory=list)
    tool_call_counts: Dict[str, int] = field(default_factory=dict)
    decision_records: List[DecisionRecord] = field(default_factory=list)
    _stopped: bool = False
    stop_reason: str = ""
    stop_summary: str = ""
    max_duration_seconds: int = 3600  # 1 hour wall-clock limit
    _start_time: float = field(default_factory=time.time)

    # Authentication (in-memory only, not persisted)
    auth_type: Optional[str] = None  # "cookie", "bearer", "basic", "header"
    auth_credentials: Optional[Dict[str, str]] = None
    credential_sets: Optional[List[Dict[str, str]]] = None
    custom_headers: Optional[Dict[str, str]] = None

    # Built in __post_init__: maps label -> pre-built headers dict
    _credential_contexts: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # Login credentials that need form submission (not header injection)
    _login_credentials: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def __post_init__(self):
        """Build credential context lookup from auth config + credential_sets."""
        self._credential_contexts = {}
        self._login_credentials = {}

        # Register single auth_type/auth_credentials as "default"
        if self.auth_type and self.auth_credentials:
            if self.auth_type == "login":
                self._login_credentials["default"] = {
                    "username": self.auth_credentials.get("username", ""),
                    "password": self.auth_credentials.get("password", ""),
                }
            else:
                self._credential_contexts["default"] = self._build_headers_for(
                    self.auth_type, self.auth_credentials,
                )

        # Register each credential set
        if self.credential_sets:
            for cs in self.credential_sets:
                label = cs.get("label", "default")
                auth_type = cs.get("auth_type", "")
                if auth_type == "login":
                    username = cs.get("username", "")
                    password = cs.get("password", "")
                    if username:
                        self._login_credentials[label] = {
                            "username": username,
                            "password": password,
                        }
                elif auth_type:
                    headers = self._build_headers_for(auth_type, cs)
                    self._credential_contexts[label] = headers

            # If no "default" yet, promote first set
            if "default" not in self._credential_contexts and "default" not in self._login_credentials and self.credential_sets:
                first_label = self.credential_sets[0].get("label", "")
                if first_label and first_label in self._credential_contexts:
                    self._credential_contexts["default"] = self._credential_contexts[first_label]
                elif first_label and first_label in self._login_credentials:
                    self._login_credentials["default"] = self._login_credentials[first_label]

    @staticmethod
    def _build_headers_for(auth_type: str, creds: Dict[str, str]) -> Dict[str, str]:
        """Build HTTP headers dict for a given auth type and credentials."""
        headers: Dict[str, str] = {}
        if auth_type == "bearer":
            token = creds.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "cookie":
            cookie = creds.get("cookie", "")
            if cookie:
                headers["Cookie"] = cookie
        elif auth_type == "basic":
            import base64 as b64
            username = creds.get("username", "")
            password = creds.get("password", "")
            if not username and "basic" in creds and ":" in str(creds["basic"]):
                parts = str(creds["basic"]).split(":", 1)
                username, password = parts[0], parts[1]
            if username:
                encoded = b64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
        elif auth_type == "header":
            name = creds.get("header_name", "")
            value = creds.get("header_value", "")
            if name:
                headers[name] = value
        return headers

    def get_auth_headers(self, label: Optional[str] = None) -> Dict[str, str]:
        """Build HTTP headers from auth configuration.

        Args:
            label: Credential context label (e.g. 'admin', 'user_a').
                   None or 'default' returns the default context.

        Returns headers dict. Tool args override these (LLM may
        intentionally test without auth).
        """
        headers: Dict[str, str] = {}

        # Custom headers first (lowest priority)
        if self.custom_headers:
            headers.update(self.custom_headers)

        # Look up credential context by label
        ctx_label = label or "default"
        ctx_headers = self._credential_contexts.get(ctx_label)

        if ctx_headers:
            headers.update(ctx_headers)
        elif ctx_label != "default" and ctx_label not in self._credential_contexts:
            logger.warning(f"Unknown credential label '{ctx_label}', using no auth")

        return headers

    def get_credential_labels(self) -> List[Dict[str, str]]:
        """Return summary of available credential contexts for prompt injection.

        Returns list of dicts: [{label, role, auth_type}]
        """
        labels = []
        if self.credential_sets:
            for cs in self.credential_sets:
                labels.append({
                    "label": cs.get("label", "default"),
                    "role": cs.get("role", "unknown"),
                    "auth_type": cs.get("auth_type", "unknown"),
                })
        elif self.auth_type:
            labels.append({
                "label": "default",
                "role": "default",
                "auth_type": self.auth_type,
            })
        return labels

    def get_login_credentials(self) -> Dict[str, Dict[str, str]]:
        """Return login-type credentials (username/password) that need form submission.

        Returns dict: {label: {"username": ..., "password": ...}}
        """
        return dict(self._login_credentials)

    # Stuck detection: track consecutive failures per method/approach
    method_attempts: Dict[str, int] = field(default_factory=dict)
    approach_attempts: Dict[str, int] = field(default_factory=dict)
    phase_start_step: int = 0
    phase_start_findings: int = 0

    @property
    def is_stopped(self) -> bool:
        return self._stopped

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self._start_time

    @property
    def time_remaining_seconds(self) -> float:
        return max(0.0, self.max_duration_seconds - self.elapsed_seconds)

    @property
    def time_exceeded(self) -> bool:
        return self.elapsed_seconds >= self.max_duration_seconds

    @property
    def budget_pct(self) -> float:
        return (self.current_step / self.max_steps * 100) if self.max_steps > 0 else 0

    def should_checkpoint(self) -> bool:
        """Check if we're at a 20/40/60/80% checkpoint."""
        if self.max_steps <= 0:
            return False
        pct = self.budget_pct
        for threshold in [20, 40, 60, 80]:
            if abs(pct - threshold) < (100 / self.max_steps):
                return True
        return False

    def get_tool_usage_summary(self) -> Dict[str, int]:
        return dict(self.tool_call_counts)


class ToolExecutor:
    """Dispatches tool calls to handler functions with governance enforcement.

    Usage:
        executor = ToolExecutor(context, governance_agent=gov)
        executor.register("shell_execute", shell_handler)
        executor.register("http_request", http_handler)

        # Use as tool_executor for UnifiedLLMClient.generate_with_tools()
        result = await executor.execute(tool_call)
    """

    def __init__(
        self,
        context: ExecutionContext,
        governance_agent=None,
        on_step: Optional[Callable] = None,
        cost_tracker=None,
    ):
        self.context = context
        self.governance = governance_agent
        self._handlers: Dict[str, Callable] = {}
        self._on_step = on_step  # Callback for step progress events
        self._cost_tracker = cost_tracker  # CostTracker for budget enforcement

    def register(self, tool_name: str, handler: Callable) -> None:
        """Register a tool handler function.

        Handler signature: async def handler(args: dict, context: ExecutionContext) -> str
        """
        self._handlers[tool_name] = handler

    def register_many(self, handlers: Dict[str, Callable]) -> None:
        """Register multiple handlers at once."""
        self._handlers.update(handlers)

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a tool call and return the result.

        This method is the tool_executor callback passed to
        UnifiedLLMClient.generate_with_tools().
        """
        # Step budget enforcement
        if self.context.current_step >= self.context.max_steps:
            return ToolResult(
                tool_call_id=tool_call.id,
                content="BUDGET EXHAUSTED: You have used all available steps. Call 'stop' to end the operation.",
                is_error=True,
            )

        # Wall-clock time enforcement
        if self.context.time_exceeded:
            return ToolResult(
                tool_call_id=tool_call.id,
                content=(
                    f"TIME LIMIT EXCEEDED: Operation has been running for "
                    f"{self.context.elapsed_seconds:.0f}s (limit: "
                    f"{self.context.max_duration_seconds}s). Call 'stop' to end."
                ),
                is_error=True,
            )

        # LLM cost budget enforcement
        if self._cost_tracker and self._cost_tracker.over_budget:
            return ToolResult(
                tool_call_id=tool_call.id,
                content=(
                    f"COST BUDGET EXCEEDED: ${self._cost_tracker.total_cost:.2f} spent "
                    f"(budget: ${self._cost_tracker.budget_usd:.2f}). "
                    f"Call 'stop' to end the operation."
                ),
                is_error=True,
            )

        # Stopped check
        if self.context.is_stopped:
            return ToolResult(
                tool_call_id=tool_call.id,
                content="Operation has been stopped.",
                is_error=True,
            )

        # Increment step
        self.context.current_step += 1
        self.context.tool_call_counts[tool_call.name] = (
            self.context.tool_call_counts.get(tool_call.name, 0) + 1
        )

        # Governance check — covers all tools that interact with external targets
        _GOVERNED_TOOLS = {
            "shell_execute", "http_request",
            "browser_submit_form", "browser_navigate",
            "browser_js", "browser_extract", "browser_screenshot",
        }
        if self.governance and tool_call.name in _GOVERNED_TOOLS:
            gov_result = self._check_governance(tool_call)
            if gov_result:
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content=f"BLOCKED BY GOVERNANCE: {gov_result}",
                    is_error=True,
                )

        # Max severity enforcement for bug bounty programs
        if tool_call.name == "report_finding" and self.governance:
            if hasattr(self.governance, 'check_finding_severity'):
                sev = tool_call.arguments.get("severity", "")
                endpoint = tool_call.arguments.get("endpoint", self.context.target)
                within_limit, effective_sev = self.governance.check_finding_severity(sev, endpoint)
                if not within_limit:
                    tool_call.arguments["_original_severity"] = sev
                    tool_call.arguments["severity"] = effective_sev

        # Find handler
        handler = self._handlers.get(tool_call.name)
        if not handler:
            return ToolResult(
                tool_call_id=tool_call.id,
                content=f"Unknown tool: {tool_call.name}",
                is_error=True,
            )

        # Execute with timing
        start = time.monotonic()
        try:
            result_content = await handler(tool_call.arguments, self.context)
            is_error = False
        except Exception as e:
            logger.error(f"Tool {tool_call.name} failed: {e}\n{traceback.format_exc()}")
            result_content = f"Tool execution error: {type(e).__name__}: {str(e)}"
            is_error = True

        elapsed_ms = (time.monotonic() - start) * 1000

        # Sanitize output (redact secrets + detect prompt injection)
        try:
            from ..output_sanitizer import sanitize_output
            result_content = sanitize_output(result_content)
        except Exception as e:
            logger.debug(f"Output sanitization error: {e}")

        # Truncate output to prevent context overflow
        if len(result_content) > 30000:
            result_content = result_content[:30000] + "\n\n[OUTPUT TRUNCATED — 30KB limit]"

        # Record execution
        record = ToolExecutionRecord(
            tool_name=tool_call.name,
            arguments=tool_call.arguments,
            result_preview=result_content[:500],
            is_error=is_error,
            duration_ms=elapsed_ms,
            step_number=self.context.current_step,
        )
        self.context.tool_records.append(record)

        # Fire step callback
        if self._on_step:
            try:
                await self._on_step(self.context.current_step, tool_call.name, record)
            except Exception:
                pass

        logger.info(
            f"[Step {self.context.current_step}/{self.context.max_steps}] "
            f"{tool_call.name} → {'ERROR' if is_error else 'OK'} ({elapsed_ms:.0f}ms)"
        )

        return ToolResult(
            tool_call_id=tool_call.id,
            content=result_content,
            is_error=is_error,
        )

    def _check_governance(self, tool_call: ToolCall) -> Optional[str]:
        """Check if a tool call is within governance scope.

        Covers:
          - URL scope enforcement on http_request, browser_*, and shell targets
          - Command safety analysis via CommandAnalyzer (replaces old string blocklist)
          - Phase-action enforcement via governance.check_action()
        """
        if not self.governance:
            return None

        try:
            # --- URL scope check for HTTP and browser tools ---
            url_tools = {
                "http_request", "browser_submit_form", "browser_navigate",
                "browser_js", "browser_extract", "browser_screenshot",
            }
            if tool_call.name in url_tools:
                url = tool_call.arguments.get("url", "")
                if url and not self.governance.is_url_in_scope(url):
                    return f"URL {url} is not in scope"

            # --- Command safety analysis for shell_execute ---
            if tool_call.name == "shell_execute":
                from ..command_analyzer import CommandAnalyzer

                command = tool_call.arguments.get("command", "")
                if command:
                    decision = CommandAnalyzer.analyze(command, strict=True)
                    if not decision.allowed:
                        return f"Command blocked: {decision.reason}"

                    # Check extracted targets against scope
                    for target in decision.extracted_targets:
                        # Build a URL for scope checking
                        test_url = f"https://{target}" if "://" not in target else target
                        if not self.governance.is_url_in_scope(test_url):
                            return f"Shell command targets out-of-scope host: {target}"

            # --- Phase-action enforcement ---
            if hasattr(self.governance, 'check_action'):
                phase_decision = self.governance.check_action(
                    tool_call.name,
                    {"tool_args": tool_call.arguments},
                )
                if not phase_decision.allowed:
                    return phase_decision.reason

        except Exception as e:
            logger.debug(f"Governance check error: {e}")

        return None


# ---------------------------------------------------------------------------
# Built-in tool handlers for non-infrastructure tools
# ---------------------------------------------------------------------------

async def handle_report_finding(args: Dict[str, Any], context: ExecutionContext) -> str:
    """Handle the report_finding tool — adds a finding to the operation results.

    Enforces proof pack policy: HIGH/CRITICAL findings require artifact-backed
    evidence and 'verified' validation status. Findings without proof are
    automatically downgraded or flagged as hypotheses.
    """
    severity = args["severity"]
    validation_status = args.get("validation_status", "verified")
    artifact_paths = args.get("artifact_paths", [])

    # Proof pack enforcement for HIGH/CRITICAL
    proof_warning = ""
    if severity in ("critical", "high"):
        if not artifact_paths and validation_status != "hypothesis":
            # Check if evidence text references artifact files
            evidence_lower = args.get("evidence", "").lower()
            has_artifact_ref = any(
                kw in evidence_lower
                for kw in ["screenshot", ".png", ".json", ".txt", "artifact", "saved to"]
            )
            if not has_artifact_ref:
                # Downgrade to hypothesis — agent should save artifacts first
                validation_status = "hypothesis"
                proof_warning = (
                    " WARNING: No artifact files referenced for HIGH/CRITICAL finding. "
                    "Status set to 'hypothesis'. Save evidence with save_artifact or "
                    "browser_screenshot, then re-report with artifact_paths."
                )

    finding = {
        "title": args["title"],
        "severity": severity,
        "vuln_type": args["vuln_type"],
        "description": args["description"],
        "evidence": args["evidence"],
        "endpoint": args["endpoint"],
        "reproduction_steps": args.get("reproduction_steps", ""),
        "remediation": args.get("remediation", ""),
        "cvss_score": args.get("cvss_score"),
        "cvss_vector": args.get("cvss_vector"),
        "cwe_id": args.get("cwe_id"),
        "impact": args.get("impact"),
        "references": args.get("references", []),
        "poc_payload": args.get("poc_payload"),
        "poc_parameter": args.get("poc_parameter"),
        "poc_request": args.get("poc_request"),
        "poc_response": args.get("poc_response"),
        "poc_code": args.get("poc_code"),
        "confidence_score": args.get("confidence_score"),
        "screenshots": args.get("screenshots", []),
        "validation_status": validation_status,
        "artifact_paths": artifact_paths,
        "step_number": context.current_step,
        "timestamp": time.time(),
    }
    context.findings.append(finding)

    # Save finding as artifact
    findings_dir = os.path.join(context.artifacts_dir, "findings")
    os.makedirs(findings_dir, exist_ok=True)
    finding_file = os.path.join(
        findings_dir, f"finding_{len(context.findings):03d}_{severity}.json"
    )
    with open(finding_file, "w") as f:
        json.dump(finding, f, indent=2)

    result = (
        f"Finding #{len(context.findings)} recorded: {args['title']} "
        f"(severity: {severity}, status: {validation_status}). Saved to {finding_file}"
    )

    # Note severity cap if bug bounty program enforced it
    original_severity = args.get("_original_severity")
    if original_severity and original_severity != severity:
        result += (
            f" NOTE: Severity capped from {original_severity} to {severity} "
            f"per bug bounty program's per-asset max_severity limit."
        )

    return result + proof_warning


async def handle_save_artifact(args: Dict[str, Any], context: ExecutionContext) -> str:
    """Handle the save_artifact tool — saves evidence files."""
    os.makedirs(context.artifacts_dir, exist_ok=True)

    # Sanitize filename
    filename = args["filename"].replace("/", "_").replace("\\", "_").replace("..", "_")
    filepath = os.path.join(context.artifacts_dir, filename)

    with open(filepath, "w") as f:
        f.write(args["content"])

    return f"Artifact saved: {filepath}"


async def handle_update_plan(args: Dict[str, Any], context: ExecutionContext) -> str:
    """Handle the update_plan tool — updates the operation plan."""
    context.plan = {
        "current_phase": args["current_phase"],
        "completed": args.get("completed", []),
        "in_progress": args.get("in_progress", []),
        "next_steps": args["next_steps"],
        "confidence": args["confidence"],
        "key_findings_summary": args.get("key_findings_summary", ""),
        "updated_at_step": context.current_step,
        "budget_pct": context.budget_pct,
    }

    # Persist plan as artifact
    plan_file = os.path.join(context.artifacts_dir, "plan.json")
    os.makedirs(context.artifacts_dir, exist_ok=True)
    with open(plan_file, "w") as f:
        json.dump(context.plan, f, indent=2)

    return (
        f"Plan updated (phase: {args['current_phase']}, "
        f"confidence: {args['confidence']}%, "
        f"step: {context.current_step}/{context.max_steps})"
    )


async def handle_stop(args: Dict[str, Any], context: ExecutionContext) -> str:
    """Handle the stop tool — terminates the operation."""
    context._stopped = True
    context.stop_reason = args["reason"]
    context.stop_summary = args["summary"]
    return f"Operation stopped: {args['reason']}"


# ---------------------------------------------------------------------------
# Payload & vulnerability knowledge base tools
# ---------------------------------------------------------------------------

# Lazy-loaded singletons (avoid re-loading on every call)
_payload_generator = None
_vulnerability_registry = None


def _get_payload_generator():
    global _payload_generator
    if _payload_generator is None:
        from ..vuln_engine.payload_generator import PayloadGenerator
        _payload_generator = PayloadGenerator()
    return _payload_generator


def _get_vulnerability_registry():
    global _vulnerability_registry
    if _vulnerability_registry is None:
        from ..vuln_engine.registry import VulnerabilityRegistry
        _vulnerability_registry = VulnerabilityRegistry()
    return _vulnerability_registry


async def handle_get_payloads(args: Dict[str, Any], context: ExecutionContext) -> str:
    """Handle the get_payloads tool — returns curated payloads with PATT-first dedup.

    Merge order: PATT payloads first (community-maintained, more comprehensive),
    then curated payloads appended only if not already present.
    """
    vuln_type = args["vuln_type"]
    ctx = args.get("context", {})
    xss_context = args.get("xss_context")
    filter_bypass = args.get("filter_bypass")
    include_polyglot = args.get("include_polyglot", False)

    pg = _get_payload_generator()

    # Normalize the vuln_type
    from ..vuln_engine.payload_generator import normalize_vuln_type
    canonical = normalize_vuln_type(vuln_type)

    # 1. Load PATT payloads first (highest priority)
    patt_payloads: List[str] = []
    try:
        patt_payloads = pg.patt.get_payloads(canonical)
    except Exception as e:
        logger.warning(f"PATT payload load failed for {canonical}: {e}")

    # 2. Load curated payloads
    curated_payloads: List[str] = list(pg.payload_libraries.get(canonical, []))

    # 3. DB-specific payloads if technology detected
    if ctx.get("detected_technology"):
        db_payloads = pg._select_db_payloads(canonical, ctx)
        if db_payloads:
            curated_payloads = db_payloads + curated_payloads

    # 4. PATT-first merge: start with PATT set, append curated only if not present
    seen = set(patt_payloads)
    merged = list(patt_payloads)
    for p in curated_payloads:
        if p not in seen:
            seen.add(p)
            merged.append(p)

    # 5. XSS context-specific payloads
    if xss_context:
        context_payloads = pg.get_context_payloads(xss_context)
        for p in context_payloads:
            if p not in seen:
                seen.add(p)
                merged.append(p)

    # 6. Filter bypass payloads
    if filter_bypass:
        filter_map = {
            "blocked_chars": filter_bypass.get("blocked_chars", ""),
            "blocked_tags": filter_bypass.get("blocked_tags", ""),
            "blocked_events": filter_bypass.get("blocked_events", ""),
        }
        bypass_payloads = pg.get_filter_bypass_payloads(filter_map)
        for p in bypass_payloads:
            if p not in seen:
                seen.add(p)
                merged.append(p)

    # 7. Polyglot payloads (multi-context probing)
    if include_polyglot:
        polyglot_payloads = pg.get_polyglot_payloads(max_count=10)
        for p in polyglot_payloads:
            if p not in seen:
                seen.add(p)
                merged.append(p)

    # 8. WAF bypass variants
    if ctx.get("waf_detected"):
        merged = pg._add_waf_bypasses(merged, canonical)

    # 9. Depth-based limiting
    depth = ctx.get("depth", "standard")
    depth_limits = {"quick": 3, "standard": 10, "thorough": 20, "exhaustive": 0}
    limit = depth_limits.get(depth, 10)
    if limit > 0 and len(merged) > limit:
        merged = merged[:limit]

    if not merged:
        return f"No payloads found for vuln_type '{vuln_type}' (canonical: '{canonical}'). Use get_vuln_info with list_types=true to see available types."

    # Format output
    lines = [
        f"Payloads for {canonical} ({len(merged)} payloads, depth={depth}):",
        "",
    ]
    for i, p in enumerate(merged, 1):
        lines.append(f"  {i}. {p}")

    return "\n".join(lines)


async def handle_get_vuln_info(args: Dict[str, Any], context: ExecutionContext) -> str:
    """Handle the get_vuln_info tool — returns vulnerability metadata."""
    list_types = args.get("list_types", False)
    registry = _get_vulnerability_registry()

    if list_types:
        type_keys = sorted(registry.VULNERABILITY_INFO.keys())
        lines = [f"Available vulnerability types ({len(type_keys)} total):", ""]
        for key in type_keys:
            info = registry.VULNERABILITY_INFO[key]
            lines.append(f"  {key}: {info.get('title', key)} [{info.get('severity', 'medium')}] ({info.get('cwe_id', 'N/A')})")
        return "\n".join(lines)

    vuln_type = args["vuln_type"]

    # Try to normalize
    try:
        from ..vuln_engine.payload_generator import normalize_vuln_type
        canonical = normalize_vuln_type(vuln_type)
    except Exception:
        canonical = vuln_type

    info = registry.VULNERABILITY_INFO.get(canonical)
    if not info:
        # Try exact match with original
        info = registry.VULNERABILITY_INFO.get(vuln_type)

    if not info:
        return (
            f"No vulnerability info found for '{vuln_type}' (canonical: '{canonical}'). "
            f"Use list_types=true to see all {len(registry.VULNERABILITY_INFO)} available types."
        )

    lines = [
        f"Vulnerability: {info.get('title', canonical)}",
        f"Type Key: {canonical}",
        f"Severity: {info.get('severity', 'medium')}",
        f"CWE: {info.get('cwe_id', 'N/A')}",
        f"",
        f"Description: {info.get('description', 'N/A')}",
        f"",
        f"Impact: {info.get('impact', 'N/A')}",
        f"",
        f"Remediation: {info.get('remediation', 'N/A')}",
    ]

    return "\n".join(lines)

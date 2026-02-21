"""API router for the LLM-driven agent (v2).

Provides endpoints to start, stop, and monitor LLM-driven autonomous
security assessments.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.api.websocket import manager as ws_manager
from backend.db.database import async_session_maker

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory state for running operations
# ---------------------------------------------------------------------------

_running_agents: Dict[str, "LLMDrivenAgent"] = {}
_agent_tasks: Dict[str, asyncio.Task] = {}
_agent_results: Dict[str, dict] = {}
_operation_to_scan: Dict[str, str] = {}  # operation_id -> scan_id
_scan_to_operation: Dict[str, str] = {}  # scan_id -> operation_id
_MAX_RETAINED = 50


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class AgentV2StartRequest(BaseModel):
    target: str = Field(..., description="Target URL or host")
    additional_targets: Optional[List[str]] = Field(
        default=None,
        description="Additional target URLs to include in assessment",
    )
    subdomain_discovery: bool = Field(
        default=False,
        description="Run subdomain enumeration before testing",
    )
    objective: str = Field(
        default="Perform a comprehensive security assessment",
        description="Assessment objective",
    )
    max_steps: int = Field(default=100, ge=10, le=500, description="Maximum steps")
    scope_profile: str = Field(
        default="pentest",
        description="Governance scope (bug_bounty, ctf, pentest, auto_pwn)",
    )
    auth_type: Optional[str] = Field(
        default=None,
        description="Auth type: cookie, bearer, basic, header, or login",
    )
    auth_credentials: Optional[Dict[str, str]] = Field(
        default=None,
        description="Auth credentials (type-specific keys)",
    )
    credential_sets: Optional[List[Dict[str, str]]] = Field(
        default=None,
        description=(
            "Multiple credential sets for differential access testing. "
            "Each dict: {label, role, auth_type, ...type-specific fields}"
        ),
    )
    custom_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom HTTP headers to inject",
    )
    task_id: Optional[str] = Field(
        default=None,
        description="Task library ID — loads task prompt as objective",
    )
    bugbounty_platform: Optional[str] = Field(
        default=None,
        description="Bug bounty platform (e.g. 'hackerone')",
    )
    bugbounty_program: Optional[str] = Field(
        default=None,
        description="Bug bounty program handle (e.g. 'security')",
    )


class AgentV2StartResponse(BaseModel):
    operation_id: str
    status: str
    target: str
    objective: str
    max_steps: int
    message: str
    scan_id: Optional[str] = None


class AgentV2StatusResponse(BaseModel):
    operation_id: str
    status: str
    target: str
    objective: str
    steps_used: int
    max_steps: int
    findings_count: int
    confidence: Optional[float] = None
    plan_snapshot: Optional[str] = None
    plan_phases: Optional[list] = None
    tool_usage: Optional[dict] = None
    cost_report: Optional[dict] = None
    quality_evaluation: Optional[dict] = None
    stop_reason: Optional[str] = None
    stop_summary: Optional[str] = None
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    scan_id: Optional[str] = None


class AgentV2PromptRequest(BaseModel):
    prompt: str = Field(..., description="Custom instruction to inject")


class TestCredentialsRequest(BaseModel):
    target: str = Field(..., description="Target URL to test against")
    credential_set: Dict[str, str] = Field(
        ..., description="Credential set: {auth_type, ...type-specific fields}",
    )


class TestCredentialsResponse(BaseModel):
    success: bool
    status_code: int
    message: str
    duration_ms: float
    response_preview: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/test-credentials", response_model=TestCredentialsResponse)
async def test_credentials(request: TestCredentialsRequest):
    """Test a credential set against the target before starting an operation."""
    import aiohttp
    from backend.core.llm.tool_executor import ExecutionContext

    auth_type = request.credential_set.get("auth_type", "")
    if not auth_type:
        raise HTTPException(status_code=400, detail="credential_set must include auth_type")

    # Build auth headers using the same logic the agent uses
    auth_headers = ExecutionContext._build_headers_for(auth_type, request.credential_set)
    if not auth_headers:
        raise HTTPException(
            status_code=400,
            detail=f"Could not build auth headers for type '{auth_type}' — check credential fields",
        )

    target_url = request.target.strip()

    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False)

    start_ts = time.monotonic()
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # Unauthenticated request first (baseline)
            async with session.get(target_url, allow_redirects=True) as resp:
                unauth_status = resp.status
                unauth_body = await resp.text(errors="replace")

            # Authenticated request
            async with session.get(target_url, headers=auth_headers, allow_redirects=True) as resp:
                auth_status = resp.status
                auth_body = await resp.text(errors="replace")
    except aiohttp.ClientError as e:
        duration_ms = (time.monotonic() - start_ts) * 1000
        return TestCredentialsResponse(
            success=False,
            status_code=0,
            message=f"Connection failed: {e}",
            duration_ms=round(duration_ms, 1),
        )
    except Exception as e:
        duration_ms = (time.monotonic() - start_ts) * 1000
        return TestCredentialsResponse(
            success=False,
            status_code=0,
            message=f"Request error: {e}",
            duration_ms=round(duration_ms, 1),
        )

    duration_ms = (time.monotonic() - start_ts) * 1000

    # --- Assess success by comparing authenticated vs unauthenticated ---
    is_2xx = 200 <= auth_status < 300
    unauth_blocked = unauth_status in (401, 403)

    if auth_status in (401, 403):
        # Clear rejection
        message = f"{auth_status} — credentials rejected"
        success = False
    elif is_2xx and unauth_blocked:
        # Best case: unauth was blocked, auth got through
        message = f"{auth_status} OK — credentials grant access (unauthenticated returned {unauth_status})"
        success = True
    elif is_2xx and unauth_status == auth_status:
        # Both returned 2xx — compare bodies to see if credentials made a difference
        # Normalize whitespace for comparison to avoid false negatives from timestamps etc.
        auth_trimmed = auth_body.strip()[:8192]
        unauth_trimmed = unauth_body.strip()[:8192]
        if auth_trimmed == unauth_trimmed:
            message = (
                f"{auth_status} — identical response with and without credentials; "
                f"endpoint may not validate auth (try a protected path)"
            )
            success = False
        else:
            # Bodies differ — credentials are changing behavior
            message = f"{auth_status} OK — authenticated response differs from unauthenticated"
            success = True
    elif is_2xx:
        # Auth 2xx but unauth returned something else (3xx, 5xx, etc.)
        message = f"{auth_status} OK (unauthenticated returned {unauth_status})"
        success = True
    else:
        message = f"{auth_status} — unexpected response"
        success = False

    # Truncated response preview
    preview = auth_body[:500] if auth_body else None

    return TestCredentialsResponse(
        success=success,
        status_code=auth_status,
        message=message,
        duration_ms=round(duration_ms, 1),
        response_preview=preview,
    )


def _scope_to_task_category(scope_profile: str) -> str:
    """Map scope profile to task category for phase ceiling enforcement."""
    _SCOPE_TASK_CATEGORY = {
        "recon_only": "recon",
        "full_auto": "full_auto",
        "ctf": "full_auto",
        "vuln_lab": "vulnerability",
        "bug_bounty": "vulnerability",
    }
    return _SCOPE_TASK_CATEGORY.get(scope_profile, "full_auto")


@router.post("/start", response_model=AgentV2StartResponse)
async def start_agent(request: AgentV2StartRequest):
    """Start an LLM-driven autonomous security assessment."""
    from backend.core.llm_agent import LLMDrivenAgent
    from backend.core.governance import GovernanceAgent
    from backend.core.governance_facade import create_governance

    # Cleanup stale entries
    _cleanup_stale()

    # Resolve objective from task library if task_id provided
    objective = request.objective
    if request.task_id:
        try:
            from backend.core.task_library import get_task_library
            library = get_task_library()
            task_obj = library.get_task(request.task_id)
            if task_obj:
                objective = task_obj.prompt or objective
        except Exception as e:
            logger.warning(f"Failed to load task {request.task_id}: {e}")

    # Build combined target list for governance scope
    all_targets = [request.target]
    if request.additional_targets:
        all_targets.extend(request.additional_targets)

    # Create governance scope — bug bounty path or standard factories
    bugbounty_context = None
    if request.bugbounty_platform and request.bugbounty_program:
        # Bug bounty scope: fetch program + scope from platform, build governance scope
        try:
            import aiohttp as _aiohttp
            from backend.core.bugbounty.registry import get_platform_registry
            from backend.core.bugbounty.governance_bridge import build_scan_scope_from_program

            registry = get_platform_registry()
            provider = registry.get(request.bugbounty_platform)
            if not provider:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown bug bounty platform: {request.bugbounty_platform}",
                )
            if not provider.enabled:
                raise HTTPException(
                    status_code=400,
                    detail=f"Platform '{request.bugbounty_platform}' credentials not configured",
                )

            async with _aiohttp.ClientSession() as bb_session:
                program = await provider.get_program(request.bugbounty_program, bb_session)
                if not program:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Program '{request.bugbounty_program}' not found on {request.bugbounty_platform}",
                    )
                program_scope = await provider.get_scope(request.bugbounty_program, bb_session)

            scope, bugbounty_context = build_scan_scope_from_program(
                program, program_scope, request.target,
            )
            # Wrap in Governance facade for phase-action enforcement
            scope_agent = GovernanceAgent(scope)
            from backend.core.governance_gate import create_governance_gate
            phase_gate = create_governance_gate(
                scan_id=operation_id if 'operation_id' in dir() else "pending",
                task_category="vulnerability",
            )
            from backend.core.governance_facade import Governance
            governance = Governance(
                scope_agent=scope_agent,
                phase_gate=phase_gate,
                scan_id="pending",
            )
            logger.info(
                f"Bug bounty scope built for {request.bugbounty_platform}/{request.bugbounty_program}"
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Bug bounty scope creation failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Bug bounty scope creation failed: {e}")
    else:
        governance = create_governance(
            scan_id="pending",  # Updated below after operation_id is known
            target_url=request.target,
            scope_profile=request.scope_profile,
            governance_mode="strict" if request.scope_profile == "recon_only" else "warn",
            task_category=_scope_to_task_category(request.scope_profile),
        )

    # Create event callback for WebSocket broadcasting
    async def on_event(event_type: str, data: dict):
        operation_id = data.get("operation_id", "")
        # Broadcast to both the operation_id and scan_id rooms
        await ws_manager.send_to_scan(operation_id, {
            "type": f"agent_v2_{event_type}",
            "operation_id": operation_id,
            **data,
        })
        # Also broadcast to scan_id room if mapping exists
        sid = _operation_to_scan.get(operation_id)
        if sid:
            await ws_manager.send_to_scan(sid, {
                "type": f"agent_v2_{event_type}",
                "operation_id": operation_id,
                **data,
            })

    # Create agent
    agent = LLMDrivenAgent(
        target=request.target,
        objective=objective,
        max_steps=request.max_steps,
        governance_agent=governance,
        on_event=on_event,
        auth_type=request.auth_type,
        auth_credentials=request.auth_credentials,
        credential_sets=request.credential_sets,
        custom_headers=request.custom_headers,
        additional_targets=request.additional_targets,
        subdomain_discovery=request.subdomain_discovery,
        bugbounty_context=bugbounty_context,
    )

    operation_id = agent.operation_id

    # Update governance scan_id now that operation_id is known
    if hasattr(governance, 'scan_id'):
        governance.scan_id = operation_id
    if hasattr(governance, '_phase_gate') and governance._phase_gate:
        governance._phase_gate.scan_id = operation_id

    # Create Scan + Target DB records so findings appear in dashboard
    scan_id = None
    try:
        from backend.models.scan import Scan, Target
        from urllib.parse import urlparse
        import uuid as uuid_mod

        parsed = urlparse(request.target)
        scan_id = str(uuid_mod.uuid4())

        async with async_session_maker() as db:
            scan = Scan(
                id=scan_id,
                name=f"Agent: {request.target}",
                status="running",
                scan_type="llm_driven",
                recon_enabled=False,
                progress=0,
                current_phase="agent_running",
                config={"agent_mode": "llm_driven", "operation_id": operation_id},
            )
            db.add(scan)

            target_record = Target(
                scan_id=scan_id,
                url=request.target,
                hostname=parsed.hostname or "",
                port=parsed.port,
                protocol=parsed.scheme or "https",
                path=parsed.path or "/",
                status="active",
            )
            db.add(target_record)
            await db.commit()

        _operation_to_scan[operation_id] = scan_id
        _scan_to_operation[scan_id] = operation_id
    except Exception as e:
        logger.warning(f"Failed to create Scan/Target records: {e}")
        scan_id = None

    # Store agent and start background task
    _running_agents[operation_id] = agent
    _agent_results[operation_id] = {
        "status": "running",
        "target": request.target,
        "objective": objective,
        "started_at": datetime.utcnow().isoformat(),
        "scan_id": scan_id,
    }

    task = asyncio.create_task(_run_agent(operation_id, agent))
    _agent_tasks[operation_id] = task

    return AgentV2StartResponse(
        operation_id=operation_id,
        status="running",
        target=request.target,
        objective=objective,
        max_steps=request.max_steps,
        message=f"LLM-driven agent started for {request.target}",
        scan_id=scan_id,
    )


@router.post("/{operation_id}/stop")
async def stop_agent(operation_id: str):
    """Stop a running LLM-driven agent."""
    agent = _running_agents.get(operation_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")

    agent.cancel()

    # Also cancel the asyncio task
    task = _agent_tasks.get(operation_id)
    if task and not task.done():
        task.cancel()

    return {"operation_id": operation_id, "status": "stopping", "message": "Stop requested"}


@router.post("/{operation_id}/pause")
async def pause_agent(operation_id: str):
    """Pause a running LLM-driven agent."""
    agent = _running_agents.get(operation_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found or not running")
    agent.pause()
    return {"operation_id": operation_id, "status": "paused", "message": "Pause requested"}


@router.post("/{operation_id}/resume")
async def resume_agent(operation_id: str):
    """Resume a paused LLM-driven agent."""
    agent = _running_agents.get(operation_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found or not running")
    agent.resume()
    return {"operation_id": operation_id, "status": "running", "message": "Resume requested"}


@router.post("/{operation_id}/prompt")
async def send_prompt(operation_id: str, request: AgentV2PromptRequest):
    """Inject a custom prompt into a running agent's conversation."""
    agent = _running_agents.get(operation_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found or not running")
    agent.add_custom_prompt(request.prompt)
    return {"operation_id": operation_id, "status": "prompt_queued", "message": "Prompt injected"}


@router.get("/by-scan/{scan_id}")
async def get_operation_by_scan(scan_id: str):
    """Reverse-lookup: get operation ID from scan ID."""
    operation_id = _scan_to_operation.get(scan_id)
    if operation_id:
        return {"scan_id": scan_id, "operation_id": operation_id}
    raise HTTPException(status_code=404, detail=f"No operation found for scan {scan_id}")


@router.get("/{operation_id}/status", response_model=AgentV2StatusResponse)
async def get_agent_status(operation_id: str):
    """Get the status of an LLM-driven agent operation."""
    # Check running agents
    agent = _running_agents.get(operation_id)
    if agent:
        plan_phases = None
        confidence = None
        if agent.plan_manager.plan:
            try:
                plan_dict = agent.plan_manager.plan.to_dict()
                plan_phases = plan_dict.get("phases")
                confidence = plan_dict.get("confidence")
            except Exception:
                pass

        # Live cost report from the running agent's cost tracker
        cost_report = None
        try:
            cost_report = agent.llm.cost_tracker.report()
        except Exception:
            pass

        # Live duration from start time
        duration_seconds = None
        started_at = _agent_results.get(operation_id, {}).get("started_at")
        if hasattr(agent, '_start_time') and agent._start_time:
            duration_seconds = time.monotonic() - agent._start_time
        elif started_at:
            try:
                start_dt = datetime.fromisoformat(started_at)
                duration_seconds = (datetime.utcnow() - start_dt).total_seconds()
            except Exception:
                pass

        # Determine live status (running vs paused)
        live_status = "paused" if agent._paused else "running"

        return AgentV2StatusResponse(
            operation_id=operation_id,
            status=live_status,
            target=agent.target,
            objective=agent.objective,
            steps_used=agent.context.current_step,
            max_steps=agent.max_steps,
            findings_count=len(agent.context.findings),
            confidence=confidence,
            plan_snapshot=agent.plan_manager.get_snapshot(),
            plan_phases=plan_phases,
            tool_usage=agent.context.get_tool_usage_summary(),
            cost_report=cost_report,
            duration_seconds=duration_seconds,
            scan_id=_operation_to_scan.get(operation_id),
        )

    # Check completed results (in-memory)
    result = _agent_results.get(operation_id)
    if result:
        return AgentV2StatusResponse(
            operation_id=operation_id,
            status=result.get("status", "unknown"),
            target=result.get("target", ""),
            objective=result.get("objective", ""),
            steps_used=result.get("steps_used", 0),
            max_steps=result.get("max_steps", 0),
            findings_count=result.get("findings_count", 0),
            confidence=result.get("confidence"),
            plan_snapshot=result.get("plan_snapshot"),
            plan_phases=result.get("plan_phases"),
            tool_usage=result.get("tool_usage"),
            cost_report=result.get("cost_report"),
            quality_evaluation=result.get("quality_evaluation"),
            stop_reason=result.get("stop_reason"),
            stop_summary=result.get("stop_summary"),
            error=result.get("error"),
            duration_seconds=result.get("duration_seconds"),
            scan_id=result.get("scan_id") or _operation_to_scan.get(operation_id),
        )

    # DB fallback — operation may have been from a previous container session
    try:
        from backend.models.memory import AgentOperation
        from sqlalchemy import select

        async with async_session_maker() as db:
            stmt = select(AgentOperation).where(AgentOperation.id == operation_id)
            row = await db.execute(stmt)
            op = row.scalar_one_or_none()
            if op:
                return AgentV2StatusResponse(
                    operation_id=op.id,
                    status=op.status,
                    target=op.target,
                    objective=op.objective,
                    steps_used=op.steps_used or 0,
                    max_steps=op.max_steps or 0,
                    findings_count=op.findings_count or 0,
                    confidence=op.confidence,
                    plan_snapshot=op.plan_snapshot,
                    plan_phases=op.plan_phases_json,
                    tool_usage=op.tool_usage_json,
                    cost_report=op.cost_report_json,
                    quality_evaluation=op.quality_evaluation_json,
                    stop_reason=op.stop_reason,
                    stop_summary=op.stop_summary,
                    error=op.error_message,
                    duration_seconds=op.duration_seconds,
                )
    except Exception as e:
        logger.error(f"DB fallback failed for status: {e}")

    raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")


@router.get("/{operation_id}/findings")
async def get_agent_findings(operation_id: str):
    """Get findings from an LLM-driven agent operation."""
    agent = _running_agents.get(operation_id)
    if agent:
        return {"operation_id": operation_id, "findings": agent.context.findings}

    result = _agent_results.get(operation_id)
    if result:
        return {"operation_id": operation_id, "findings": result.get("findings", [])}

    # DB fallback
    try:
        from backend.models.memory import AgentOperation
        from sqlalchemy import select

        async with async_session_maker() as db:
            stmt = select(AgentOperation).where(AgentOperation.id == operation_id)
            row = await db.execute(stmt)
            op = row.scalar_one_or_none()
            if op:
                findings = (op.results_json or {}).get("findings", [])
                return {"operation_id": operation_id, "findings": findings}
    except Exception as e:
        logger.error(f"DB fallback failed for findings: {e}")

    raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")


@router.get("/{operation_id}/decisions")
async def get_agent_decisions(operation_id: str):
    """Get the decision log for an agent operation.

    Returns step-by-step LLM reasoning and tool call records.
    Sources: live agent > in-memory cache > DB > artifact file fallback.
    """
    # Live agent
    agent = _running_agents.get(operation_id)
    if agent:
        decisions = [d.to_dict() for d in agent.context.decision_records]
        return {"operation_id": operation_id, "decisions": decisions}

    # In-memory cache
    result = _agent_results.get(operation_id)
    if result and result.get("decision_log") is not None:
        return {"operation_id": operation_id, "decisions": result["decision_log"]}

    # DB fallback
    try:
        from backend.models.memory import AgentOperation
        from sqlalchemy import select

        async with async_session_maker() as db:
            stmt = select(AgentOperation).where(AgentOperation.id == operation_id)
            row = await db.execute(stmt)
            op = row.scalar_one_or_none()
            if op and op.decision_log_json:
                return {"operation_id": operation_id, "decisions": op.decision_log_json}
            if op and op.artifacts_dir:
                # Artifact file fallback
                decision_file = os.path.join(op.artifacts_dir, "decision_log.json")
                if os.path.isfile(decision_file):
                    with open(decision_file) as f:
                        decisions = json.load(f)
                    return {"operation_id": operation_id, "decisions": decisions}
    except Exception as e:
        logger.error(f"DB/file fallback failed for decisions: {e}")

    raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found or no decisions recorded")


@router.get("/operations")
async def list_operations():
    """List all agent operations (running and completed)."""
    operations = []
    seen_ids = set()

    for op_id, agent in _running_agents.items():
        seen_ids.add(op_id)
        live_cost = 0.0
        try:
            live_cost = agent.llm.cost_tracker.report().get("total_cost_usd", 0)
        except Exception:
            pass
        operations.append({
            "operation_id": op_id,
            "status": "running",
            "target": agent.target,
            "objective": agent.objective,
            "steps_used": agent.context.current_step,
            "max_steps": agent.max_steps,
            "findings_count": len(agent.context.findings),
            "total_cost_usd": live_cost,
        })

    for op_id, result in _agent_results.items():
        if op_id not in seen_ids:
            seen_ids.add(op_id)
            result_cost = 0.0
            cr = result.get("cost_report")
            if cr:
                result_cost = cr.get("total_cost_usd", 0)
            operations.append({
                "operation_id": op_id,
                "status": result.get("status", "unknown"),
                "target": result.get("target", ""),
                "objective": result.get("objective", ""),
                "steps_used": result.get("steps_used", 0),
                "max_steps": result.get("max_steps", 0),
                "findings_count": result.get("findings_count", 0),
                "total_cost_usd": result_cost,
            })

    # DB fallback — include operations not in memory
    try:
        from backend.models.memory import AgentOperation
        from sqlalchemy import select

        async with async_session_maker() as db:
            stmt = (
                select(AgentOperation)
                .order_by(AgentOperation.created_at.desc())
                .limit(100)
            )
            rows = await db.execute(stmt)
            for op in rows.scalars().all():
                if op.id not in seen_ids:
                    seen_ids.add(op.id)
                    operations.append({
                        "operation_id": op.id,
                        "status": op.status,
                        "target": op.target,
                        "objective": op.objective,
                        "steps_used": op.steps_used or 0,
                        "max_steps": op.max_steps or 0,
                        "findings_count": op.findings_count or 0,
                        "total_cost_usd": op.total_cost_usd or 0.0,
                    })
    except Exception as e:
        logger.error(f"DB fallback failed for list_operations: {e}")

    return {"operations": operations}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

class ReportGenerateRequest(BaseModel):
    format: str = Field(default="html", description="Report format: html or json")
    title: Optional[str] = Field(default=None, description="Optional report title")
    report_type: str = Field(default="team", description="Report type: client or team")


class ReportGenerateResponse(BaseModel):
    operation_id: str
    format: str
    file_path: str
    message: str


@router.post("/{operation_id}/report", response_model=ReportGenerateResponse)
async def generate_report(operation_id: str, request: ReportGenerateRequest):
    """Generate an HTML or JSON report for a completed agent operation."""
    # Reject if still running
    if operation_id in _running_agents:
        raise HTTPException(
            status_code=409,
            detail="Cannot generate report while operation is still running",
        )

    # Load operation data
    data = await _load_operation_data(operation_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")

    # Ensure operation_id is in the data dict
    data.setdefault("operation_id", operation_id)

    from backend.core.report_engine.agent_generator import AgentReportGenerator

    generator = AgentReportGenerator()
    try:
        file_path, summary = generator.generate(
            data,
            format=request.format,
            title=request.title,
            report_type=request.report_type,
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    # Persist to reports table so it appears on the Reports page
    try:
        from backend.models.report import Report

        target = data.get("target", "unknown")
        report_title = request.title or f"Agent Report — {target}"

        async with async_session_maker() as db:
            report = Report(
                operation_id=operation_id,
                title=report_title,
                report_type=request.report_type,
                format=request.format,
                file_path=str(file_path),
                executive_summary=summary[:2000] if summary else None,
                auto_generated=False,
                is_partial=data.get("status") not in ("completed",),
            )
            db.add(report)
            await db.commit()
    except Exception as e:
        logger.warning(f"Failed to persist report to DB: {e}")

    return ReportGenerateResponse(
        operation_id=operation_id,
        format=request.format,
        file_path=str(file_path),
        message=f"Report generated successfully",
    )


@router.get("/{operation_id}/report/download")
async def download_report(
    operation_id: str,
    format: str = Query(default="html", description="Report format: html or json"),
    report_type: str = Query(default="team", description="Report type: client or team"),
):
    """Download (or generate on-the-fly) a report for a completed operation."""
    if operation_id in _running_agents:
        raise HTTPException(
            status_code=409,
            detail="Cannot download report while operation is still running",
        )

    data = await _load_operation_data(operation_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")

    data.setdefault("operation_id", operation_id)

    from backend.core.report_engine.agent_generator import AgentReportGenerator

    generator = AgentReportGenerator()
    file_path, _ = generator.generate(data, format=format, report_type=report_type)

    media = "text/html" if format == "html" else "application/json"
    return FileResponse(
        path=str(file_path),
        media_type=media,
        filename=file_path.name,
    )


async def _load_operation_data(operation_id: str) -> Optional[dict]:
    """Load operation data from in-memory cache or database fallback."""
    # Check in-memory results first
    result = _agent_results.get(operation_id)
    if result:
        return result

    # Fallback: load from database
    try:
        from backend.models.memory import AgentOperation
        from sqlalchemy import select

        async with async_session_maker() as db:
            stmt = select(AgentOperation).where(AgentOperation.id == operation_id)
            row = await db.execute(stmt)
            op = row.scalar_one_or_none()
            if not op:
                return None

            return {
                "operation_id": op.id,
                "target": op.target,
                "objective": op.objective,
                "status": op.status,
                "steps_used": op.steps_used,
                "max_steps": op.max_steps,
                "findings": (op.results_json or {}).get("findings", []),
                "findings_count": op.findings_count,
                "confidence": op.confidence,
                "plan_snapshot": op.plan_snapshot,
                "plan_phases": op.plan_phases_json,
                "cost_report": op.cost_report_json,
                "tool_usage": op.tool_usage_json,
                "quality_evaluation": op.quality_evaluation_json,
                "quality_score": op.quality_score,
                "duration_seconds": op.duration_seconds,
                "stop_reason": op.stop_reason,
                "stop_summary": op.stop_summary,
                "error": op.error_message,
                "artifacts_dir": op.artifacts_dir,
                "decision_log": op.decision_log_json,
            }
    except Exception as e:
        logger.error(f"Failed to load operation from DB: {e}")
        return None


# ---------------------------------------------------------------------------
# WebSocket for real-time streaming
# ---------------------------------------------------------------------------

@router.websocket("/{operation_id}/ws")
async def agent_websocket(websocket: WebSocket, operation_id: str):
    """WebSocket endpoint for real-time agent event streaming."""
    await ws_manager.connect(websocket, operation_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, operation_id)


# ---------------------------------------------------------------------------
# Background task runner
# ---------------------------------------------------------------------------

async def _run_agent(operation_id: str, agent):
    """Run the agent in a background task and store results."""
    try:
        result = await agent.run()

        # Run quality evaluation
        quality_evaluation = None
        try:
            from backend.core.observability.quality_evaluator import QualityEvaluator
            evaluator = QualityEvaluator()
            plan_phases_raw = []
            if agent.plan_manager.plan:
                try:
                    plan_phases_raw = [
                        p if isinstance(p, dict) else p.to_dict()
                        for p in agent.plan_manager.plan.phases
                    ]
                except Exception:
                    pass
            eval_result = evaluator.evaluate(
                findings=result.findings,
                steps_used=result.steps_used,
                max_steps=result.max_steps,
                tool_usage=result.tool_usage or {},
                plan_phases=plan_phases_raw,
                duration_seconds=result.duration_seconds or 0,
            )
            quality_evaluation = {
                "overall_score": eval_result.overall_score,
                "dimensions": eval_result.dimensions,
                "notes": eval_result.notes,
            }
        except Exception as e:
            logger.warning(f"Quality evaluation failed: {e}")

        # Extract plan phases and confidence
        plan_phases = None
        confidence = None
        if agent.plan_manager.plan:
            try:
                plan_dict = agent.plan_manager.plan.to_dict()
                plan_phases = plan_dict.get("phases")
                confidence = plan_dict.get("confidence")
            except Exception:
                pass

        # Build decision log from agent context
        decision_log = None
        try:
            decision_log = [d.to_dict() for d in agent.context.decision_records]
        except Exception as e:
            logger.warning(f"Failed to extract decision log: {e}")

        # Persist conversation history to disk
        conversation_path = None
        try:
            if hasattr(agent, '_conversation_messages') and agent._conversation_messages:
                conv_file = os.path.join(result.artifacts_dir, "conversation.json")
                os.makedirs(result.artifacts_dir, exist_ok=True)
                with open(conv_file, "w") as f:
                    json.dump(agent._conversation_messages, f, indent=2, default=str)
                conversation_path = conv_file
        except Exception as e:
            logger.warning(f"Failed to persist conversation: {e}")

        # Persist tool records to disk
        try:
            tool_records_file = os.path.join(result.artifacts_dir, "tool_records.json")
            os.makedirs(result.artifacts_dir, exist_ok=True)
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
                        for r in agent.context.tool_records
                    ],
                    f, indent=2, default=str,
                )
        except Exception as e:
            logger.warning(f"Failed to persist tool records: {e}")

        # Store result (in-memory)
        quality_score = quality_evaluation.get("overall_score") if quality_evaluation else None

        _agent_results[operation_id] = {
            "status": result.status,
            "target": result.target,
            "objective": result.objective,
            "confidence": confidence,
            "steps_used": result.steps_used,
            "max_steps": result.max_steps,
            "findings": result.findings,
            "findings_count": len(result.findings),
            "stop_reason": result.stop_reason,
            "stop_summary": result.stop_summary,
            "cost_report": result.cost_report,
            "artifacts_dir": result.artifacts_dir,
            "duration_seconds": result.duration_seconds,
            "plan_snapshot": result.plan_snapshot,
            "plan_phases": plan_phases,
            "tool_usage": result.tool_usage,
            "quality_evaluation": quality_evaluation,
            "decision_log": decision_log,
            "error": result.error,
        }

        # Save to database
        try:
            await _save_operation_to_db(
                operation_id,
                result,
                decision_log=decision_log,
                conversation_path=conversation_path,
                quality_score=quality_score,
                quality_evaluation=quality_evaluation,
                plan_phases=plan_phases,
                plan_snapshot=result.plan_snapshot,
                confidence=confidence,
            )
        except Exception as e:
            logger.error(f"Failed to save operation to DB: {e}")

        # Save findings to vulnerabilities table + update Scan record
        scan_id = _operation_to_scan.get(operation_id)
        if scan_id:
            try:
                await _save_findings_to_scan(scan_id, result)
            except Exception as e:
                logger.error(f"Failed to save findings to scan {scan_id}: {e}")

        # Auto-generate report so it appears on the Reports page
        try:
            await _auto_generate_agent_report(operation_id, result, scan_id)
        except Exception as e:
            logger.warning(f"Failed to auto-generate agent report: {e}")

    except asyncio.CancelledError:
        _agent_results[operation_id] = {
            **_agent_results.get(operation_id, {}),
            "status": "cancelled",
        }
    except Exception as e:
        logger.error(f"Agent {operation_id} failed: {e}", exc_info=True)
        _agent_results[operation_id] = {
            **_agent_results.get(operation_id, {}),
            "status": "error",
            "error": str(e),
        }
    finally:
        # Remove from running agents
        _running_agents.pop(operation_id, None)
        _agent_tasks.pop(operation_id, None)


async def _save_operation_to_db(
    operation_id: str,
    result,
    decision_log=None,
    conversation_path=None,
    quality_score=None,
    quality_evaluation=None,
    plan_phases=None,
    plan_snapshot=None,
    confidence=None,
):
    """Save operation results to the database."""
    from backend.models.memory import AgentOperation

    async with async_session_maker() as db:
        operation = AgentOperation(
            id=operation_id,
            target=result.target,
            objective=result.objective,
            status=result.status,
            steps_used=result.steps_used,
            max_steps=result.max_steps,
            findings_count=len(result.findings),
            critical_count=sum(1 for f in result.findings if f.get("severity") == "critical"),
            high_count=sum(1 for f in result.findings if f.get("severity") == "high"),
            medium_count=sum(1 for f in result.findings if f.get("severity") == "medium"),
            low_count=sum(1 for f in result.findings if f.get("severity") == "low"),
            info_count=sum(1 for f in result.findings if f.get("severity") == "info"),
            total_cost_usd=result.cost_report.get("total_cost_usd", 0) if result.cost_report else 0,
            total_tokens=(
                (result.cost_report.get("total_input_tokens", 0) + result.cost_report.get("total_output_tokens", 0))
                if result.cost_report else 0
            ),
            duration_seconds=result.duration_seconds,
            stop_reason=result.stop_reason,
            stop_summary=result.stop_summary or "",
            error_message=result.error,
            artifacts_dir=result.artifacts_dir,
            tool_usage_json=result.tool_usage,
            results_json={"findings": result.findings},
            quality_score=quality_score,
            quality_evaluation_json=quality_evaluation,
            plan_phases_json=plan_phases,
            plan_snapshot=plan_snapshot,
            confidence=confidence,
            cost_report_json=result.cost_report,
            decision_log_json=decision_log,
            conversation_path=conversation_path,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        db.add(operation)
        await db.commit()


async def _save_findings_to_scan(scan_id: str, result):
    """Save agent findings to the vulnerabilities table and update the Scan record."""
    from backend.models.scan import Scan
    from backend.models.vulnerability import Vulnerability
    from backend.services.vuln_enrichment_utils import backfill_vulnerability_metadata
    from backend.services.vuln_enrichment import VulnEnrichmentService
    from sqlalchemy import select

    async with async_session_maker() as db:
        # Save each finding as a Vulnerability
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_ids = []
        for finding in result.findings:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            vuln = Vulnerability(
                scan_id=scan_id,
                title=finding.get("title", "Unknown")[:255],
                vulnerability_type=finding.get("vuln_type", "unknown"),
                severity=sev,
                description=finding.get("description", ""),
                affected_endpoint=finding.get("endpoint", ""),
                cvss_score=finding.get("cvss_score"),
                cvss_vector=finding.get("cvss_vector"),
                cwe_id=finding.get("cwe_id"),
                impact=finding.get("impact"),
                references=finding.get("references", []),
                poc_payload=finding.get("poc_payload") or finding.get("evidence", "")[:5000],
                poc_parameter=finding.get("poc_parameter"),
                poc_request=finding.get("poc_request") or finding.get("reproduction_steps", "")[:5000],
                poc_response=finding.get("poc_response"),
                poc_code=finding.get("poc_code"),
                poc_evidence=finding.get("evidence", "")[:5000],
                remediation=finding.get("remediation", ""),
                ai_analysis=finding.get("evidence", ""),
            )
            backfill_vulnerability_metadata(vuln)
            db.add(vuln)
            await db.flush()
            vuln_ids.append(vuln.id)

        # Update Scan record
        stmt = select(Scan).where(Scan.id == scan_id)
        row = await db.execute(stmt)
        scan = row.scalar_one_or_none()
        if scan:
            scan.status = "completed" if result.status in ("completed", "budget_exhausted") else result.status
            scan.progress = 100
            scan.current_phase = "completed"
            scan.total_vulnerabilities = len(result.findings)
            scan.critical_count = severity_counts.get("critical", 0)
            scan.high_count = severity_counts.get("high", 0)
            scan.medium_count = severity_counts.get("medium", 0)
            scan.low_count = severity_counts.get("low", 0)
            scan.info_count = severity_counts.get("info", 0)
            scan.completed_at = datetime.utcnow()
            scan.duration = int(result.duration_seconds) if result.duration_seconds else None

        await db.commit()

    # Enqueue enrichment after commit (IDs are now stable)
    enrichment_svc = VulnEnrichmentService.get_instance()
    for vid in vuln_ids:
        await enrichment_svc.enqueue(vid, scan_id)

    logger.info(f"Saved {len(result.findings)} findings to scan {scan_id}")


async def _auto_generate_agent_report(
    operation_id: str, result, scan_id: Optional[str] = None
):
    """Auto-generate an HTML report for a completed agent operation.

    Creates a Report DB record so the report appears on the Reports page.
    """
    from backend.core.report_engine.agent_generator import AgentReportGenerator
    from backend.models.report import Report

    data = {
        "operation_id": operation_id,
        "target": result.target,
        "objective": result.objective,
        "status": result.status,
        "findings": result.findings,
        "findings_count": len(result.findings),
        "steps_used": result.steps_used,
        "max_steps": result.max_steps,
        "stop_reason": result.stop_reason,
        "stop_summary": result.stop_summary,
        "cost_report": result.cost_report,
        "tool_usage": result.tool_usage,
        "duration_seconds": result.duration_seconds,
        "artifacts_dir": result.artifacts_dir,
    }

    generator = AgentReportGenerator()
    file_path, summary = generator.generate(data, format="html", report_type="team")

    is_partial = result.status not in ("completed",)
    report_title = f"Agent Report — {result.target}"

    async with async_session_maker() as db:
        report = Report(
            scan_id=scan_id,
            operation_id=operation_id,
            title=report_title,
            report_type="team",
            format="html",
            file_path=str(file_path),
            executive_summary=summary[:2000] if summary else None,
            auto_generated=True,
            is_partial=is_partial,
        )
        db.add(report)
        await db.commit()

    logger.info(f"Auto-generated agent report for operation {operation_id[:8]}")


def _cleanup_stale():
    """Remove old completed operations to prevent memory leaks."""
    if len(_agent_results) > _MAX_RETAINED:
        # Keep only the most recent operations
        sorted_ops = sorted(
            _agent_results.items(),
            key=lambda x: x[1].get("started_at", ""),
            reverse=True,
        )
        for op_id, _ in sorted_ops[_MAX_RETAINED:]:
            if op_id not in _running_agents:
                _agent_results.pop(op_id, None)

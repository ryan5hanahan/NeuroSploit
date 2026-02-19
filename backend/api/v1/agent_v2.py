"""API router for the LLM-driven agent (v2).

Provides endpoints to start, stop, and monitor LLM-driven autonomous
security assessments.
"""

import asyncio
import logging
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
_MAX_RETAINED = 50


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class AgentV2StartRequest(BaseModel):
    target: str = Field(..., description="Target URL or host")
    objective: str = Field(
        default="Perform a comprehensive security assessment",
        description="Assessment objective",
    )
    max_steps: int = Field(default=100, ge=10, le=500, description="Maximum steps")
    scope_profile: str = Field(
        default="full_auto",
        description="Governance scope (full_auto, vuln_lab, ctf, recon_only)",
    )
    auth_type: Optional[str] = Field(
        default=None,
        description="Auth type: cookie, bearer, basic, or header",
    )
    auth_credentials: Optional[Dict[str, str]] = Field(
        default=None,
        description="Auth credentials (type-specific keys)",
    )
    custom_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom HTTP headers to inject",
    )


class AgentV2StartResponse(BaseModel):
    operation_id: str
    status: str
    target: str
    objective: str
    max_steps: int
    message: str


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
    error: Optional[str] = None
    duration_seconds: Optional[float] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/start", response_model=AgentV2StartResponse)
async def start_agent(request: AgentV2StartRequest):
    """Start an LLM-driven autonomous security assessment."""
    from backend.core.llm_agent import LLMDrivenAgent
    from backend.core.governance import (
        create_full_auto_scope,
        create_ctf_scope,
        create_recon_only_scope,
        create_vuln_lab_scope,
        GovernanceAgent,
    )

    # Cleanup stale entries
    _cleanup_stale()

    # Create governance scope
    scope_factories = {
        "full_auto": lambda: create_full_auto_scope(request.target),
        "ctf": lambda: create_ctf_scope(request.target),
        "recon_only": lambda: create_recon_only_scope(request.target),
        "vuln_lab": lambda: create_vuln_lab_scope(request.target, "all"),
    }
    scope_factory = scope_factories.get(request.scope_profile, scope_factories["full_auto"])
    scope = scope_factory()
    governance = GovernanceAgent(scope)

    # Create event callback for WebSocket broadcasting
    async def on_event(event_type: str, data: dict):
        operation_id = data.get("operation_id", "")
        await ws_manager.send_to_scan(operation_id, {
            "type": f"agent_v2_{event_type}",
            "operation_id": operation_id,
            **data,
        })

    # Create agent
    agent = LLMDrivenAgent(
        target=request.target,
        objective=request.objective,
        max_steps=request.max_steps,
        governance_agent=governance,
        on_event=on_event,
        auth_type=request.auth_type,
        auth_credentials=request.auth_credentials,
        custom_headers=request.custom_headers,
    )

    operation_id = agent.operation_id

    # Store agent and start background task
    _running_agents[operation_id] = agent
    _agent_results[operation_id] = {
        "status": "running",
        "target": request.target,
        "objective": request.objective,
        "started_at": datetime.utcnow().isoformat(),
    }

    task = asyncio.create_task(_run_agent(operation_id, agent))
    _agent_tasks[operation_id] = task

    return AgentV2StartResponse(
        operation_id=operation_id,
        status="running",
        target=request.target,
        objective=request.objective,
        max_steps=request.max_steps,
        message=f"LLM-driven agent started for {request.target}",
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

        return AgentV2StatusResponse(
            operation_id=operation_id,
            status="running",
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
        )

    # Check completed results
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
            error=result.get("error"),
            duration_seconds=result.get("duration_seconds"),
        )

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

    raise HTTPException(status_code=404, detail=f"Operation {operation_id} not found")


@router.get("/operations")
async def list_operations():
    """List all agent operations (running and completed)."""
    operations = []

    for op_id, agent in _running_agents.items():
        operations.append({
            "operation_id": op_id,
            "status": "running",
            "target": agent.target,
            "objective": agent.objective,
            "steps_used": agent.context.current_step,
            "max_steps": agent.max_steps,
            "findings_count": len(agent.context.findings),
        })

    for op_id, result in _agent_results.items():
        if op_id not in _running_agents:
            operations.append({
                "operation_id": op_id,
                "status": result.get("status", "unknown"),
                "target": result.get("target", ""),
                "objective": result.get("objective", ""),
                "steps_used": result.get("steps_used", 0),
                "max_steps": result.get("max_steps", 0),
                "findings_count": result.get("findings_count", 0),
            })

    return {"operations": operations}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

class ReportGenerateRequest(BaseModel):
    format: str = Field(default="html", description="Report format: html or json")
    title: Optional[str] = Field(default=None, description="Optional report title")


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
        file_path, _summary = generator.generate(
            data,
            format=request.format,
            title=request.title,
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

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
    file_path, _ = generator.generate(data, format=format)

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
                "cost_report": None,
                "tool_usage": op.tool_usage_json,
                "duration_seconds": op.duration_seconds,
                "stop_reason": op.stop_reason,
                "error": op.error_message,
                "artifacts_dir": op.artifacts_dir,
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

        # Store result
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
            "error": result.error,
        }

        # Save to database
        try:
            await _save_operation_to_db(operation_id, result)
        except Exception as e:
            logger.error(f"Failed to save operation to DB: {e}")

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


async def _save_operation_to_db(operation_id: str, result):
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
            total_tokens=result.cost_report.get("total_tokens", 0) if result.cost_report else 0,
            duration_seconds=result.duration_seconds,
            stop_reason=result.stop_reason,
            error_message=result.error,
            artifacts_dir=result.artifacts_dir,
            tool_usage_json=result.tool_usage,
            results_json={"findings": result.findings},
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        db.add(operation)
        await db.commit()


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

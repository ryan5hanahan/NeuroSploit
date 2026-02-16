"""
NeuroSploit v3 - Scans API Endpoints
"""
import asyncio
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from urllib.parse import urlparse

from backend.db.database import get_db
from backend.models import Scan, Target, Endpoint, Vulnerability
from backend.schemas.scan import ScanCreate, ScanUpdate, ScanResponse, ScanListResponse, ScanProgress
from backend.services.scan_service import run_scan_task, skip_to_phase as _skip_to_phase, PHASE_ORDER
from backend.core import scan_registry

router = APIRouter()


# --- Diff helper functions for scan comparison ---

def _vuln_match_key(vuln):
    """Generate a matching key for vulnerability comparison."""
    endpoint = (vuln.affected_endpoint or vuln.url or "").strip().lower()
    param = (vuln.parameter or vuln.poc_parameter or "").strip().lower()
    vtype = (vuln.vulnerability_type or "").strip().lower()
    return (vtype, endpoint, param)


def _endpoint_match_key(endpoint):
    """Generate a matching key for endpoint comparison."""
    return (endpoint.url.strip().lower(), endpoint.method.strip().upper())


def _compute_vulnerability_diff(vulns_a, vulns_b):
    """Compute diff between two sets of vulnerabilities."""
    map_a = {}
    for v in vulns_a:
        key = _vuln_match_key(v)
        map_a[key] = v

    map_b = {}
    for v in vulns_b:
        key = _vuln_match_key(v)
        map_b[key] = v

    new_items = []
    resolved = []
    persistent = []
    changed = []

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    for key in keys_b - keys_a:
        new_items.append(map_b[key].to_dict())

    for key in keys_a - keys_b:
        resolved.append(map_a[key].to_dict())

    for key in keys_a & keys_b:
        va = map_a[key]
        vb = map_b[key]
        severity_changed = va.severity != vb.severity
        cvss_changed = (va.cvss_score or 0) != (vb.cvss_score or 0)

        if severity_changed or cvss_changed:
            entry = vb.to_dict()
            entry["severity_changed"] = {"from": va.severity, "to": vb.severity} if severity_changed else None
            entry["cvss_changed"] = {"from": va.cvss_score, "to": vb.cvss_score} if cvss_changed else None
            changed.append(entry)
        else:
            persistent.append(vb.to_dict())

    return {"new": new_items, "resolved": resolved, "persistent": persistent, "changed": changed}


def _compute_endpoint_diff(endpoints_a, endpoints_b):
    """Compute diff between two sets of endpoints."""
    map_a = {}
    for e in endpoints_a:
        key = _endpoint_match_key(e)
        map_a[key] = e

    map_b = {}
    for e in endpoints_b:
        key = _endpoint_match_key(e)
        map_b[key] = e

    new_items = []
    removed = []
    changed = []
    stable = []

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    for key in keys_b - keys_a:
        new_items.append(map_b[key].to_dict())

    for key in keys_a - keys_b:
        removed.append(map_a[key].to_dict())

    for key in keys_a & keys_b:
        ea = map_a[key]
        eb = map_b[key]
        changes = {}
        if ea.response_status != eb.response_status:
            changes["response_status"] = {"from": ea.response_status, "to": eb.response_status}
        if set(ea.technologies or []) != set(eb.technologies or []):
            changes["technologies"] = {"from": ea.technologies, "to": eb.technologies}
        if (ea.parameters or []) != (eb.parameters or []):
            changes["parameters"] = {"from": ea.parameters, "to": eb.parameters}

        if changes:
            entry = eb.to_dict()
            entry["changes"] = changes
            changed.append(entry)
        else:
            stable.append(eb.to_dict())

    return {"new": new_items, "removed": removed, "changed": changed, "stable": stable}


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    per_page: int = 10,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all scans with pagination"""
    query = select(Scan).order_by(Scan.created_at.desc())

    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = select(func.count()).select_from(Scan)
    if status:
        count_query = count_query.where(Scan.status == status)
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    scans = result.scalars().all()

    # Load targets for each scan
    scan_responses = []
    for scan in scans:
        targets_query = select(Target).where(Target.scan_id == scan.id)
        targets_result = await db.execute(targets_query)
        targets = targets_result.scalars().all()

        scan_dict = scan.to_dict()
        scan_dict["targets"] = [t.to_dict() for t in targets]
        scan_responses.append(ScanResponse(**scan_dict))

    return ScanListResponse(
        scans=scan_responses,
        total=total,
        page=page,
        per_page=per_page
    )


@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new scan with optional authentication for authenticated testing"""
    from backend.api.v1.settings import _settings as app_settings

    # Apply setting defaults when client didn't specify
    scan_type = scan_data.scan_type if scan_data.scan_type is not None else app_settings.get("default_scan_type", "full")
    recon_enabled = scan_data.recon_enabled if scan_data.recon_enabled is not None else app_settings.get("recon_enabled_by_default", True)

    # Process authentication config
    auth_type = None
    auth_credentials = None
    if scan_data.auth:
        auth_type = scan_data.auth.auth_type
        auth_credentials = {}
        if scan_data.auth.cookie:
            auth_credentials["cookie"] = scan_data.auth.cookie
        if scan_data.auth.bearer_token:
            auth_credentials["bearer_token"] = scan_data.auth.bearer_token
        if scan_data.auth.username:
            auth_credentials["username"] = scan_data.auth.username
        if scan_data.auth.password:
            auth_credentials["password"] = scan_data.auth.password
        if scan_data.auth.header_name and scan_data.auth.header_value:
            auth_credentials["header_name"] = scan_data.auth.header_name
            auth_credentials["header_value"] = scan_data.auth.header_value

    # Create scan
    scan = Scan(
        name=scan_data.name or f"Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        scan_type=scan_type,
        recon_enabled=recon_enabled,
        custom_prompt=scan_data.custom_prompt,
        prompt_id=scan_data.prompt_id,
        config=scan_data.config,
        auth_type=auth_type,
        auth_credentials=auth_credentials,
        custom_headers=scan_data.custom_headers,
        status="pending"
    )
    db.add(scan)
    await db.flush()

    # Create targets
    targets = []
    for url in scan_data.targets:
        parsed = urlparse(url)
        target = Target(
            scan_id=scan.id,
            url=url,
            hostname=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            protocol=parsed.scheme or "https",
            path=parsed.path or "/"
        )
        db.add(target)
        targets.append(target)

    await db.commit()
    await db.refresh(scan)

    scan_dict = scan.to_dict()
    scan_dict["targets"] = [t.to_dict() for t in targets]

    return ScanResponse(**scan_dict)


@router.get("/compare/{scan_id_a}/{scan_id_b}")
async def compare_scans(
    scan_id_a: str,
    scan_id_b: str,
    db: AsyncSession = Depends(get_db)
):
    """Compare two scans and return a structured diff"""
    if scan_id_a == scan_id_b:
        raise HTTPException(status_code=400, detail="Cannot compare a scan with itself")

    result_a = await db.execute(select(Scan).where(Scan.id == scan_id_a))
    scan_a = result_a.scalar_one_or_none()
    result_b = await db.execute(select(Scan).where(Scan.id == scan_id_b))
    scan_b = result_b.scalar_one_or_none()

    if not scan_a:
        raise HTTPException(status_code=404, detail=f"Scan A not found: {scan_id_a}")
    if not scan_b:
        raise HTTPException(status_code=404, detail=f"Scan B not found: {scan_id_b}")

    # Load vulnerabilities for both scans
    vulns_a = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id_a)
    )).scalars().all()
    vulns_b = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id_b)
    )).scalars().all()

    # Load endpoints for both scans
    endpoints_a = (await db.execute(
        select(Endpoint).where(Endpoint.scan_id == scan_id_a)
    )).scalars().all()
    endpoints_b = (await db.execute(
        select(Endpoint).where(Endpoint.scan_id == scan_id_b)
    )).scalars().all()

    vuln_diff = _compute_vulnerability_diff(vulns_a, vulns_b)
    endpoint_diff = _compute_endpoint_diff(endpoints_a, endpoints_b)

    def scan_summary(scan):
        return {
            "id": scan.id,
            "name": scan.name,
            "status": scan.status,
            "scan_type": scan.scan_type,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": scan.duration,
            "total_endpoints": scan.total_endpoints,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "info_count": scan.info_count,
        }

    return {
        "summary": {
            "scan_a": scan_summary(scan_a),
            "scan_b": scan_summary(scan_b),
            "vuln_summary": {
                "new": len(vuln_diff["new"]),
                "resolved": len(vuln_diff["resolved"]),
                "persistent": len(vuln_diff["persistent"]),
                "changed": len(vuln_diff["changed"]),
            },
            "endpoint_summary": {
                "new": len(endpoint_diff["new"]),
                "removed": len(endpoint_diff["removed"]),
                "changed": len(endpoint_diff["changed"]),
                "stable": len(endpoint_diff["stable"]),
            },
        },
        "vulnerabilities": vuln_diff,
        "endpoints": endpoint_diff,
    }


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan details by ID"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load targets
    targets_result = await db.execute(select(Target).where(Target.scan_id == scan_id))
    targets = targets_result.scalars().all()

    scan_dict = scan.to_dict()
    scan_dict["targets"] = [t.to_dict() for t in targets]

    return ScanResponse(**scan_dict)


@router.post("/{scan_id}/start")
async def start_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Start a scan execution"""
    from backend.api.v1.settings import _settings as app_settings

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Scan is already running")

    # Enforce MAX_CONCURRENT_SCANS
    max_concurrent = app_settings.get("max_concurrent_scans", 3)
    running_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "running")
    )
    running_count = running_result.scalar() or 0
    if running_count >= max_concurrent:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent scans reached ({max_concurrent}). Stop a running scan first."
        )

    # Update scan status
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    scan.current_phase = "initializing"
    scan.progress = 0
    await db.commit()

    # Register in scan registry BEFORE creating task to avoid race condition
    handle = scan_registry.register(scan_id)
    task = asyncio.create_task(run_scan_task(scan_id))
    handle.task = task

    return {"message": "Scan started", "scan_id": scan_id}


@router.post("/{scan_id}/repeat", response_model=ScanResponse)
async def repeat_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Clone a completed/stopped/failed scan's config and immediately start a new scan"""
    from backend.api.v1.settings import _settings as app_settings

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    original = result.scalar_one_or_none()
    if not original:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Enforce MAX_CONCURRENT_SCANS
    max_concurrent = app_settings.get("max_concurrent_scans", 3)
    running_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "running")
    )
    running_count = running_result.scalar() or 0
    if running_count >= max_concurrent:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent scans reached ({max_concurrent}). Stop a running scan first."
        )

    if original.status not in ("completed", "stopped", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Can only repeat completed, stopped, or failed scans. Current status: {original.status}"
        )

    # Load original targets
    targets_result = await db.execute(select(Target).where(Target.scan_id == scan_id))
    original_targets = targets_result.scalars().all()
    if not original_targets:
        raise HTTPException(status_code=400, detail="Original scan has no targets")

    # Create new scan cloning config
    new_scan = Scan(
        name=f"Repeat: {original.name or 'Unnamed Scan'}",
        scan_type=original.scan_type,
        recon_enabled=original.recon_enabled,
        custom_prompt=original.custom_prompt,
        prompt_id=original.prompt_id,
        config=original.config or {},
        auth_type=original.auth_type,
        auth_credentials=original.auth_credentials,
        custom_headers=original.custom_headers,
        repeated_from_id=original.id,
        status="pending"
    )
    db.add(new_scan)
    await db.flush()

    # Clone targets
    new_targets = []
    for t in original_targets:
        new_target = Target(
            scan_id=new_scan.id,
            url=t.url,
            hostname=t.hostname,
            port=t.port,
            protocol=t.protocol,
            path=t.path
        )
        db.add(new_target)
        new_targets.append(new_target)

    await db.commit()
    await db.refresh(new_scan)

    # Auto-start the new scan
    new_scan.status = "running"
    new_scan.started_at = datetime.utcnow()
    new_scan.current_phase = "initializing"
    new_scan.progress = 0
    await db.commit()

    # Register in scan registry BEFORE creating task to avoid race condition
    handle = scan_registry.register(new_scan.id)
    task = asyncio.create_task(run_scan_task(new_scan.id))
    handle.task = task

    scan_dict = new_scan.to_dict()
    scan_dict["targets"] = [t.to_dict() for t in new_targets]
    return ScanResponse(**scan_dict)


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Stop a running scan and save partial results"""
    from backend.api.websocket import manager as ws_manager
    from backend.api.v1.agent import scan_to_agent, agent_instances, agent_results

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("running", "paused"):
        raise HTTPException(status_code=400, detail="Scan is not running or paused")

    # Cancel via scan registry (handles both ScanService and Agent paths)
    scan_registry.cancel(scan_id)

    # Also signal the agent instance directly for backward compatibility
    agent_id = scan_to_agent.get(scan_id)
    if agent_id and agent_id in agent_instances:
        agent_instances[agent_id].cancel()
        if agent_id in agent_results:
            agent_results[agent_id]["status"] = "stopped"
            agent_results[agent_id]["phase"] = "stopped"

    # Update scan status
    scan.status = "stopped"
    scan.completed_at = datetime.utcnow()
    scan.current_phase = "stopped"

    # Calculate duration
    if scan.started_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()
        scan.duration = int(duration)

    # Compute final vulnerability statistics from database
    for severity in ["critical", "high", "medium", "low", "info"]:
        count_result = await db.execute(
            select(func.count()).select_from(Vulnerability)
            .where(Vulnerability.scan_id == scan_id)
            .where(Vulnerability.severity == severity)
        )
        setattr(scan, f"{severity}_count", count_result.scalar() or 0)

    # Get total vulnerability count
    total_vuln_result = await db.execute(
        select(func.count()).select_from(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
    )
    scan.total_vulnerabilities = total_vuln_result.scalar() or 0

    # Get total endpoint count
    total_endpoint_result = await db.execute(
        select(func.count()).select_from(Endpoint)
        .where(Endpoint.scan_id == scan_id)
    )
    scan.total_endpoints = total_endpoint_result.scalar() or 0

    await db.commit()

    # Build summary for WebSocket broadcast
    summary = {
        "total_endpoints": scan.total_endpoints,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "info": scan.info_count,
        "duration": scan.duration,
        "progress": scan.progress
    }

    # Broadcast stop event via WebSocket
    await ws_manager.broadcast_scan_stopped(scan_id, summary)
    await ws_manager.broadcast_log(scan_id, "warning", "Scan stopped by user")
    await ws_manager.broadcast_log(scan_id, "info", f"Partial results: {scan.total_vulnerabilities} vulnerabilities found")

    # Auto-generate partial report
    report_data = None
    try:
        from backend.services.report_service import auto_generate_report
        await ws_manager.broadcast_log(scan_id, "info", "Generating partial report...")
        report = await auto_generate_report(db, scan_id, is_partial=True)
        report_data = report.to_dict()
        await ws_manager.broadcast_log(scan_id, "info", f"Partial report generated: {report.title}")
    except Exception as report_error:
        await ws_manager.broadcast_log(scan_id, "warning", f"Failed to generate partial report: {str(report_error)}")

    return {
        "message": "Scan stopped",
        "scan_id": scan_id,
        "summary": summary,
        "report": report_data
    }


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Pause a running scan"""
    from backend.api.websocket import manager as ws_manager
    from backend.api.v1.agent import scan_to_agent, agent_instances, agent_results

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    # Signal the agent to pause
    agent_id = scan_to_agent.get(scan_id)
    if agent_id and agent_id in agent_instances:
        agent_instances[agent_id].pause()
        if agent_id in agent_results:
            agent_results[agent_id]["status"] = "paused"
            agent_results[agent_id]["phase"] = "paused"

    scan.status = "paused"
    scan.current_phase = "paused"
    await db.commit()

    await ws_manager.broadcast_log(scan_id, "warning", "Scan paused by user")

    return {"message": "Scan paused", "scan_id": scan_id}


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Resume a paused scan"""
    from backend.api.websocket import manager as ws_manager
    from backend.api.v1.agent import scan_to_agent, agent_instances, agent_results

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "paused":
        raise HTTPException(status_code=400, detail="Scan is not paused")

    # Signal the agent to resume
    agent_id = scan_to_agent.get(scan_id)
    if agent_id and agent_id in agent_instances:
        agent_instances[agent_id].resume()
        if agent_id in agent_results:
            agent_results[agent_id]["status"] = "running"
            agent_results[agent_id]["phase"] = "testing"

    scan.status = "running"
    scan.current_phase = "testing"
    await db.commit()

    await ws_manager.broadcast_log(scan_id, "info", "Scan resumed by user")

    return {"message": "Scan resumed", "scan_id": scan_id}


@router.post("/{scan_id}/skip-to/{target_phase}")
async def skip_to_phase_endpoint(scan_id: str, target_phase: str, db: AsyncSession = Depends(get_db)):
    """Skip the current scan phase and jump to a target phase.

    Valid phases: recon, analyzing, testing, completed
    Can only skip forward (to a phase ahead of current).
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("running", "paused"):
        raise HTTPException(status_code=400, detail="Scan is not running or paused")

    # If paused, resume first so the skip can be processed
    if scan.status == "paused":
        from backend.api.v1.agent import scan_to_agent, agent_instances, agent_results
        agent_id = scan_to_agent.get(scan_id)
        if agent_id and agent_id in agent_instances:
            agent_instances[agent_id].resume()
            if agent_id in agent_results:
                agent_results[agent_id]["status"] = "running"
                agent_results[agent_id]["phase"] = agent_results[agent_id].get("last_phase", "testing")
        scan.status = "running"
        await db.commit()

    if target_phase not in PHASE_ORDER:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid phase '{target_phase}'. Valid: {', '.join(PHASE_ORDER[1:])}"
        )

    # Validate forward skip
    current_idx = PHASE_ORDER.index(scan.current_phase) if scan.current_phase in PHASE_ORDER else 0
    target_idx = PHASE_ORDER.index(target_phase)

    if target_idx <= current_idx:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot skip backward. Current: {scan.current_phase}, target: {target_phase}"
        )

    # Signal the running scan to skip
    success = _skip_to_phase(scan_id, target_phase)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to signal phase skip")

    # Broadcast via WebSocket
    from backend.api.websocket import manager as ws_manager
    await ws_manager.broadcast_log(scan_id, "warning", f">> User requested skip to phase: {target_phase}")
    await ws_manager.broadcast_phase_change(scan_id, f"skipping_to_{target_phase}")

    return {
        "message": f"Skipping to phase: {target_phase}",
        "scan_id": scan_id,
        "from_phase": scan.current_phase,
        "target_phase": target_phase
    }


@router.get("/{scan_id}/status", response_model=ScanProgress)
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan progress and status"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanProgress(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        current_phase=scan.current_phase,
        total_endpoints=scan.total_endpoints,
        total_vulnerabilities=scan.total_vulnerabilities
    )


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Cannot delete running scan")

    await db.delete(scan)
    await db.commit()

    return {"message": "Scan deleted", "scan_id": scan_id}


@router.get("/{scan_id}/endpoints")
async def get_scan_endpoints(
    scan_id: str,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """Get endpoints discovered in a scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Endpoint).where(Endpoint.scan_id == scan_id).order_by(Endpoint.discovered_at.desc())

    # Count
    count_result = await db.execute(select(func.count()).select_from(Endpoint).where(Endpoint.scan_id == scan_id))
    total = count_result.scalar()

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    endpoints = result.scalars().all()

    return {
        "endpoints": [e.to_dict() for e in endpoints],
        "total": total,
        "page": page,
        "per_page": per_page
    }


@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """Get vulnerabilities found in a scan"""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Vulnerability).where(Vulnerability.scan_id == scan_id)

    if severity:
        query = query.where(Vulnerability.severity == severity)

    query = query.order_by(Vulnerability.created_at.desc())

    # Count
    count_query = select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == scan_id)
    if severity:
        count_query = count_query.where(Vulnerability.severity == severity)
    count_result = await db.execute(count_query)
    total = count_result.scalar()

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()

    return {
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "total": total,
        "page": page,
        "per_page": per_page
    }


class ValidationRequest(BaseModel):
    validation_status: str  # "validated" | "false_positive" | "ai_confirmed" | "ai_rejected" | "pending_review"
    notes: Optional[str] = None


@router.patch("/vulnerabilities/{vuln_id}/validate")
async def validate_vulnerability(
    vuln_id: str,
    body: ValidationRequest,
    db: AsyncSession = Depends(get_db)
):
    """Manually validate or reject a vulnerability finding"""
    valid_statuses = {"validated", "false_positive", "ai_confirmed", "ai_rejected", "pending_review"}
    if body.validation_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}")

    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    old_status = vuln.validation_status or "ai_confirmed"
    vuln.validation_status = body.validation_status
    if body.notes:
        vuln.ai_rejection_reason = body.notes

    # Update scan severity counts when validation status changes
    scan_result = await db.execute(select(Scan).where(Scan.id == vuln.scan_id))
    scan = scan_result.scalar_one_or_none()

    if scan:
        sev = vuln.severity
        # If changing from rejected to validated: add to counts
        if old_status == "ai_rejected" and body.validation_status == "validated":
            scan.total_vulnerabilities = (scan.total_vulnerabilities or 0) + 1
            if sev == "critical":
                scan.critical_count = (scan.critical_count or 0) + 1
            elif sev == "high":
                scan.high_count = (scan.high_count or 0) + 1
            elif sev == "medium":
                scan.medium_count = (scan.medium_count or 0) + 1
            elif sev == "low":
                scan.low_count = (scan.low_count or 0) + 1
            elif sev == "info":
                scan.info_count = (scan.info_count or 0) + 1
        # If changing from confirmed to false_positive: subtract from counts
        elif old_status in ("ai_confirmed", "validated") and body.validation_status == "false_positive":
            scan.total_vulnerabilities = max(0, (scan.total_vulnerabilities or 0) - 1)
            if sev == "critical":
                scan.critical_count = max(0, (scan.critical_count or 0) - 1)
            elif sev == "high":
                scan.high_count = max(0, (scan.high_count or 0) - 1)
            elif sev == "medium":
                scan.medium_count = max(0, (scan.medium_count or 0) - 1)
            elif sev == "low":
                scan.low_count = max(0, (scan.low_count or 0) - 1)
            elif sev == "info":
                scan.info_count = max(0, (scan.info_count or 0) - 1)

    await db.commit()

    return {"message": "Vulnerability validation updated", "vulnerability": vuln.to_dict()}

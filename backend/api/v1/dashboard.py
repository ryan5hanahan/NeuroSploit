"""
NeuroSploit v3 - Dashboard API Endpoints
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, cast, Date
from datetime import datetime, timedelta

from backend.db.database import get_db
from backend.models import Scan, Vulnerability, Endpoint, AgentTask, Report
from backend.models.memory import AgentOperation

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get overall dashboard statistics"""
    # Total scans
    total_scans_result = await db.execute(select(func.count()).select_from(Scan))
    total_scans = total_scans_result.scalar() or 0

    # Scans by status
    running_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "running")
    )
    running_scans = running_result.scalar() or 0

    completed_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "completed")
    )
    completed_scans = completed_result.scalar() or 0

    stopped_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "stopped")
    )
    stopped_scans = stopped_result.scalar() or 0

    failed_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "failed")
    )
    failed_scans = failed_result.scalar() or 0

    pending_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "pending")
    )
    pending_scans = pending_result.scalar() or 0

    # Total vulnerabilities by severity
    vuln_counts = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        result = await db.execute(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == severity)
        )
        vuln_counts[severity] = result.scalar() or 0

    total_vulns = sum(vuln_counts.values())

    # Total endpoints
    endpoints_result = await db.execute(select(func.count()).select_from(Endpoint))
    total_endpoints = endpoints_result.scalar() or 0

    # Recent activity (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_scans_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.created_at >= week_ago)
    )
    recent_scans = recent_scans_result.scalar() or 0

    recent_vulns_result = await db.execute(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.created_at >= week_ago)
    )
    recent_vulns = recent_vulns_result.scalar() or 0

    # Trend data: findings per day for last 7 days
    findings_by_day = []
    for i in range(6, -1, -1):
        day_start = (datetime.utcnow() - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_result = await db.execute(
            select(func.count()).select_from(Vulnerability).where(
                Vulnerability.created_at >= day_start,
                Vulnerability.created_at < day_end
            )
        )
        findings_by_day.append(day_result.scalar() or 0)

    # Total cost from agent operations
    cost_result = await db.execute(
        select(func.coalesce(func.sum(AgentOperation.total_cost_usd), 0.0))
    )
    total_cost = cost_result.scalar() or 0.0

    # Agent operation counts
    agent_running_result = await db.execute(
        select(func.count()).select_from(AgentOperation).where(AgentOperation.status == "running")
    )
    agent_running = agent_running_result.scalar() or 0

    agent_completed_result = await db.execute(
        select(func.count()).select_from(AgentOperation).where(AgentOperation.status == "completed")
    )
    agent_completed = agent_completed_result.scalar() or 0

    agent_stopped_result = await db.execute(
        select(func.count()).select_from(AgentOperation).where(
            AgentOperation.status.in_(["stopped", "error"])
        )
    )
    agent_stopped = agent_stopped_result.scalar() or 0

    return {
        "scans": {
            "total": total_scans,
            "running": running_scans,
            "completed": completed_scans,
            "stopped": stopped_scans,
            "failed": failed_scans,
            "pending": pending_scans,
            "recent": recent_scans
        },
        "vulnerabilities": {
            "total": total_vulns,
            "critical": vuln_counts["critical"],
            "high": vuln_counts["high"],
            "medium": vuln_counts["medium"],
            "low": vuln_counts["low"],
            "info": vuln_counts["info"],
            "recent": recent_vulns
        },
        "endpoints": {
            "total": total_endpoints
        },
        "operations": {
            "running": agent_running,
            "completed": agent_completed,
            "stopped": agent_stopped,
        },
        "trend": {
            "period_days": 7,
            "findings_by_day": findings_by_day,
            "net_new_findings": sum(findings_by_day),
            "total_cost_usd": round(total_cost, 4),
        }
    }


@router.get("/live-operations")
async def get_live_operations(
    limit: int = 5,
    db: AsyncSession = Depends(get_db)
):
    """Get unified list of recent agent operations + scans, running items first."""
    items = []

    # Agent operations (most recent)
    ops_result = await db.execute(
        select(AgentOperation)
        .order_by(
            case((AgentOperation.status == "running", 0), else_=1),
            AgentOperation.created_at.desc()
        )
        .limit(limit)
    )
    for op in ops_result.scalars().all():
        progress = 0
        progress_label = op.status
        if op.max_steps and op.max_steps > 0:
            progress = min(round((op.steps_used or 0) / op.max_steps * 100), 100)
            progress_label = f"{op.steps_used}/{op.max_steps} steps"
        if op.status == "completed":
            progress = 100

        items.append({
            "id": op.id,
            "type": "agent",
            "target": op.target,
            "status": op.status,
            "objective": op.objective,
            "progress": progress,
            "progress_label": progress_label,
            "findings_count": op.findings_count or 0,
            "severity_breakdown": {
                "critical": op.critical_count or 0,
                "high": op.high_count or 0,
                "medium": op.medium_count or 0,
                "low": op.low_count or 0,
                "info": op.info_count or 0,
            },
            "duration_seconds": op.duration_seconds or 0,
            "started_at": op.started_at.isoformat() if op.started_at else op.created_at.isoformat(),
            "completed_at": op.completed_at.isoformat() if op.completed_at else None,
            "cost_usd": round(op.total_cost_usd or 0, 4),
        })

    # Recent scans
    scans_result = await db.execute(
        select(Scan)
        .order_by(
            case((Scan.status == "running", 0), else_=1),
            Scan.created_at.desc()
        )
        .limit(limit)
    )
    for scan in scans_result.scalars().all():
        # Get finding severity counts for this scan
        sev_counts = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_result = await db.execute(
                select(func.count()).select_from(Vulnerability).where(
                    Vulnerability.scan_id == scan.id,
                    Vulnerability.severity == sev
                )
            )
            sev_counts[sev] = sev_result.scalar() or 0

        duration = scan.duration or 0
        if scan.status == "running" and scan.started_at:
            duration = int((datetime.utcnow() - scan.started_at).total_seconds())

        items.append({
            "id": scan.id,
            "type": "scan",
            "target": scan.name or (scan.targets[0].url if hasattr(scan, 'targets') and scan.targets else "Unknown"),
            "status": scan.status,
            "objective": f"{scan.scan_type} scan",
            "progress": scan.progress or 0,
            "progress_label": scan.current_phase or scan.status,
            "findings_count": scan.total_vulnerabilities or 0,
            "severity_breakdown": sev_counts,
            "duration_seconds": duration,
            "started_at": scan.started_at.isoformat() if scan.started_at else scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "cost_usd": 0,
        })

    # Sort: running first, then by started_at desc
    def sort_key(item):
        is_running = 0 if item["status"] == "running" else 1
        return (is_running, item["started_at"])

    items.sort(key=sort_key)
    # For non-running, reverse the time sort (newest first)
    running = [i for i in items if i["status"] == "running"]
    non_running = sorted(
        [i for i in items if i["status"] != "running"],
        key=lambda x: x["started_at"],
        reverse=True
    )
    items = running + non_running

    return {
        "operations": items[:limit],
        "total": len(items),
    }


@router.get("/attention")
async def get_attention_required(
    limit: int = 10,
    db: AsyncSession = Depends(get_db)
):
    """Get unreviewed high/critical findings that need attention."""
    # Count total unreviewed
    count_result = await db.execute(
        select(func.count()).select_from(Vulnerability).where(
            Vulnerability.severity.in_(["critical", "high"]),
            Vulnerability.validation_status != "dismissed",
        )
    )
    total_unreviewed = count_result.scalar() or 0

    # Fetch findings
    query = (
        select(Vulnerability)
        .where(
            Vulnerability.severity.in_(["critical", "high"]),
            Vulnerability.validation_status != "dismissed",
        )
        .order_by(
            case((Vulnerability.severity == "critical", 0), else_=1),
            Vulnerability.created_at.desc()
        )
        .limit(limit)
    )
    result = await db.execute(query)
    vulns = result.scalars().all()

    findings = []
    for v in vulns:
        findings.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "vulnerability_type": v.vulnerability_type,
            "target": v.url or v.affected_endpoint or "",
            "endpoint": v.affected_endpoint or "",
            "scan_id": v.scan_id,
            "validation_status": v.validation_status,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        })

    return {
        "findings": findings,
        "total_unreviewed": total_unreviewed,
    }


@router.post("/attention/{vuln_id}/dismiss")
async def dismiss_finding(
    vuln_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Dismiss a finding (sets validation_status to 'dismissed')."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.validation_status = "dismissed"
    await db.commit()

    return {"id": vuln_id, "validation_status": "dismissed", "message": "Finding dismissed"}


@router.get("/recent")
async def get_recent_activity(
    limit: int = 10,
    db: AsyncSession = Depends(get_db)
):
    """Get recent scan activity"""
    # Recent scans
    scans_query = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    scans_result = await db.execute(scans_query)
    recent_scans = scans_result.scalars().all()

    # Recent vulnerabilities
    vulns_query = select(Vulnerability).order_by(Vulnerability.created_at.desc()).limit(limit)
    vulns_result = await db.execute(vulns_query)
    recent_vulns = vulns_result.scalars().all()

    return {
        "recent_scans": [s.to_dict() for s in recent_scans],
        "recent_vulnerabilities": [v.to_dict() for v in recent_vulns]
    }


@router.get("/findings")
async def get_recent_findings(
    limit: int = 20,
    severity: str = None,
    db: AsyncSession = Depends(get_db)
):
    """Get recent vulnerability findings"""
    query = select(Vulnerability).order_by(Vulnerability.created_at.desc())

    if severity:
        query = query.where(Vulnerability.severity == severity)

    query = query.limit(limit)
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()

    return {
        "findings": [v.to_dict() for v in vulnerabilities],
        "total": len(vulnerabilities)
    }


@router.get("/vulnerability-types")
async def get_vulnerability_distribution(db: AsyncSession = Depends(get_db)):
    """Get vulnerability distribution by type"""
    query = select(
        Vulnerability.vulnerability_type,
        func.count(Vulnerability.id).label("count")
    ).group_by(Vulnerability.vulnerability_type)

    result = await db.execute(query)
    distribution = result.all()

    return {
        "distribution": [
            {"type": row[0], "count": row[1]}
            for row in distribution
        ]
    }


@router.get("/scan-history")
async def get_scan_history(
    days: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """Get scan history for charts"""
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get scans grouped by date
    scans = await db.execute(
        select(Scan).where(Scan.created_at >= start_date).order_by(Scan.created_at)
    )
    all_scans = scans.scalars().all()

    # Group by date
    history = {}
    for scan in all_scans:
        date_str = scan.created_at.strftime("%Y-%m-%d")
        if date_str not in history:
            history[date_str] = {
                "date": date_str,
                "scans": 0,
                "vulnerabilities": 0,
                "critical": 0,
                "high": 0
            }
        history[date_str]["scans"] += 1
        history[date_str]["vulnerabilities"] += scan.total_vulnerabilities
        history[date_str]["critical"] += scan.critical_count
        history[date_str]["high"] += scan.high_count

    return {"history": list(history.values())}


@router.get("/agent-tasks")
async def get_recent_agent_tasks(
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    """Get recent agent tasks across all scans"""
    query = (
        select(AgentTask)
        .order_by(AgentTask.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    tasks = result.scalars().all()

    return {
        "agent_tasks": [t.to_dict() for t in tasks],
        "total": len(tasks)
    }


@router.get("/activity-feed")
async def get_activity_feed(
    limit: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """Get unified activity feed with all recent events"""
    activities = []

    # Get recent scans
    scans_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit // 3)
    )
    for scan in scans_result.scalars().all():
        activities.append({
            "type": "scan",
            "action": f"Scan {scan.status}",
            "title": scan.name or "Unnamed Scan",
            "description": f"{scan.total_vulnerabilities} vulnerabilities found",
            "status": scan.status,
            "severity": None,
            "timestamp": scan.created_at.isoformat(),
            "scan_id": scan.id,
            "link": f"/scan/{scan.id}"
        })

    # Get recent vulnerabilities (join with Scan to exclude orphaned records)
    vulns_result = await db.execute(
        select(Vulnerability)
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .order_by(Vulnerability.created_at.desc())
        .limit(limit // 3)
    )
    for vuln in vulns_result.scalars().all():
        activities.append({
            "type": "vulnerability",
            "action": "Vulnerability found",
            "title": vuln.title,
            "description": vuln.affected_endpoint or "",
            "status": None,
            "severity": vuln.severity,
            "timestamp": vuln.created_at.isoformat(),
            "scan_id": vuln.scan_id,
            "link": f"/scan/{vuln.scan_id}"
        })

    # Get recent agent tasks (join with Scan to exclude orphaned tasks)
    tasks_result = await db.execute(
        select(AgentTask)
        .join(Scan, AgentTask.scan_id == Scan.id)
        .order_by(AgentTask.created_at.desc())
        .limit(limit // 3)
    )
    for task in tasks_result.scalars().all():
        activities.append({
            "type": "agent_task",
            "action": f"Task {task.status}",
            "title": task.task_name,
            "description": task.result_summary or task.description or "",
            "status": task.status,
            "severity": None,
            "timestamp": task.created_at.isoformat(),
            "scan_id": task.scan_id,
            "link": f"/scan/{task.scan_id}"
        })

    # Get recent reports
    reports_result = await db.execute(
        select(Report).order_by(Report.generated_at.desc()).limit(limit // 4)
    )
    for report in reports_result.scalars().all():
        activities.append({
            "type": "report",
            "action": "Report generated" if report.auto_generated else "Report created",
            "title": report.title or "Report",
            "description": f"{report.format.upper()} format",
            "status": "auto" if report.auto_generated else "manual",
            "severity": None,
            "timestamp": report.generated_at.isoformat(),
            "scan_id": report.scan_id,
            "link": f"/reports"
        })

    # Sort all activities by timestamp (newest first)
    activities.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "activities": activities[:limit],
        "total": len(activities)
    }

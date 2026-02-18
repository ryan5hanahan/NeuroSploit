"""
NeuroSploit v3 - Governance API Endpoints

Query governance violations and enforcement stats for a scan.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.db.database import get_db
from backend.models import Scan, GovernanceViolationRecord

router = APIRouter()


@router.get("/scans/{scan_id}/governance/violations")
async def list_governance_violations(
    scan_id: str,
    layer: Optional[str] = None,
    disposition: Optional[str] = None,
    page: int = 1,
    per_page: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """List governance violations for a scan.

    Optional filters:
      - layer: "scope" or "phase"
      - disposition: "blocked" or "warned"
    """
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(GovernanceViolationRecord).where(
        GovernanceViolationRecord.scan_id == scan_id
    )

    if layer:
        query = query.where(GovernanceViolationRecord.layer == layer)
    if disposition:
        query = query.where(GovernanceViolationRecord.disposition == disposition)

    query = query.order_by(GovernanceViolationRecord.created_at.desc())

    # Count
    count_query = select(func.count()).select_from(GovernanceViolationRecord).where(
        GovernanceViolationRecord.scan_id == scan_id
    )
    if layer:
        count_query = count_query.where(GovernanceViolationRecord.layer == layer)
    if disposition:
        count_query = count_query.where(GovernanceViolationRecord.disposition == disposition)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    violations = result.scalars().all()

    return {
        "scan_id": scan_id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "violations": [v.to_dict() for v in violations],
    }


@router.get("/scans/{scan_id}/governance/stats")
async def get_governance_stats(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated governance stats for a scan."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Total violations
    total_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.scan_id == scan_id
        )
    )
    total = total_result.scalar() or 0

    # By layer
    scope_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.scan_id == scan_id,
            GovernanceViolationRecord.layer == "scope",
        )
    )
    scope_count = scope_result.scalar() or 0

    phase_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.scan_id == scan_id,
            GovernanceViolationRecord.layer == "phase",
        )
    )
    phase_count = phase_result.scalar() or 0

    # By disposition
    blocked_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.scan_id == scan_id,
            GovernanceViolationRecord.disposition == "blocked",
        )
    )
    blocked_count = blocked_result.scalar() or 0

    warned_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.scan_id == scan_id,
            GovernanceViolationRecord.disposition == "warned",
        )
    )
    warned_count = warned_result.scalar() or 0

    return {
        "scan_id": scan_id,
        "total_violations": total,
        "scope_violations": scope_count,
        "phase_violations": phase_count,
        "blocked": blocked_count,
        "warned": warned_count,
    }

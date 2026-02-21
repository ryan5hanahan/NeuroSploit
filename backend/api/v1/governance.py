"""
sploit.ai - Governance API Endpoints

Query governance violations and enforcement stats for a scan.
Export governance audit trail. List global governance overview.
CRUD for governance profiles.

Router mounted at /api/v1/governance — all paths below are relative to that.
"""
import csv
import io
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, distinct

from backend.db.database import get_db
from backend.models import Scan, GovernanceViolationRecord, GovernanceProfileRecord

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic schemas for governance profiles
# ---------------------------------------------------------------------------

class GovernanceProfileCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = None
    scope_profile: str = "pentest"
    governance_mode: str = "warn"
    allowed_vuln_types: List[str] = []
    include_subdomains: bool = True
    max_recon_depth: str = "medium"
    max_steps: int = 100
    max_duration_seconds: int = 3600
    budget_usd: float = 5.0
    sandbox_fallback_policy: str = "warn"


class GovernanceProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope_profile: Optional[str] = None
    governance_mode: Optional[str] = None
    allowed_vuln_types: Optional[List[str]] = None
    include_subdomains: Optional[bool] = None
    max_recon_depth: Optional[str] = None
    max_steps: Optional[int] = None
    max_duration_seconds: Optional[int] = None
    budget_usd: Optional[float] = None
    sandbox_fallback_policy: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-scan violation endpoints
# Mounted at: /api/v1/governance/violations/{scan_id}
# ---------------------------------------------------------------------------

@router.get("/violations/{scan_id}")
async def list_governance_violations(
    scan_id: str,
    layer: Optional[str] = None,
    disposition: Optional[str] = None,
    action_category: Optional[str] = None,
    page: int = 1,
    per_page: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """List governance violations for a scan.

    Optional filters:
      - layer: "scope" or "phase"
      - disposition: "blocked" or "warned"
      - action_category: filter by action category
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
    if action_category:
        query = query.where(GovernanceViolationRecord.action_category == action_category)

    query = query.order_by(GovernanceViolationRecord.created_at.desc())

    # Count
    count_query = select(func.count()).select_from(GovernanceViolationRecord).where(
        GovernanceViolationRecord.scan_id == scan_id
    )
    if layer:
        count_query = count_query.where(GovernanceViolationRecord.layer == layer)
    if disposition:
        count_query = count_query.where(GovernanceViolationRecord.disposition == disposition)
    if action_category:
        count_query = count_query.where(GovernanceViolationRecord.action_category == action_category)
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


@router.get("/stats/{scan_id}")
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

    # By action category
    cat_query = await db.execute(
        select(
            GovernanceViolationRecord.action_category,
            func.count().label("count"),
        )
        .where(GovernanceViolationRecord.scan_id == scan_id)
        .group_by(GovernanceViolationRecord.action_category)
    )
    by_category = {row[0]: row[1] for row in cat_query.all()}

    return {
        "scan_id": scan_id,
        "total_violations": total,
        "scope_violations": scope_count,
        "phase_violations": phase_count,
        "blocked": blocked_count,
        "warned": warned_count,
        "by_category": by_category,
    }


@router.get("/export/{scan_id}")
async def export_governance_audit(
    scan_id: str,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
):
    """Export full governance audit trail for a scan.

    Supported formats: json, csv
    """
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(GovernanceViolationRecord)
        .where(GovernanceViolationRecord.scan_id == scan_id)
        .order_by(GovernanceViolationRecord.created_at.asc())
    )
    violations = result.scalars().all()
    records = [v.to_dict() for v in violations]

    if format == "csv":
        output = io.StringIO()
        if records:
            writer = csv.DictWriter(output, fieldnames=records[0].keys())
            writer.writeheader()
            for r in records:
                # Flatten complex fields
                row = {k: str(v) if isinstance(v, (dict, list)) else v for k, v in r.items()}
                writer.writerow(row)
        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=governance_{scan_id}.csv"
            },
        )

    # Default: JSON
    return {
        "scan_id": scan_id,
        "total": len(records),
        "violations": records,
    }


# ---------------------------------------------------------------------------
# Global overview
# Mounted at: /api/v1/governance/overview
# ---------------------------------------------------------------------------

@router.get("/overview")
async def governance_overview(
    db: AsyncSession = Depends(get_db),
):
    """Global governance overview — stats across all scans.

    Returns aggregate counts plus recent violations.
    """
    # Total violation count
    total_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord)
    )
    total = total_result.scalar() or 0

    # Count of scans with violations
    scans_result = await db.execute(
        select(func.count(distinct(GovernanceViolationRecord.scan_id)))
        .select_from(GovernanceViolationRecord)
    )
    scans_with_violations = scans_result.scalar() or 0

    # By disposition
    blocked_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.disposition == "blocked"
        )
    )
    blocked = blocked_result.scalar() or 0

    warned_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.disposition == "warned"
        )
    )
    warned = warned_result.scalar() or 0

    # By layer
    scope_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.layer == "scope"
        )
    )
    scope_count = scope_result.scalar() or 0

    phase_result = await db.execute(
        select(func.count()).select_from(GovernanceViolationRecord).where(
            GovernanceViolationRecord.layer == "phase"
        )
    )
    phase_count = phase_result.scalar() or 0

    # Recent violations (last 50)
    recent_result = await db.execute(
        select(GovernanceViolationRecord)
        .order_by(GovernanceViolationRecord.created_at.desc())
        .limit(50)
    )
    recent = [v.to_dict() for v in recent_result.scalars().all()]

    # By action category (global)
    cat_query = await db.execute(
        select(
            GovernanceViolationRecord.action_category,
            func.count().label("count"),
        )
        .group_by(GovernanceViolationRecord.action_category)
    )
    by_category = {row[0]: row[1] for row in cat_query.all()}

    return {
        "total_violations": total,
        "scans_with_violations": scans_with_violations,
        "blocked": blocked,
        "warned": warned,
        "scope_violations": scope_count,
        "phase_violations": phase_count,
        "by_category": by_category,
        "recent_violations": recent,
    }


# ---------------------------------------------------------------------------
# Governance Profiles CRUD
# Mounted at: /api/v1/governance/profiles
# ---------------------------------------------------------------------------

@router.get("/profiles")
async def list_governance_profiles(
    db: AsyncSession = Depends(get_db),
):
    """List all saved governance profiles."""
    result = await db.execute(
        select(GovernanceProfileRecord)
        .order_by(GovernanceProfileRecord.name.asc())
    )
    profiles = result.scalars().all()
    return {"profiles": [p.to_dict() for p in profiles]}


@router.get("/profiles/{profile_id}")
async def get_governance_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a single governance profile by ID."""
    result = await db.execute(
        select(GovernanceProfileRecord).where(GovernanceProfileRecord.id == profile_id)
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile.to_dict()


@router.post("/profiles")
async def create_governance_profile(
    data: GovernanceProfileCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new governance profile."""
    # Check for duplicate name
    existing = await db.execute(
        select(GovernanceProfileRecord).where(GovernanceProfileRecord.name == data.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Profile '{data.name}' already exists")

    profile = GovernanceProfileRecord(
        id=str(uuid.uuid4()),
        name=data.name,
        description=data.description,
        scope_profile=data.scope_profile,
        governance_mode=data.governance_mode,
        allowed_vuln_types=data.allowed_vuln_types,
        include_subdomains=data.include_subdomains,
        max_recon_depth=data.max_recon_depth,
        max_steps=data.max_steps,
        max_duration_seconds=data.max_duration_seconds,
        budget_usd=data.budget_usd,
        sandbox_fallback_policy=data.sandbox_fallback_policy,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return profile.to_dict()


@router.put("/profiles/{profile_id}")
async def update_governance_profile(
    profile_id: str,
    data: GovernanceProfileUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an existing governance profile."""
    result = await db.execute(
        select(GovernanceProfileRecord).where(GovernanceProfileRecord.id == profile_id)
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(profile, key, value)

    await db.commit()
    await db.refresh(profile)
    return profile.to_dict()


@router.delete("/profiles/{profile_id}")
async def delete_governance_profile(
    profile_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a governance profile."""
    result = await db.execute(
        select(GovernanceProfileRecord).where(GovernanceProfileRecord.id == profile_id)
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    await db.delete(profile)
    await db.commit()
    return {"status": "deleted", "id": profile_id}

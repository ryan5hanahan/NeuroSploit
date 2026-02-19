"""
NeuroSploit v3 - Vulnerability Enrichment API

Provides manual enrichment triggers and enrichment data retrieval.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.models.vulnerability import Vulnerability
from backend.services.vuln_enrichment import VulnEnrichmentService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/vulnerabilities/{vuln_id}/enrich")
async def enrich_vulnerability(vuln_id: str, db: AsyncSession = Depends(get_db)):
    """Manually trigger enrichment for a single vulnerability."""
    stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
    row = await db.execute(stmt)
    vuln = row.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    svc = VulnEnrichmentService.get_instance()
    result = await svc.enrich_now(vuln_id)

    return {
        "vulnerability_id": vuln_id,
        "status": "enriched",
        "cve_count": len(result.get("nvd", [])) if isinstance(result, dict) else 0,
        "exploit_count": len(result.get("exploitdb", [])) if isinstance(result, dict) else 0,
    }


@router.post("/scans/{scan_id}/enrich")
async def enrich_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Batch enrich all pending vulnerabilities in a scan."""
    svc = VulnEnrichmentService.get_instance()
    count = await svc.enrich_scan(scan_id)
    return {
        "scan_id": scan_id,
        "enqueued": count,
        "message": f"Enqueued {count} vulnerabilities for enrichment",
    }


@router.get("/vulnerabilities/{vuln_id}/enrichment")
async def get_enrichment(vuln_id: str, db: AsyncSession = Depends(get_db)):
    """Get enrichment data for a vulnerability."""
    stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
    row = await db.execute(stmt)
    vuln = row.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return {
        "vulnerability_id": vuln_id,
        "enrichment_status": vuln.enrichment_status or "pending",
        "enriched_at": vuln.enriched_at.isoformat() if vuln.enriched_at else None,
        "cve_ids": vuln.cve_ids or [],
        "known_exploits": vuln.known_exploits or [],
        "enrichment_data": vuln.enrichment_data,
    }

"""
NeuroSploit v3 - Persistent Memory API Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db, async_session_maker
from backend.core.persistent_memory import PersistentMemory

router = APIRouter()


def _get_memory() -> PersistentMemory:
    return PersistentMemory(async_session_maker)


@router.get("/stats")
async def get_memory_stats():
    """Get persistent memory statistics."""
    mem = _get_memory()
    return await mem.get_stats()


@router.get("/target/{domain}")
async def get_target_memory(domain: str):
    """Get cumulative knowledge about a target domain."""
    mem = _get_memory()
    fp = await mem.get_target_fingerprint(domain)
    if not fp:
        raise HTTPException(status_code=404, detail=f"No memory for domain: {domain}")
    return fp


@router.get("/payloads")
async def get_successful_payloads(
    vuln_type: str = Query(..., description="Vulnerability type"),
    limit: int = Query(20, ge=1, le=100),
):
    """Get highest-success payloads for a vulnerability type."""
    mem = _get_memory()
    return await mem.get_priority_payloads(vuln_type, limit=limit)


@router.get("/vuln-types")
async def get_priority_vuln_types(limit: int = Query(20, ge=1, le=100)):
    """Get vulnerability types ranked by historical success rate."""
    mem = _get_memory()
    return await mem.get_priority_vuln_types(limit=limit)


@router.delete("/clear")
async def clear_memory():
    """Clear all persistent memory data."""
    mem = _get_memory()
    await mem.clear()
    return {"message": "Persistent memory cleared", "status": "success"}

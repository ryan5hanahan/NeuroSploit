"""
sploit.ai - Bug Bounty API Endpoints

HackerOne integration: test connection, list programs, scope checking,
duplicate detection, and draft report generation.
All endpoints gated by enable_bugbounty_integration setting.
"""
import logging
import time
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.v1.settings import _settings
from backend.core.bugbounty import (
    DuplicateDetector,
    H1ReportFormatter,
    HackerOneClient,
    ScopeParser,
)
from backend.db.database import get_db
from backend.models import Vulnerability
from backend.models.bugbounty_submission import BugBountySubmission

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory TTL cache: key -> (expiry_timestamp, data)
# ---------------------------------------------------------------------------
_cache: Dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 300  # 5 minutes


def _cache_get(key: str) -> Any:
    entry = _cache.get(key)
    if entry and entry[0] > time.time():
        return entry[1]
    _cache.pop(key, None)
    return None


def _cache_set(key: str, value: Any) -> None:
    _cache[key] = (time.time() + _CACHE_TTL, value)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_enabled() -> None:
    """Raise 403 if bug bounty integration is disabled."""
    if not _settings.get("enable_bugbounty_integration"):
        raise HTTPException(status_code=403, detail="Bug bounty integration is disabled. Enable it in Settings.")


def _get_h1_client() -> HackerOneClient:
    """Build a HackerOneClient from current settings + env vars."""
    import os
    token = _settings.get("hackerone_api_token") or os.getenv("HACKERONE_API_TOKEN", "")
    username = _settings.get("hackerone_username") or os.getenv("HACKERONE_USERNAME", "")
    return HackerOneClient(api_token=token, username=username)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScopeCheckRequest(BaseModel):
    program_handle: str
    url: str


class DuplicateCheckRequest(BaseModel):
    program_handle: str
    title: str
    vuln_type: str = ""
    endpoint: str = ""
    description: str = ""


class DraftReportRequest(BaseModel):
    vulnerability_id: str
    program_handle: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/test-connection")
async def test_connection():
    """Verify HackerOne credentials by making a lightweight API call."""
    _require_enabled()
    client = _get_h1_client()
    if not client.enabled:
        return {"success": False, "error": "HackerOne username and API token are required. Configure them in Settings."}

    async with aiohttp.ClientSession() as session:
        result = await client.test_connection(session)
    return result


@router.get("/programs")
async def list_programs():
    """List the authenticated user's HackerOne programs (cached 5 min)."""
    _require_enabled()
    client = _get_h1_client()
    if not client.enabled:
        raise HTTPException(status_code=400, detail="HackerOne credentials not configured")

    cached = _cache_get("programs")
    if cached is not None:
        return {"programs": cached}

    async with aiohttp.ClientSession() as session:
        programs = await client.list_programs(session)

    _cache_set("programs", programs)
    return {"programs": programs}


@router.get("/programs/{handle}")
async def get_program(handle: str):
    """Get details for a specific program."""
    _require_enabled()
    client = _get_h1_client()
    if not client.enabled:
        raise HTTPException(status_code=400, detail="HackerOne credentials not configured")

    cache_key = f"program:{handle}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    async with aiohttp.ClientSession() as session:
        program = await client.get_program(handle, session)

    if not program:
        raise HTTPException(status_code=404, detail=f"Program '{handle}' not found")

    _cache_set(cache_key, program)
    return program


@router.get("/programs/{handle}/scope")
async def get_program_scope(handle: str):
    """Get scope assets for a program + summary stats."""
    _require_enabled()
    client = _get_h1_client()
    if not client.enabled:
        raise HTTPException(status_code=400, detail="HackerOne credentials not configured")

    cache_key = f"scope:{handle}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    async with aiohttp.ClientSession() as session:
        scope_data = await client.get_scope(handle, session)

    parser = ScopeParser(scope_data)
    result = {
        "in_scope": scope_data.get("in_scope", []),
        "out_of_scope": scope_data.get("out_of_scope", []),
        "in_scope_count": len(scope_data.get("in_scope", [])),
        "out_of_scope_count": len(scope_data.get("out_of_scope", [])),
        "bounty_eligible_count": len(parser.get_bounty_eligible_domains()),
        "bounty_eligible_domains": parser.get_bounty_eligible_domains(),
    }
    _cache_set(cache_key, result)
    return result


@router.post("/check-scope")
async def check_scope(request: ScopeCheckRequest):
    """Check if a URL is in scope for a program."""
    _require_enabled()
    client = _get_h1_client()
    if not client.enabled:
        raise HTTPException(status_code=400, detail="HackerOne credentials not configured")

    cache_key = f"scope:{request.program_handle}"
    cached = _cache_get(cache_key)

    if cached:
        scope_data = {"in_scope": cached.get("in_scope", []), "out_of_scope": cached.get("out_of_scope", [])}
    else:
        async with aiohttp.ClientSession() as session:
            scope_data = await client.get_scope(request.program_handle, session)

    parser = ScopeParser(scope_data)
    in_scope = parser.is_in_scope(request.url)

    return {
        "url": request.url,
        "program_handle": request.program_handle,
        "in_scope": in_scope,
    }


@router.post("/check-duplicate")
async def check_duplicate(request: DuplicateCheckRequest):
    """Check if a finding might be a duplicate of an existing H1 report."""
    _require_enabled()
    client = _get_h1_client()
    if not client.enabled:
        raise HTTPException(status_code=400, detail="HackerOne credentials not configured")

    async with aiohttp.ClientSession() as session:
        reports = await client.get_reports(request.program_handle, session)

    detector = DuplicateDetector(reports)
    dup = detector.check_duplicate(
        title=request.title,
        vuln_type=request.vuln_type,
        endpoint=request.endpoint,
        description=request.description,
    )

    return {
        "is_duplicate": dup is not None,
        "matching_report": dup,
        "reports_checked": len(reports),
    }


@router.post("/draft-report")
async def draft_report(
    request: DraftReportRequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate an H1 draft report from a stored vulnerability and save as a submission."""
    _require_enabled()

    # Fetch the vulnerability
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == request.vulnerability_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln_dict = vuln.to_dict()

    # Format the draft
    draft = H1ReportFormatter.format_draft(vuln_dict)
    preview = H1ReportFormatter.format_preview_markdown(draft)

    # Save as a BugBountySubmission record
    submission = BugBountySubmission(
        vulnerability_id=request.vulnerability_id,
        program_handle=request.program_handle,
        status="draft",
        draft_title=draft["title"],
        draft_vulnerability_information=draft["vulnerability_information"],
        draft_impact=draft["impact"],
        draft_severity_rating=draft["severity_rating"],
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    return {
        "submission_id": submission.id,
        "draft": draft,
        "preview_markdown": preview,
    }


@router.get("/submissions")
async def list_submissions(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List local bug bounty submission tracking records."""
    _require_enabled()

    result = await db.execute(
        select(BugBountySubmission)
        .order_by(BugBountySubmission.created_at.desc())
        .limit(limit)
    )
    submissions = result.scalars().all()

    return {
        "submissions": [s.to_dict() for s in submissions],
        "total": len(submissions),
    }

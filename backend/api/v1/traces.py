"""
sploit.ai - Trace API Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.models.trace import TraceSpan

router = APIRouter()


@router.get("/scan/{scan_id}")
async def get_trace_by_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get all trace spans for a scan."""
    spans = (
        await db.execute(
            select(TraceSpan)
            .where(TraceSpan.trace_id == scan_id)
            .order_by(TraceSpan.start_time)
        )
    ).scalars().all()

    if not spans:
        raise HTTPException(status_code=404, detail=f"No traces found for scan: {scan_id}")

    total_input = sum(s.input_tokens or 0 for s in spans)
    total_output = sum(s.output_tokens or 0 for s in spans)
    total_duration = sum(s.duration_ms or 0 for s in spans)

    return {
        "trace_id": scan_id,
        "span_count": len(spans),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_duration_ms": total_duration,
        "spans": [
            {
                "id": s.id,
                "parent_id": s.parent_id,
                "name": s.name,
                "type": s.span_type,
                "duration_ms": s.duration_ms,
                "status": s.status,
                "input_tokens": s.input_tokens,
                "output_tokens": s.output_tokens,
                "metadata": s.metadata_json,
                "error": s.error_message,
                "start_time": s.start_time.isoformat() if s.start_time else None,
                "end_time": s.end_time.isoformat() if s.end_time else None,
            }
            for s in spans
        ],
    }


@router.get("/span/{span_id}")
async def get_span_details(span_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed info about a specific span."""
    span = (
        await db.execute(
            select(TraceSpan).where(TraceSpan.id == span_id)
        )
    ).scalar_one_or_none()

    if not span:
        raise HTTPException(status_code=404, detail=f"Span not found: {span_id}")

    # Get children
    children = (
        await db.execute(
            select(TraceSpan)
            .where(TraceSpan.parent_id == span_id)
            .order_by(TraceSpan.start_time)
        )
    ).scalars().all()

    return {
        "id": span.id,
        "trace_id": span.trace_id,
        "parent_id": span.parent_id,
        "name": span.name,
        "type": span.span_type,
        "duration_ms": span.duration_ms,
        "status": span.status,
        "input_tokens": span.input_tokens,
        "output_tokens": span.output_tokens,
        "metadata": span.metadata_json,
        "error": span.error_message,
        "start_time": span.start_time.isoformat() if span.start_time else None,
        "end_time": span.end_time.isoformat() if span.end_time else None,
        "children": [
            {
                "id": c.id,
                "name": c.name,
                "type": c.span_type,
                "duration_ms": c.duration_ms,
                "status": c.status,
            }
            for c in children
        ],
    }


@router.get("/stats")
async def get_trace_stats(db: AsyncSession = Depends(get_db)):
    """Get global tracing statistics."""
    total_spans = (
        await db.execute(select(func.count()).select_from(TraceSpan))
    ).scalar() or 0

    total_traces = (
        await db.execute(
            select(func.count(func.distinct(TraceSpan.trace_id)))
        )
    ).scalar() or 0

    total_input = (
        await db.execute(select(func.sum(TraceSpan.input_tokens)))
    ).scalar() or 0

    total_output = (
        await db.execute(select(func.sum(TraceSpan.output_tokens)))
    ).scalar() or 0

    error_count = (
        await db.execute(
            select(func.count()).select_from(TraceSpan)
            .where(TraceSpan.status == "error")
        )
    ).scalar() or 0

    return {
        "total_traces": total_traces,
        "total_spans": total_spans,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "error_spans": error_count,
    }

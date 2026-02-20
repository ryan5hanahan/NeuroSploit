"""
sploit.ai - Scan Tracer

Structured tracing for agent execution. Each scan gets a trace_id,
and phases/tools/LLM calls get nested spans.

Usage:
    tracer = ScanTracer(scan_id, db_session_factory)
    async with tracer.span("recon", span_type="phase") as s:
        # do work
        s.set_metadata({"subdomains_found": 42})
        async with tracer.span("nmap_scan", span_type="tool", parent=s) as child:
            # nested span
            pass
"""

import logging
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from backend.models.trace import TraceSpan

logger = logging.getLogger(__name__)


class Span:
    """Async context manager for a trace span."""

    def __init__(
        self,
        tracer: 'ScanTracer',
        name: str,
        span_type: str = "generic",
        parent: Optional['Span'] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.tracer = tracer
        self.id = str(uuid.uuid4())
        self.name = name
        self.span_type = span_type
        self.parent_id = parent.id if parent else None
        self._metadata = metadata or {}
        self._start_time: float = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._status = "running"
        self._error: Optional[str] = None

    def set_metadata(self, data: Dict[str, Any]):
        """Add metadata to this span."""
        self._metadata.update(data)

    def record_tokens(self, input_tokens: int = 0, output_tokens: int = 0):
        """Record LLM token usage."""
        self._input_tokens += input_tokens
        self._output_tokens += output_tokens

    async def __aenter__(self):
        self._start_time = time.monotonic()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        elapsed_ms = int((time.monotonic() - self._start_time) * 1000)

        if exc_type:
            self._status = "error"
            self._error = str(exc_val) if exc_val else str(exc_type.__name__)
        else:
            self._status = "completed"

        await self.tracer._persist_span(
            span_id=self.id,
            parent_id=self.parent_id,
            name=self.name,
            span_type=self.span_type,
            metadata=self._metadata,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            start_time=datetime.utcnow(),
            duration_ms=elapsed_ms,
            status=self._status,
            error_message=self._error,
        )
        return False  # Don't suppress exceptions


class ScanTracer:
    """Factory for creating trace spans for a scan."""

    def __init__(self, trace_id: str, db_session_factory):
        """
        Args:
            trace_id: Usually the scan_id
            db_session_factory: async session maker
        """
        self.trace_id = trace_id
        self._session_factory = db_session_factory
        self.enabled = os.getenv('ENABLE_TRACING', 'false').lower() == 'true'

        # Accumulated token counts
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def span(
        self,
        name: str,
        span_type: str = "generic",
        parent: Optional[Span] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Span:
        """Create a new span. Use as async context manager."""
        return Span(self, name, span_type, parent, metadata)

    async def _persist_span(
        self,
        span_id: str,
        parent_id: Optional[str],
        name: str,
        span_type: str,
        metadata: Dict,
        input_tokens: int,
        output_tokens: int,
        start_time: datetime,
        duration_ms: int,
        status: str,
        error_message: Optional[str],
    ):
        """Write a completed span to the database."""
        if not self.enabled:
            return

        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

        try:
            async with self._session_factory() as db:
                span = TraceSpan(
                    id=span_id,
                    trace_id=self.trace_id,
                    parent_id=parent_id,
                    name=name,
                    span_type=span_type,
                    metadata_json=metadata,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    start_time=start_time,
                    end_time=datetime.utcnow(),
                    duration_ms=duration_ms,
                    status=status,
                    error_message=error_message,
                )
                db.add(span)
                await db.commit()
        except Exception as e:
            logger.debug(f"Failed to persist trace span: {e}")

    async def get_summary(self) -> Dict[str, Any]:
        """Get trace summary for this scan."""
        from sqlalchemy import select, func
        try:
            async with self._session_factory() as db:
                spans = (
                    await db.execute(
                        select(TraceSpan)
                        .where(TraceSpan.trace_id == self.trace_id)
                        .order_by(TraceSpan.start_time)
                    )
                ).scalars().all()

                return {
                    "trace_id": self.trace_id,
                    "span_count": len(spans),
                    "total_input_tokens": self.total_input_tokens,
                    "total_output_tokens": self.total_output_tokens,
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
                        }
                        for s in spans
                    ],
                }
        except Exception as e:
            logger.debug(f"Failed to get trace summary: {e}")
            return {"trace_id": self.trace_id, "span_count": 0, "spans": []}

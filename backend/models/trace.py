"""
NeuroSploit v3 - Trace Span Model

Structured tracing for agent decisions, tool calls, and LLM usage.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Float, Integer, DateTime, JSON
from backend.db.database import Base


class TraceSpan(Base):
    """A single span in a trace hierarchy."""
    __tablename__ = "trace_spans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    trace_id = Column(String(36), nullable=False, index=True)  # Groups spans into a trace (usually scan_id)
    parent_id = Column(String(36), index=True)  # Parent span ID for nesting
    name = Column(String(255), nullable=False)  # e.g. "recon", "test_xss", "llm_call"
    span_type = Column(String(50))  # "phase", "tool", "llm", "http", "validation"
    metadata_json = Column(JSON, default=dict)  # Arbitrary key-value metadata
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime)
    duration_ms = Column(Integer)
    status = Column(String(20), default="running")  # "running", "completed", "error"
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

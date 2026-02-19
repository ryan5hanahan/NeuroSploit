"""
NeuroSploit v3 - Persistent Memory Models

Three memory types for cross-session learning:
1. AttackPatternMemory — what worked/failed against which tech stacks
2. TargetFingerprint — cumulative knowledge per domain
3. SuccessfulPayload — high-value payloads indexed by tech+vuln_type
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Float, Integer, Boolean, DateTime, JSON
from backend.db.database import Base


class AttackPatternMemory(Base):
    """Records what attack patterns worked or failed against specific tech stacks."""
    __tablename__ = "attack_pattern_memory"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, index=True)
    vuln_type = Column(String(100), nullable=False, index=True)
    tech_stack = Column(JSON, default=list)  # ["nginx", "react", "express"]
    payload = Column(Text)
    parameter = Column(String(500))
    endpoint = Column(Text)
    success = Column(Boolean, nullable=False)
    confidence = Column(Float, default=0.0)
    severity = Column(String(20))
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class TargetFingerprint(Base):
    """Cumulative knowledge about a specific target domain."""
    __tablename__ = "target_fingerprints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, unique=True, index=True)
    tech_stack = Column(JSON, default=list)
    waf_detected = Column(String(100))
    open_ports = Column(JSON, default=list)
    interesting_paths = Column(JSON, default=list)
    known_vulns = Column(JSON, default=list)  # [{type, endpoint, severity}]
    auth_type = Column(String(50))  # "jwt", "session", "basic", "none"
    scan_count = Column(Integer, default=0)
    last_scanned = Column(DateTime)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SuccessfulPayload(Base):
    """High-value payloads that have been confirmed to work."""
    __tablename__ = "successful_payloads"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vuln_type = Column(String(100), nullable=False, index=True)
    tech_stack_tag = Column(String(255), index=True)  # e.g. "nginx+express" for lookup
    payload = Column(Text, nullable=False)
    parameter = Column(String(500))
    endpoint_pattern = Column(String(500))  # generalized pattern e.g. "/api/users/{id}"
    success_count = Column(Integer, default=1)
    last_success_domain = Column(String(255))
    confidence = Column(Float, default=0.0)
    severity = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ---------------------------------------------------------------------------
# LLM-Driven Agent models (Phase 3)
# ---------------------------------------------------------------------------

class AgentMemoryEntry(Base):
    """Persistent memory entry for the LLM-driven agent.

    Stores observations, findings, hypotheses, and evidence across
    operations for cross-engagement learning. Future engagements
    against the same target automatically load prior context.
    """
    __tablename__ = "agent_memory_entries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    content = Column(Text, nullable=False)
    category = Column(String(50), nullable=False, index=True)
    metadata_json = Column(JSON, nullable=True)
    target = Column(String(255), nullable=False, index=True)
    operation_id = Column(String(36), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "content": self.content,
            "category": self.category,
            "metadata": self.metadata_json,
            "target": self.target,
            "operation_id": self.operation_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AgentOperationPlan(Base):
    """Operation plan with phases and checkpoints.

    Plans persist across operations so future engagements against the
    same target can build on prior progress and context.
    """
    __tablename__ = "agent_operation_plans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    objective = Column(Text, nullable=False)
    phases_json = Column(JSON, nullable=True)
    current_phase = Column(String(100), nullable=True)
    confidence = Column(Float, default=50.0)
    key_findings_json = Column(JSON, nullable=True)
    checkpoints_json = Column(JSON, nullable=True)
    target = Column(String(255), nullable=False, index=True)
    operation_id = Column(String(36), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "objective": self.objective,
            "phases": self.phases_json,
            "current_phase": self.current_phase,
            "confidence": self.confidence,
            "key_findings": self.key_findings_json,
            "target": self.target,
            "operation_id": self.operation_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AgentOperation(Base):
    """Record of an LLM-driven agent operation.

    Stores operation results, metrics, and cost data for tracking
    and cross-engagement learning.
    """
    __tablename__ = "agent_operations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(255), nullable=False, index=True)
    objective = Column(Text, nullable=False)
    status = Column(String(50), default="pending", nullable=False, index=True)
    steps_used = Column(Integer, default=0)
    max_steps = Column(Integer, default=100)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    total_cost_usd = Column(Float, default=0.0)
    total_tokens = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    stop_reason = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    artifacts_dir = Column(String(500), nullable=True)
    config_json = Column(JSON, nullable=True)
    results_json = Column(JSON, nullable=True)
    tool_usage_json = Column(JSON, nullable=True)
    quality_score = Column(Float, nullable=True)
    quality_evaluation_json = Column(JSON, nullable=True)
    plan_phases_json = Column(JSON, nullable=True)
    plan_snapshot = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    decision_log_json = Column(JSON, nullable=True)
    stop_summary = Column(Text, nullable=True)
    cost_report_json = Column(JSON, nullable=True)
    conversation_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "objective": self.objective,
            "status": self.status,
            "steps_used": self.steps_used,
            "max_steps": self.max_steps,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "total_cost_usd": self.total_cost_usd,
            "total_tokens": self.total_tokens,
            "duration_seconds": self.duration_seconds,
            "stop_reason": self.stop_reason,
            "stop_summary": self.stop_summary,
            "error_message": self.error_message,
            "artifacts_dir": self.artifacts_dir,
            "quality_score": self.quality_score,
            "cost_report": self.cost_report_json,
            "decision_log": self.decision_log_json,
            "conversation_path": self.conversation_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

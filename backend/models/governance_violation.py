"""
NeuroSploit v3 - Governance Violation Model

Persists governance enforcement actions (blocked or warned) for audit trails.
Shared by both scope (GovernanceAgent) and phase-action (GovernanceGate) layers.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.db.database import Base
import uuid


class GovernanceViolationRecord(Base):
    """Persisted record of a governance enforcement action."""
    __tablename__ = "governance_violations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE")
    )

    # Which governance layer triggered this
    layer: Mapped[str] = mapped_column(String(10), default="phase")  # "scope" | "phase"

    # Enforcement context
    phase: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    allowed_categories: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    # Context (url, vuln_type, tool args, etc.)
    context: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Outcome
    disposition: Mapped[str] = mapped_column(
        String(20), default="blocked"
    )  # "blocked" | "warned"
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # Indexes
    __table_args__ = (
        Index("idx_gov_violations_scan_id", "scan_id"),
        Index("idx_gov_violations_layer", "layer"),
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "layer": self.layer,
            "phase": self.phase,
            "action": self.action,
            "action_category": self.action_category,
            "allowed_categories": self.allowed_categories,
            "context": self.context,
            "disposition": self.disposition,
            "detail": self.detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

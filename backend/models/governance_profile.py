"""
NeuroSploit v3 - Governance Profile Model

Persists reusable governance configurations (scope profile, mode, budget limits, etc.)
that can be applied to operations.
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, DateTime, Text, JSON, Float, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from backend.db.database import Base
import uuid


class GovernanceProfileRecord(Base):
    """Persisted reusable governance configuration."""
    __tablename__ = "governance_profiles"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Scope settings
    scope_profile: Mapped[str] = mapped_column(String(20), default="pentest")
    governance_mode: Mapped[str] = mapped_column(String(10), default="warn")
    allowed_vuln_types: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, default=True)
    max_recon_depth: Mapped[str] = mapped_column(String(10), default="medium")

    # Budget settings
    max_steps: Mapped[int] = mapped_column(Integer, default=100)
    max_duration_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    budget_usd: Mapped[float] = mapped_column(Float, default=5.0)

    # Sandbox settings
    sandbox_fallback_policy: Mapped[str] = mapped_column(String(10), default="warn")

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "scope_profile": self.scope_profile,
            "governance_mode": self.governance_mode,
            "allowed_vuln_types": self.allowed_vuln_types or [],
            "include_subdomains": self.include_subdomains,
            "max_recon_depth": self.max_recon_depth,
            "max_steps": self.max_steps,
            "max_duration_seconds": self.max_duration_seconds,
            "budget_usd": self.budget_usd,
            "sandbox_fallback_policy": self.sandbox_fallback_policy,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

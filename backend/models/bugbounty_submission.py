"""
NeuroSploit v3 - Bug Bounty Submission Tracking Model
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Float, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.db.database import Base
import uuid


class BugBountySubmission(Base):
    """Tracks draft and submitted bug bounty reports."""
    __tablename__ = "bugbounty_submissions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    program_handle: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft/ready/submitted/triaged/resolved/duplicate
    draft_title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    draft_vulnerability_information: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    draft_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    draft_severity_rating: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    duplicate_check_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    h1_report_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    h1_state: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    bounty_amount: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "program_handle": self.program_handle,
            "status": self.status,
            "draft_title": self.draft_title,
            "draft_impact": self.draft_impact,
            "draft_severity_rating": self.draft_severity_rating,
            "duplicate_check_score": self.duplicate_check_score,
            "h1_report_id": self.h1_report_id,
            "h1_state": self.h1_state,
            "bounty_amount": self.bounty_amount,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

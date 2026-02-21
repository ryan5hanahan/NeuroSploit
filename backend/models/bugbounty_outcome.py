"""Bug Bounty Outcome model — tracks submission results for adaptive learning."""
from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, Float, DateTime, Text
from backend.db.database import Base


class BugBountyOutcome(Base):
    """Records bug bounty submission outcomes for adaptive intelligence."""
    __tablename__ = "bugbounty_outcomes"

    id = Column(String, primary_key=True)
    report_id = Column(String, nullable=False)
    program_handle = Column(String, nullable=False, index=True)
    outcome = Column(String, nullable=False)  # accepted, duplicate, rejected, not_applicable
    vuln_type = Column(String, default="")
    severity = Column(String, default="")
    payout = Column(Float, default=0.0)
    feedback = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

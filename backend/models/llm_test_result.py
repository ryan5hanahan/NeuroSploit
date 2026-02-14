"""
NeuroSploit v3 - LLM Test Result Model
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.db.database import Base
import uuid


class LlmTestResult(Base):
    """Stores results of LLM connection tests"""
    __tablename__ = "llm_test_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    provider: Mapped[str] = mapped_column(String(50))
    model: Mapped[str] = mapped_column(String(200), default="")
    response_time_ms: Mapped[int] = mapped_column(Integer, default=0)
    response_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="")
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "success": self.success,
            "provider": self.provider,
            "model": self.model,
            "response_time_ms": self.response_time_ms,
            "response_preview": self.response_preview,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

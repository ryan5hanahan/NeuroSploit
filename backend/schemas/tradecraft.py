"""
NeuroSploit v3 - Tradecraft Schemas
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class TradecraftCreate(BaseModel):
    """Schema for creating a new TTP"""
    name: str = Field(..., max_length=255)
    content: str = Field(..., min_length=10)
    category: str = Field(..., max_length=50)
    description: Optional[str] = None
    enabled: bool = True


class TradecraftUpdate(BaseModel):
    """Schema for updating a TTP"""
    name: Optional[str] = Field(None, max_length=255)
    content: Optional[str] = Field(None, min_length=10)
    category: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    enabled: Optional[bool] = None


class TradecraftResponse(BaseModel):
    """Schema for TTP response"""
    id: str
    name: str
    description: Optional[str]
    content: str
    category: str
    is_builtin: bool
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TradecraftToggle(BaseModel):
    """Schema for bulk toggle"""
    ids: List[str]
    enabled: bool

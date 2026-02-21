"""Pydantic models for technique YAML schema validation."""
from typing import List, Optional
from pydantic import BaseModel, Field


class Payload(BaseModel):
    """A single payload within a technique."""
    value: str
    description: str = ""
    encoding: str = "none"  # none, url, base64, hex, double_url
    waf_bypass: bool = False


class DetectionPattern(BaseModel):
    """Pattern for detecting successful exploitation."""
    type: str = "string"  # string, regex, status_code, time_based
    value: str
    description: str = ""


class Technique(BaseModel):
    """A complete attack technique with payloads and detection patterns."""
    id: str
    name: str
    vuln_type: str  # Canonical vuln type (matches PayloadGenerator keys)
    description: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    technology: List[str] = Field(default_factory=list)  # e.g., ["php", "mysql"]
    waf_bypass: bool = False
    depth: str = "standard"  # quick, standard, thorough
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    payloads: List[Payload] = Field(default_factory=list)
    detection: List[DetectionPattern] = Field(default_factory=list)

    class Config:
        extra = "allow"

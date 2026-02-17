"""
NeuroSploit v3 - Scan Schemas
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """Authentication configuration for authenticated testing"""
    auth_type: str = Field("none", description="Auth type: none, cookie, header, basic, bearer")
    cookie: Optional[str] = Field(None, description="Session cookie value")
    bearer_token: Optional[str] = Field(None, description="Bearer/JWT token")
    username: Optional[str] = Field(None, description="Username for basic auth")
    password: Optional[str] = Field(None, description="Password for basic auth")
    header_name: Optional[str] = Field(None, description="Custom header name")
    header_value: Optional[str] = Field(None, description="Custom header value")


class CredentialSet(BaseModel):
    """A labeled credential set for multi-context access control testing"""
    label: str = Field(..., description="Role label: 'admin', 'user_alice', 'guest'")
    auth_type: str = Field("none", description="none, cookie, bearer, basic, header, login")
    cookie: Optional[str] = None
    bearer_token: Optional[str] = None
    header_name: Optional[str] = None
    header_value: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    role: str = Field("user", description="user, admin, moderator")


class ScanCreate(BaseModel):
    """Schema for creating a new scan"""
    name: Optional[str] = Field(None, max_length=255, description="Scan name")
    targets: List[str] = Field(..., min_length=1, description="List of target URLs")
    scan_type: Optional[str] = Field(None, description="Scan type: quick, full, custom. Uses DEFAULT_SCAN_TYPE setting if not specified.")
    recon_enabled: Optional[bool] = Field(None, description="Enable reconnaissance phase. Uses RECON_ENABLED_BY_DEFAULT setting if not specified.")
    custom_prompt: Optional[str] = Field(None, max_length=32000, description="Custom prompt (up to 32k tokens)")
    prompt_id: Optional[str] = Field(None, description="ID of preset prompt to use")
    config: dict = Field(default_factory=dict, description="Additional configuration")
    auth: Optional[AuthConfig] = Field(None, description="Authentication configuration")
    custom_headers: Optional[dict] = Field(None, description="Custom HTTP headers to include")
    tradecraft_ids: Optional[List[str]] = Field(None, description="TTP IDs to use for this scan")
    credential_sets: Optional[List[CredentialSet]] = Field(None, description="Multiple credential sets for differential access control testing")


class ScanUpdate(BaseModel):
    """Schema for updating a scan"""
    name: Optional[str] = None
    status: Optional[str] = None
    progress: Optional[int] = None
    current_phase: Optional[str] = None
    error_message: Optional[str] = None


class ScanProgress(BaseModel):
    """Schema for scan progress updates"""
    scan_id: str
    status: str
    progress: int
    current_phase: Optional[str] = None
    message: Optional[str] = None
    total_endpoints: int = 0
    total_vulnerabilities: int = 0


class ScanResponse(BaseModel):
    """Schema for scan response"""
    id: str
    name: Optional[str]
    status: str
    scan_type: str
    recon_enabled: bool
    progress: int
    current_phase: Optional[str]
    config: dict
    custom_prompt: Optional[str]
    prompt_id: Optional[str]
    auth_type: Optional[str] = None
    custom_headers: Optional[dict] = None
    repeated_from_id: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    total_endpoints: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    targets: List[dict] = []

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for list of scans"""
    scans: List[ScanResponse]
    total: int
    page: int = 1
    per_page: int = 10

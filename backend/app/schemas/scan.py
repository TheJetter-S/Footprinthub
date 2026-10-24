# =============================================================================
# FootprintHub — Scan Schemas (Pydantic)
# =============================================================================

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from app.core.ssrf_guard import validate_domain, SSRFError


# ── Request Schemas ─────────────────────────────────────────────────────────

class ScanCreateRequest(BaseModel):
    """Request to start a new scan."""
    domain: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Target domain to scan",
        examples=["example.com"],
    )
    profile: str = Field(
        default="passive",
        description="Scan profile: passive | standard | full",
    )
    authorization_confirmed: bool = Field(
        ...,
        description="User must confirm they are authorized to scan this domain",
    )

    @field_validator("domain")
    @classmethod
    def validate_target_domain(cls, v: str) -> str:
        """Validate and sanitize the domain using the SSRF guard."""
        try:
            return validate_domain(v)
        except SSRFError as e:
            raise ValueError(str(e))

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        allowed = {"passive", "standard", "full"}
        if v.lower() not in allowed:
            raise ValueError(f"Profile must be one of: {allowed}")
        return v.lower()

    @field_validator("authorization_confirmed")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm authorization before scanning. "
                "Only scan domains you own or have explicit written permission to test."
            )
        return v


# ── Response Schemas ────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """Scan details returned to the client."""
    id: str
    domain: str
    profile: str
    status: str
    risk_score: Optional[int]
    authorization_confirmed: bool
    created_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Paginated list of scans."""
    scans: list[ScanResponse]
    total: int
    page: int
    per_page: int


class ModuleResultResponse(BaseModel):
    """Result from a single module."""
    id: str
    module_name: str
    mode: str
    status: str
    data: dict[str, Any]
    error_message: Optional[str]
    duration_seconds: Optional[float]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    """A security finding."""
    id: str
    module_name: str
    severity: str
    title: str
    description: str
    remediation: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanProgressMessage(BaseModel):
    """WebSocket message for scan progress updates."""
    scan_id: str
    module: str
    percent: int
    message: str
    status: str  # running | success | error

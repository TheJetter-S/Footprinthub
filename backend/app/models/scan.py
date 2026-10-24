# =============================================================================
# FootprintHub — Scan Model
# =============================================================================

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base, TimestampMixin):
    """A single reconnaissance scan against a target domain."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    domain: Mapped[str] = mapped_column(
        String(255), index=True, nullable=False,
        comment="Target domain for the scan"
    )
    profile: Mapped[str] = mapped_column(
        String(20), nullable=False, default="passive",
        comment="Scan profile: passive | standard | full"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending",
        comment="Scan status: pending | running | completed | failed | cancelled"
    )
    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="User confirmed authorization to scan this domain"
    )
    client_ip: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True,
        comment="IP address of the client that initiated the scan"
    )
    authorization_ts: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Timestamp when authorization was confirmed"
    )
    risk_score: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True,
        comment="Computed risk score 0-100"
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="scans", lazy="selectin")
    results = relationship("ModuleResult", back_populates="scan", lazy="selectin", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", lazy="selectin", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.domain} [{self.status}]>"

# =============================================================================
# FootprintHub — Shareable Report Model
# =============================================================================

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class ReportShare(Base, TimestampMixin):
    """
    Tokenized, read-only public access grant for a specific reconnaissance scan.
    Can be configured with an expiration date and revoked at any time.
    """

    __tablename__ = "report_shares"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    token: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False,
        comment="Cryptographically secure URL-safe token"
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Expiration timestamp; None means never expires"
    )
    is_revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="Whether the token has been revoked by the owner"
    )
    views_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Total access counter"
    )
    last_viewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Timestamp of most recent access"
    )

    # Relationships
    scan = relationship("Scan", lazy="selectin")
    user = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<ReportShare {self.token[:8]}... scan={self.scan_id} revoked={self.is_revoked}>"


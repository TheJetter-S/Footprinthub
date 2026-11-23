# =============================================================================
# FootprintHub — Public API Key Model
# =============================================================================

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class ApiKey(Base, TimestampMixin):
    """
    Public API key for programmatic access and CLI integration.
    Raw keys are never stored; only the SHA-256 hash is persisted.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="Human-readable label (e.g. CI/CD or CLI)"
    )
    key_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False,
        comment="SHA-256 hash of the full API key"
    )
    key_prefix: Mapped[str] = mapped_column(
        String(16), nullable=False,
        comment="Prefix visible to user (e.g. fph_live_a1b2)"
    )
    scopes: Mapped[str] = mapped_column(
        String(255), nullable=False, default="read,scan",
        comment="Comma-separated permission scopes (e.g. read,scan,admin)"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True,
        comment="Whether the key is active"
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Expiration timestamp; None means never expires"
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Timestamp when the key was last authenticated"
    )

    # Relationships
    user = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<ApiKey {self.name} prefix={self.key_prefix} active={self.is_active}>"


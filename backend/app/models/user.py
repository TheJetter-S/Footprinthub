# =============================================================================
# FootprintHub — User Model
# =============================================================================

import uuid
from typing import Optional

from sqlalchemy import String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class User(Base, TimestampMixin):
    """Registered user account."""

    __tablename__ = "users"

    # Use String(36) for SQLite + PostgreSQL portability (avoids Uuid dialect bugs)
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    encrypted_api_keys: Mapped[Optional[dict]] = mapped_column(
        JSON, nullable=True, default=dict,
        comment="User-provided API keys, encrypted at rest"
    )
    is_active: Mapped[bool] = mapped_column(default=True)

    # Relationships
    scans = relationship("Scan", back_populates="user", lazy="selectin")

    def __repr__(self) -> str:
        return f"<User {self.email}>"

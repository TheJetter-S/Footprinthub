# =============================================================================
# FootprintHub — White-Label Configuration Model
# =============================================================================

import uuid
from typing import Optional

from sqlalchemy import String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class WhiteLabelConfig(Base, TimestampMixin):
    """
    White-label branding settings for PDF reports and public share views.
    """

    __tablename__ = "white_label_configs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )
    company_name: Mapped[str] = mapped_column(
        String(255), nullable=False, default="FootprintHub Security",
        comment="Organization or consultancy name"
    )
    logo_url: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True,
        comment="URL or data URI for custom brand logo"
    )
    accent_color: Mapped[str] = mapped_column(
        String(20), nullable=False, default="#2563eb",
        comment="Primary branding hex color"
    )
    footer_text: Mapped[str] = mapped_column(
        String(500), nullable=False,
        default="Confidential Reconnaissance & Security Assessment Report",
        comment="Footer disclaimer printed on reports"
    )

    # Relationships
    user = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<WhiteLabelConfig {self.company_name}>"


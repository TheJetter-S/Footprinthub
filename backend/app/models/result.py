# =============================================================================
# FootprintHub — Module Result Model
# =============================================================================

import uuid

from sqlalchemy import String, Float, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class ModuleResult(Base, TimestampMixin):
    """Result from a single reconnaissance module execution."""

    __tablename__ = "module_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    module_name: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="Name of the module (dns, subdomains, ssl_tls, etc.)"
    )
    mode: Mapped[str] = mapped_column(
        String(10), nullable=False, default="passive",
        comment="Module mode: passive | active"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending",
        comment="Module status: pending | running | success | partial | error"
    )
    data: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict,
        comment="Structured JSON result from the module"
    )
    error_message: Mapped[str] = mapped_column(
        String(1000), nullable=True,
        comment="Error message if the module failed"
    )
    duration_seconds: Mapped[float] = mapped_column(
        Float, nullable=True,
        comment="How long the module took to execute"
    )

    # Relationships
    scan = relationship("Scan", back_populates="results")

    def __repr__(self) -> str:
        return f"<ModuleResult {self.module_name} [{self.status}]>"

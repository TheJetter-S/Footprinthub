# =============================================================================
# FootprintHub — Finding Audit Log Model
# =============================================================================

import uuid

from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class FindingAuditLog(Base, TimestampMixin):
    """
    Audit log tracking finding lifecycle transitions
    (open -> accepted_risk, false_positive, fixed) with required justification.
    """

    __tablename__ = "finding_audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True
    )
    old_status: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    new_status: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    reason: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Required business or technical justification for status change"
    )

    # Relationships
    finding = relationship("Finding", back_populates="audit_logs")
    user = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<FindingAuditLog {self.finding_id} {self.old_status}->{self.new_status}>"


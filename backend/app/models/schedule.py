# =============================================================================
# FootprintHub — Scheduled Monitoring Model
# =============================================================================

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Schedule(Base, TimestampMixin):
    """
    Scheduled reconnaissance monitoring job for a target domain.
    Fires on a recurring basis (daily, weekly, monthly) and sends alerts on diff.
    """

    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True,
        comment="Target domain to monitor"
    )
    profile: Mapped[str] = mapped_column(
        String(20), nullable=False, default="passive",
        comment="Scan profile: passive | standard | full"
    )
    frequency: Mapped[str] = mapped_column(
        String(20), nullable=False, default="daily",
        comment="Frequency: daily | weekly | monthly"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True,
        comment="Whether the schedule is actively running"
    )
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Last execution timestamp"
    )
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        comment="Next scheduled execution timestamp"
    )

    # Notification channels
    email_alert: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True,
        comment="Send email notifications"
    )
    notification_email: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True,
        comment="Optional override recipient email"
    )
    slack_webhook_url: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True,
        comment="Slack incoming webhook URL (SSRF guarded)"
    )
    generic_webhook_url: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True,
        comment="Custom JSON webhook endpoint (SSRF guarded)"
    )
    notify_on: Mapped[str] = mapped_column(
        String(50), nullable=False, default="changes_only",
        comment="Alert condition: always | changes_only | high_risk_only"
    )

    # Relationships
    user = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Schedule {self.domain} [{self.frequency}] active={self.is_active}>"


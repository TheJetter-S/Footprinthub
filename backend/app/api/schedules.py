# =============================================================================
# FootprintHub — Scheduled Monitoring & Delta API Routes
# =============================================================================

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.delta_engine import DeltaEngine
from app.core.notification_service import NotificationService
from app.core.ssrf_guard import SSRFError, validate_domain
from app.models.finding import Finding
from app.models.result import ModuleResult
from app.models.scan import Scan
from app.models.schedule import Schedule
from app.models.user import User

router = APIRouter(prefix="", tags=["Scheduled Monitoring & Delta"])


class ScheduleCreate(BaseModel):
    domain: str
    profile: str = "passive"
    frequency: str = "daily"  # daily | weekly | monthly
    email_alert: bool = True
    notification_email: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    generic_webhook_url: Optional[str] = None
    notify_on: str = "changes_only"  # always | changes_only | high_risk_only


class ScheduleUpdate(BaseModel):
    is_active: Optional[bool] = None
    frequency: Optional[str] = None
    profile: Optional[str] = None
    email_alert: Optional[bool] = None
    notification_email: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    generic_webhook_url: Optional[str] = None
    notify_on: Optional[str] = None


def _calc_next_run(frequency: str) -> datetime:
    now = datetime.now(timezone.utc)
    if frequency == "weekly":
        return now + timedelta(days=7)
    elif frequency == "monthly":
        return now + timedelta(days=30)
    return now + timedelta(days=1)


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Register a new recurring reconnaissance monitoring schedule."""
    try:
        clean_domain = validate_domain(payload.domain)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Validate webhooks if provided
    if payload.slack_webhook_url:
        try:
            NotificationService.validate_webhook_url(payload.slack_webhook_url)
        except SSRFError as e:
            raise HTTPException(status_code=400, detail=f"Invalid Slack webhook: {e}")

    if payload.generic_webhook_url:
        try:
            NotificationService.validate_webhook_url(payload.generic_webhook_url)
        except SSRFError as e:
            raise HTTPException(status_code=400, detail=f"Invalid generic webhook: {e}")

    freq = payload.frequency.lower()
    if freq not in ("daily", "weekly", "monthly"):
        freq = "daily"

    sched = Schedule(
        user_id=current_user.id,
        domain=clean_domain,
        profile=payload.profile.lower() if payload.profile in ("passive", "standard", "full") else "passive",
        frequency=freq,
        is_active=True,
        next_run_at=_calc_next_run(freq),
        email_alert=payload.email_alert,
        notification_email=payload.notification_email or current_user.email,
        slack_webhook_url=payload.slack_webhook_url,
        generic_webhook_url=payload.generic_webhook_url,
        notify_on=payload.notify_on,
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)

    return {
        "id": sched.id,
        "domain": sched.domain,
        "profile": sched.profile,
        "frequency": sched.frequency,
        "is_active": sched.is_active,
        "next_run_at": sched.next_run_at,
        "email_alert": sched.email_alert,
        "notification_email": sched.notification_email,
        "slack_configured": bool(sched.slack_webhook_url),
        "generic_webhook_configured": bool(sched.generic_webhook_url),
        "notify_on": sched.notify_on,
        "created_at": sched.created_at,
    }


@router.get("/schedules")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all monitoring schedules for the authenticated user."""
    res = await db.execute(
        select(Schedule)
        .where(Schedule.user_id == current_user.id)
        .order_by(desc(Schedule.created_at))
    )
    schedules = res.scalars().all()
    return [
        {
            "id": s.id,
            "domain": s.domain,
            "profile": s.profile,
            "frequency": s.frequency,
            "is_active": s.is_active,
            "last_run_at": s.last_run_at,
            "next_run_at": s.next_run_at,
            "email_alert": s.email_alert,
            "notification_email": s.notification_email,
            "slack_configured": bool(s.slack_webhook_url),
            "generic_webhook_configured": bool(s.generic_webhook_url),
            "notify_on": s.notify_on,
            "created_at": s.created_at,
        }
        for s in schedules
    ]


@router.patch("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a monitoring schedule."""
    res = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.user_id == current_user.id)
    )
    sched = res.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if payload.is_active is not None:
        sched.is_active = payload.is_active
    if payload.frequency is not None and payload.frequency in ("daily", "weekly", "monthly"):
        sched.frequency = payload.frequency
        sched.next_run_at = _calc_next_run(payload.frequency)
    if payload.profile is not None and payload.profile in ("passive", "standard", "full"):
        sched.profile = payload.profile
    if payload.email_alert is not None:
        sched.email_alert = payload.email_alert
    if payload.notification_email is not None:
        sched.notification_email = payload.notification_email
    if payload.notify_on is not None:
        sched.notify_on = payload.notify_on

    if payload.slack_webhook_url is not None:
        if payload.slack_webhook_url.strip():
            try:
                NotificationService.validate_webhook_url(payload.slack_webhook_url)
                sched.slack_webhook_url = payload.slack_webhook_url.strip()
            except SSRFError as e:
                raise HTTPException(status_code=400, detail=f"Invalid Slack webhook: {e}")
        else:
            sched.slack_webhook_url = None

    if payload.generic_webhook_url is not None:
        if payload.generic_webhook_url.strip():
            try:
                NotificationService.validate_webhook_url(payload.generic_webhook_url)
                sched.generic_webhook_url = payload.generic_webhook_url.strip()
            except SSRFError as e:
                raise HTTPException(status_code=400, detail=f"Invalid generic webhook: {e}")
        else:
            sched.generic_webhook_url = None

    await db.commit()
    await db.refresh(sched)
    return {"status": "updated", "id": sched.id, "is_active": sched.is_active}


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a monitoring schedule."""
    res = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.user_id == current_user.id)
    )
    sched = res.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await db.delete(sched)
    await db.commit()
    return {"status": "deleted", "id": schedule_id}


@router.get("/scans/{scan_id}/delta")
async def get_scan_delta(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get detailed changes between this scan and the previous scan of the same domain.
    """
    s_res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    curr_scan = s_res.scalar_one_or_none()
    if not curr_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Fetch prior completed scan for this domain
    prior_res = await db.execute(
        select(Scan)
        .where(
            Scan.domain == curr_scan.domain,
            Scan.user_id == current_user.id,
            Scan.status == "completed",
            Scan.created_at < curr_scan.created_at,
        )
        .order_by(desc(Scan.created_at))
        .limit(1)
    )
    prior_scan = prior_res.scalar_one_or_none()

    delta = DeltaEngine.calculate_delta(curr_scan, prior_scan)
    return {
        "current_scan_id": curr_scan.id,
        "prior_scan_id": prior_scan.id if prior_scan else None,
        "domain": curr_scan.domain,
        "delta": delta,
    }


@router.post("/schedules/{schedule_id}/trigger")
async def trigger_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Manually trigger an immediate execution check and delta notification for a schedule.
    """
    res = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.user_id == current_user.id)
    )
    sched = res.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Find the most recent scan for this domain
    s_res = await db.execute(
        select(Scan)
        .where(Scan.domain == sched.domain, Scan.user_id == current_user.id)
        .order_by(desc(Scan.created_at))
        .limit(2)
    )
    scans = s_res.scalars().all()
    if not scans:
        raise HTTPException(status_code=400, detail="No prior scans exist for this domain. Run a baseline scan first.")

    curr_scan = scans[0]
    prior_scan = scans[1] if len(scans) > 1 else None

    delta = DeltaEngine.calculate_delta(curr_scan, prior_scan)

    scan_dict = {
        "id": curr_scan.id,
        "domain": curr_scan.domain,
        "profile": curr_scan.profile,
        "risk_score": curr_scan.risk_score or 0,
    }

    notification_results = await NotificationService.dispatch_monitoring_alert(
        schedule=sched,
        scan_data=scan_dict,
        delta_data=delta,
    )

    sched.last_run_at = datetime.now(timezone.utc)
    sched.next_run_at = _calc_next_run(sched.frequency)
    await db.commit()

    return {
        "status": "triggered",
        "domain": sched.domain,
        "delta_summary": delta.get("summary"),
        "notifications": notification_results,
    }


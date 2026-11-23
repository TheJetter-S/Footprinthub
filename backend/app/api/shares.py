# =============================================================================
# FootprintHub — Shareable Report Links API Routes
# =============================================================================

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.executive_summary import ExecutiveSummaryGenerator
from app.models.finding import Finding
from app.models.result import ModuleResult
from app.models.scan import Scan
from app.models.share import ReportShare
from app.models.user import User
from app.models.white_label import WhiteLabelConfig

router = APIRouter(prefix="", tags=["Report Sharing"])


class ShareCreateRequest(BaseModel):
    expires_in_days: Optional[int] = 7  # 1, 7, 30, or None (never)


@router.post("/scans/{scan_id}/shares", status_code=status.HTTP_201_CREATED)
async def create_share_link(
    scan_id: str,
    payload: ShareCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a tokenized, read-only public access link for a scan."""
    s_res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = s_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    token = secrets.token_urlsafe(32)
    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)

    share = ReportShare(
        scan_id=scan.id,
        user_id=current_user.id,
        token=token,
        expires_at=expires_at,
        is_revoked=False,
    )
    db.add(share)
    await db.commit()
    await db.refresh(share)

    return {
        "share_id": share.id,
        "token": share.token,
        "scan_id": share.scan_id,
        "expires_at": share.expires_at,
        "is_revoked": share.is_revoked,
        "share_url": f"/public/reports/{share.token}",
        "created_at": share.created_at,
    }


@router.get("/scans/{scan_id}/shares")
async def list_scan_shares(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all share links created for this scan."""
    res = await db.execute(
        select(ReportShare)
        .where(ReportShare.scan_id == scan_id, ReportShare.user_id == current_user.id)
        .order_by(desc(ReportShare.created_at))
    )
    shares = res.scalars().all()
    return [
        {
            "id": s.id,
            "token": s.token,
            "expires_at": s.expires_at,
            "is_revoked": s.is_revoked,
            "views_count": s.views_count,
            "last_viewed_at": s.last_viewed_at,
            "created_at": s.created_at,
        }
        for s in shares
    ]


@router.delete("/shares/{share_token}")
async def revoke_share(
    share_token: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke public access for a share token."""
    res = await db.execute(
        select(ReportShare).where(ReportShare.token == share_token, ReportShare.user_id == current_user.id)
    )
    share = res.scalar_one_or_none()
    if not share:
        raise HTTPException(status_code=404, detail="Share token not found")

    share.is_revoked = True
    await db.commit()
    return {"status": "revoked", "token": share_token}


@router.get("/public/reports/{share_token}")
async def get_public_report(
    share_token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Public read-only reconnaissance report view.
    No authentication required. Validates expiration and revocation.
    """
    res = await db.execute(
        select(ReportShare).where(ReportShare.token == share_token)
    )
    share = res.scalar_one_or_none()
    if not share:
        raise HTTPException(status_code=404, detail="Report share link not found")

    if share.is_revoked:
        raise HTTPException(status_code=403, detail="This share link has been revoked by the owner")

    if share.expires_at and share.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="This share link has expired")

    # Increment view counter
    share.views_count += 1
    share.last_viewed_at = datetime.now(timezone.utc)
    await db.commit()

    # Load scan data
    s_res = await db.execute(select(Scan).where(Scan.id == share.scan_id))
    scan = s_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan data not found")

    # Load white-label configuration of the owner
    wl_res = await db.execute(
        select(WhiteLabelConfig).where(WhiteLabelConfig.user_id == share.user_id)
    )
    wl = wl_res.scalar_one_or_none()
    branding = {
        "company_name": wl.company_name if wl else "FootprintHub Security",
        "logo_url": wl.logo_url if wl else None,
        "accent_color": wl.accent_color if wl else "#2563eb",
        "footer_text": wl.footer_text if wl else "Confidential Security Assessment Report",
    }

    # Generate executive summary
    exec_summary = ExecutiveSummaryGenerator.generate(scan)

    # Format findings (omitting raw user ids or sensitive internal details)
    findings_list = [
        {
            "id": f.id,
            "module_name": f.module_name,
            "severity": f.severity,
            "confidence": getattr(f, "confidence", "likely"),
            "title": f.title,
            "description": f.description,
            "remediation": f.remediation,
            "evidence": getattr(f, "evidence", None),
            "status": getattr(f, "status", "open"),
        }
        for f in scan.findings
        if getattr(f, "status", "open") not in ("accepted_risk", "false_positive")
    ]

    return {
        "branding": branding,
        "domain": scan.domain,
        "profile": scan.profile,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
        "executive_summary": exec_summary,
        "findings": findings_list,
        "is_public_view": True,
    }

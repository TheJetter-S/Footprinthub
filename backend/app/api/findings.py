# =============================================================================
# FootprintHub — Finding Lifecycle Workflow & Integration Routes
# =============================================================================

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.integrations import IntegrationsService
from app.core.risk_engine import RiskEngine
from app.models.finding import Finding
from app.models.finding_audit import FindingAuditLog
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(prefix="/findings", tags=["Findings Workflow & Integrations"])


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="Target status: open | accepted_risk | false_positive | fixed")
    reason: str = Field(..., description="Required justification for status transition")


class IssueExportRequest(BaseModel):
    provider: str = Field("github", description="Target tracker: github | jira")
    repo: Optional[str] = None
    token: Optional[str] = None
    jira_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_token: Optional[str] = None
    project_key: Optional[str] = "SEC"


VALID_STATUSES = {"open", "accepted_risk", "false_positive", "fixed"}


@router.patch("/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update finding workflow status with mandatory reason, record audit log,
    and dynamically recalculate the parent scan risk score.
    """
    new_stat = payload.status.lower().strip()
    if new_stat not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{new_stat}'. Allowed statuses: {', '.join(sorted(VALID_STATUSES))}",
        )

    reason = payload.reason.strip()
    if new_stat != "open" and not reason:
        raise HTTPException(
            status_code=400,
            detail="A substantive reason is required when transitioning a finding out of 'open'.",
        )

    # Fetch finding and parent scan
    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    s_res = await db.execute(
        select(Scan).where(Scan.id == finding.scan_id, Scan.user_id == current_user.id)
    )
    scan = s_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=403, detail="Unauthorized to modify findings for this scan")

    old_stat = getattr(finding, "status", "open")

    # Record audit log
    audit_entry = FindingAuditLog(
        finding_id=finding.id,
        user_id=current_user.id,
        old_status=old_stat,
        new_status=new_stat,
        reason=reason,
    )
    db.add(audit_entry)

    # Update finding
    finding.status = new_stat
    finding.status_reason = reason
    finding.status_updated_at = datetime.now(timezone.utc)
    finding.status_updated_by = current_user.id

    # Recalculate parent scan risk score
    # Fetch all findings for scan
    all_f_res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    all_findings = all_f_res.scalars().all()

    assessment = RiskEngine.calculate_score(all_findings)
    scan.risk_score = assessment.score

    await db.commit()
    await db.refresh(finding)
    await db.refresh(scan)

    return {
        "finding_id": finding.id,
        "old_status": old_stat,
        "new_status": finding.status,
        "reason": finding.status_reason,
        "updated_at": finding.status_updated_at,
        "scan_id": scan.id,
        "recalculated_risk_score": scan.risk_score,
        "recalculated_grade": assessment.grade,
    }


@router.get("/{finding_id}/audit-trail")
async def get_finding_audit_trail(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full chronological audit history for a finding."""
    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Verify authorization
    s_res = await db.execute(
        select(Scan).where(Scan.id == finding.scan_id, Scan.user_id == current_user.id)
    )
    if not s_res.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="Unauthorized to view audit trail for this finding")

    res = await db.execute(
        select(FindingAuditLog)
        .where(FindingAuditLog.finding_id == finding_id)
        .order_by(desc(FindingAuditLog.created_at))
    )
    logs = res.scalars().all()
    return [
        {
            "id": log.id,
            "old_status": log.old_status,
            "new_status": log.new_status,
            "reason": log.reason,
            "user_email": log.user.email if log.user else "System",
            "created_at": log.created_at,
        }
        for log in logs
    ]


@router.post("/{finding_id}/export-issue")
async def export_finding_issue(
    finding_id: str,
    payload: IssueExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Format and export a finding as a tracked issue on GitHub or Jira.
    """
    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    s_res = await db.execute(
        select(Scan).where(Scan.id == finding.scan_id, Scan.user_id == current_user.id)
    )
    scan = s_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=403, detail="Unauthorized")

    issue_data = IntegrationsService.format_issue_payload(
        finding=finding,
        domain=scan.domain,
        scan_id=scan.id,
    )

    prov = payload.provider.lower()
    if prov == "github":
        result = await IntegrationsService.create_github_issue(
            repo=payload.repo or "example/security-findings",
            token=payload.token,
            issue_data=issue_data,
        )
        return result
    elif prov == "jira":
        result = await IntegrationsService.create_jira_issue(
            jira_url=payload.jira_url,
            email=payload.jira_email,
            api_token=payload.jira_token,
            project_key=payload.project_key or "SEC",
            issue_data=issue_data,
        )
        return result
    else:
        return {"success": True, "status": "draft", "data": issue_data}


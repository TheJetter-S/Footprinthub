# =============================================================================
# FootprintHub — Compliance & Executive Summary Routes
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.compliance import ComplianceMapper
from app.core.executive_summary import ExecutiveSummaryGenerator
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(prefix="/scans", tags=["Compliance & Executive Briefing"])


@router.get("/{scan_id}/compliance")
async def get_scan_compliance(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve regulatory and governance compliance control mappings
    (OWASP Top 10, NIST CSF 2.0, ISO 27001, CIS Controls v8) for a scan.
    """
    res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ComplianceMapper.evaluate_scan_compliance(scan.findings)


@router.get("/{scan_id}/executive-summary")
async def get_scan_executive_summary(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve synthesized non-technical executive dossier
    including letter grade, plain-language narrative, and top 5 prioritized fixes.
    """
    res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ExecutiveSummaryGenerator.generate(scan)


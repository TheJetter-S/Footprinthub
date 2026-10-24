# =============================================================================
# FootprintHub — Export API Routes
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.core.export import ExportService
from app.models.finding import Finding
from app.models.result import ModuleResult
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(prefix="/scans", tags=["Export"])


@router.get("/{scan_id}/export")
async def export_scan_report(
    scan_id: str,
    format: str = Query(default="pdf", pattern="^(pdf|json|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a structured scan report in PDF, JSON, or CSV format."""
    scan_res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    results_res = await db.execute(
        select(ModuleResult).where(ModuleResult.scan_id == scan_id).order_by(ModuleResult.module_name)
    )
    results = results_res.scalars().all()

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_res.scalars().all()

    filename_base = f"footprinthub_{scan.domain}_{scan.id[:8]}"

    if format == "json":
        json_content = ExportService.export_json(scan, results, findings)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.json"},
        )
    elif format == "csv":
        csv_content = ExportService.export_csv(findings)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename_base}_findings.csv"},
        )
    else:  # pdf
        pdf_bytes = ExportService.export_pdf(scan, results, findings)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename_base}_report.pdf"},
        )

# =============================================================================
# FootprintHub — Scan History, Comparison, and Relationship Graph Routes
# =============================================================================

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.finding import Finding
from app.models.result import ModuleResult
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanResponse

router = APIRouter(prefix="/scans", tags=["History & Analytics"])


@router.get("/history/domain", response_model=list[ScanResponse])
async def get_domain_scan_history(
    domain: str = Query(..., description="Target domain to retrieve scan history for"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all historical reconnaissance scans performed on a specific domain."""
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id, Scan.domain.ilike(domain.strip()))
        .order_by(desc(Scan.created_at))
    )
    return result.scalars().all()


@router.get("/analytics/compare")
async def compare_scans(
    scan1_id: str = Query(..., description="First (older or baseline) scan ID"),
    scan2_id: str = Query(..., description="Second (newer or target) scan ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare two reconnaissance scans to identify newly introduced risks."""
    s1_res = await db.execute(
        select(Scan).where(Scan.id == scan1_id, Scan.user_id == current_user.id)
    )
    scan1 = s1_res.scalar_one_or_none()

    s2_res = await db.execute(
        select(Scan).where(Scan.id == scan2_id, Scan.user_id == current_user.id)
    )
    scan2 = s2_res.scalar_one_or_none()

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    f1_res = await db.execute(select(Finding).where(Finding.scan_id == scan1_id))
    findings1 = f1_res.scalars().all()

    f2_res = await db.execute(select(Finding).where(Finding.scan_id == scan2_id))
    findings2 = f2_res.scalars().all()

    f1_titles = {f.title: f for f in findings1}
    f2_titles = {f.title: f for f in findings2}

    new_findings = [
        {"severity": f.severity, "module": f.module_name, "title": f.title, "description": f.description}
        for title, f in f2_titles.items() if title not in f1_titles
    ]
    resolved_findings = [
        {"severity": f.severity, "module": f.module_name, "title": f.title, "description": f.description}
        for title, f in f1_titles.items() if title not in f2_titles
    ]
    persisting_findings = [
        {"severity": f.severity, "module": f.module_name, "title": f.title}
        for title, f in f2_titles.items() if title in f1_titles
    ]

    score_delta = (scan2.risk_score or 0) - (scan1.risk_score or 0)

    return {
        "scan1": {"id": scan1.id, "domain": scan1.domain, "profile": scan1.profile, "risk_score": scan1.risk_score, "created_at": scan1.created_at},
        "scan2": {"id": scan2.id, "domain": scan2.domain, "profile": scan2.profile, "risk_score": scan2.risk_score, "created_at": scan2.created_at},
        "comparison": {
            "risk_score_delta": score_delta,
            "posture": "worsened" if score_delta > 0 else "improved" if score_delta < 0 else "unchanged",
            "new_findings_count": len(new_findings),
            "resolved_findings_count": len(resolved_findings),
            "persisting_findings_count": len(persisting_findings),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
        },
    }


@router.get("/{scan_id}/graph")
async def get_relationship_graph(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate graph topology nodes and edges for the infrastructure visualization."""
    scan_res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    res_query = await db.execute(
        select(ModuleResult).where(ModuleResult.scan_id == scan_id)
    )
    results = {r.module_name: r.data for r in res_query.scalars().all()}

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    root_id = "root-domain"
    nodes.append({"id": root_id, "type": "target", "data": {"label": scan.domain, "category": "Domain"}, "position": {"x": 400, "y": 250}})

    for idx, sub_item in enumerate((results.get("subdomains", {}).get("subdomains", []))[:12]):
        sub_name = sub_item.get("subdomain")
        if sub_name and sub_name != scan.domain:
            node_id = f"sub-{idx}"
            nodes.append({"id": node_id, "type": "subdomain", "data": {"label": sub_name, "category": "Subdomain"}, "position": {"x": 150 + (idx % 4) * 180, "y": 80 + (idx // 4) * 90}})
            edges.append({"id": f"e-root-{node_id}", "source": root_id, "target": node_id, "label": "subdomain"})

    for idx, net in enumerate((results.get("ip_network", {}).get("networks", []))[:6]):
        if ip_addr := net.get("ip"):
            ip_id = f"ip-{idx}"
            nodes.append({"id": ip_id, "type": "ip", "data": {"label": f"{ip_addr} ({net.get('country', '')})", "category": "IP Address", "isp": net.get("isp", "Host")}, "position": {"x": 200 + idx * 200, "y": 420}})
            edges.append({"id": f"e-root-{ip_id}", "source": root_id, "target": ip_id, "label": "resolves to"})

    for idx, tech in enumerate((results.get("web_tech", {}).get("technologies", []))[:8]):
        tech_id = f"tech-{idx}"
        nodes.append({"id": tech_id, "type": "tech", "data": {"label": tech, "category": "Technology"}, "position": {"x": 650 + (idx % 2) * 140, "y": 180 + (idx // 2) * 80}})
        edges.append({"id": f"e-root-{tech_id}", "source": root_id, "target": tech_id, "label": "uses"})

    for idx, b in enumerate((results.get("cloud", {}).get("buckets", []))[:6]):
        b_id = f"bucket-{idx}"
        nodes.append({"id": b_id, "type": "cloud", "data": {"label": b.get("bucket_name"), "provider": b.get("provider"), "status": b.get("status")}, "position": {"x": 100 + idx * 160, "y": 550}})
        edges.append({"id": f"e-root-{b_id}", "source": root_id, "target": b_id, "label": "cloud asset"})

    return {"nodes": nodes, "edges": edges}

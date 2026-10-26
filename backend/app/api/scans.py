# =============================================================================
# FootprintHub — Scans API Routes
# =============================================================================

import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user, get_client_ip, check_rate_limit
from app.models.scan import Scan
from app.models.result import ModuleResult
from app.models.finding import Finding
from app.models.user import User
from app.schemas.scan import (
    ScanCreateRequest,
    ScanResponse,
    ScanListResponse,
    ModuleResultResponse,
    FindingResponse,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _rate: None = Depends(check_rate_limit),
):
    """Start a new reconnaissance scan. Requires authorization confirmation."""
    scan = Scan(
        user_id=current_user.id,
        domain=body.domain,
        profile=body.profile,
        status="running",
        authorization_confirmed=body.authorization_confirmed,
        client_ip=get_client_ip(request),
        authorization_ts=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    # Create placeholder module rows (one per module)
    modules = get_modules_for_profile(body.profile)
    for module_name, mode in modules:
        result = ModuleResult(
            scan_id=scan.id,
            module_name=module_name,
            mode=mode,
            status="pending",
            data={},
        )
        db.add(result)

    await db.commit()

    scan_id = scan.id
    domain = body.domain
    profile = body.profile

    # Dispatch in-process concurrent runner immediately
    asyncio.create_task(_run_scan_concurrent(scan_id, domain, profile))

    return scan


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    domain: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List the current user's scans with pagination."""
    query = select(Scan).where(Scan.user_id == current_user.id)
    count_query = select(func.count(Scan.id)).where(Scan.user_id == current_user.id)

    if domain:
        query = query.where(Scan.domain.ilike(f"%{domain}%"))
        count_query = count_query.where(Scan.domain.ilike(f"%{domain}%"))

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.order_by(desc(Scan.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get details of a specific scan."""
    return await _get_user_scan(db, scan_id, current_user.id)


@router.get("/{scan_id}/results", response_model=list[ModuleResultResponse])
async def get_scan_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all module results for a scan."""
    await _get_user_scan(db, scan_id, current_user.id)
    result = await db.execute(
        select(ModuleResult)
        .where(ModuleResult.scan_id == scan_id)
        .order_by(ModuleResult.module_name)
    )
    return result.scalars().all()


@router.get("/{scan_id}/results/{module_name}", response_model=ModuleResultResponse)
async def get_module_result(
    scan_id: str,
    module_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the result of a specific module for a scan."""
    await _get_user_scan(db, scan_id, current_user.id)
    result = await db.execute(
        select(ModuleResult).where(
            ModuleResult.scan_id == scan_id,
            ModuleResult.module_name == module_name,
        )
    )
    module_result = result.scalar_one_or_none()
    if not module_result:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' result not found")
    return module_result


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all findings for a scan, optionally filtered by severity."""
    await _get_user_scan(db, scan_id, current_user.id)
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity.lower())

    result = await db.execute(query)
    findings = result.scalars().all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    return findings


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scan and all its results."""
    scan = await _get_user_scan(db, scan_id, current_user.id)
    await db.delete(scan)


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_user_scan(db: AsyncSession, scan_id: str, user_id: str) -> Scan:
    """Fetch a scan and verify ownership."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def get_modules_for_profile(profile: str) -> list[tuple[str, str]]:
    """Return (module_name, mode) pairs for a given scan profile."""
    modules = [
        ("dns", "passive"),
        ("subdomains", "passive"),
        ("ip_network", "passive"),
        ("web_tech", "passive"),
        ("ssl_tls", "passive"),
        ("content", "passive"),
        ("ports", "passive"),
        ("osint", "passive"),
        ("cloud", "passive"),
        ("reputation", "passive"),
    ]
    return modules


# ── Concurrent Scan Runner ────────────────────────────────────────────────────

async def _run_scan_concurrent(scan_id: str, target: str, profile: str) -> None:
    """
    Run all recon modules CONCURRENTLY and save each result to the DB
    immediately upon completion — enabling live frontend updates.
    """
    from app.modules import (
        DNSModule, SubdomainModule, IPNetworkModule, WebTechModule,
        SSLModule, ContentModule, PortsModule, OSINTModule,
        CloudModule, ReputationModule,
    )
    from app.models.base import async_session_factory

    module_instances = {
        "dns": DNSModule(),
        "subdomains": SubdomainModule(),
        "ip_network": IPNetworkModule(),
        "web_tech": WebTechModule(),
        "ssl_tls": SSLModule(),
        "content": ContentModule(),
        "ports": PortsModule(),
        "osint": OSINTModule(),
        "cloud": CloudModule(),
        "reputation": ReputationModule(),
    }

    def _publish(module_name: str, percent: int, message: str, status: str) -> None:
        """Publish progress via in-process WS queue."""
        try:
            from app.api.ws import get_or_create_queue
            import json
            data = {
                "scan_id": scan_id,
                "module": module_name,
                "percent": percent,
                "message": message,
                "status": status,
            }
            q = get_or_create_queue(scan_id)
            try:
                q.put_nowait(data)
            except Exception:
                pass
        except Exception:
            pass

        # Also try Redis
        try:
            import redis
            from app.config import settings
            r = redis.from_url(settings.REDIS_URL)
            r.publish(f"scan:{scan_id}", json.dumps(data))
            r.close()
        except Exception:
            pass

    async def _run_one(module_name: str, instance) -> None:
        """Execute one module, persist result + findings, and notify progress."""
        try:
            _publish(module_name, 5, f"Starting {module_name}...", "running")

            # Mark as running
            async with async_session_factory() as session:
                await session.execute(
                    update(ModuleResult)
                    .where(ModuleResult.scan_id == scan_id, ModuleResult.module_name == module_name)
                    .values(status="running")
                )
                await session.commit()

            # Execute with timeout
            try:
                mod_timeout = getattr(instance, "timeout", 120)
                result = await asyncio.wait_for(
                    instance.execute(target),
                    timeout=max(mod_timeout + 30, 150),
                )
            except asyncio.TimeoutError:
                async with async_session_factory() as session:
                    await session.execute(
                        update(ModuleResult)
                        .where(ModuleResult.scan_id == scan_id, ModuleResult.module_name == module_name)
                        .values(status="error", error_message="Module timed out")
                    )
                    await session.commit()
                _publish(module_name, 100, f"{module_name} timed out", "error")
                return

            # Save result and findings immediately
            async with async_session_factory() as session:
                await session.execute(
                    update(ModuleResult)
                    .where(ModuleResult.scan_id == scan_id, ModuleResult.module_name == module_name)
                    .values(
                        status=result.status,
                        data=result.data,
                        duration_seconds=result.duration_seconds,
                        error_message=result.error_message,
                    )
                )
                for finding in result.findings:
                    session.add(Finding(
                        scan_id=scan_id,
                        module_name=result.module_name,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        remediation=finding.remediation,
                    ))
                await session.commit()

            _publish(
                module_name, 100,
                f"{module_name} done in {result.duration_seconds:.1f}s — {len(result.findings)} finding(s)",
                result.status,
            )

        except Exception as e:
            err = f"{type(e).__name__}: {str(e)}"
            try:
                async with async_session_factory() as session:
                    await session.execute(
                        update(ModuleResult)
                        .where(ModuleResult.scan_id == scan_id, ModuleResult.module_name == module_name)
                        .values(status="error", error_message=err)
                    )
                    await session.commit()
            except Exception:
                pass
            _publish(module_name, 100, f"{module_name} error: {err[:80]}", "error")

    # ── Run all modules concurrently ──────────────────────────────────────────
    modules = get_modules_for_profile(profile)
    tasks = [_run_one(name, module_instances[name]) for name, _ in modules if name in module_instances]
    await asyncio.gather(*tasks, return_exceptions=True)

    # ── Finalize: calculate risk score and mark scan as completed ─────────────
    try:
        from app.core.risk_engine import RiskEngine
        async with async_session_factory() as session:
            findings_res = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
            all_findings = findings_res.scalars().all()
            assessment = RiskEngine.calculate_score(all_findings)
            await session.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    status="completed",
                    risk_score=assessment.score,
                    completed_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()
        _publish("_system", 100, f"Scan complete! Risk score: {assessment.score}/100", "completed")
    except Exception as e:
        try:
            from app.models.base import async_session_factory as asf
            async with asf() as session:
                await session.execute(
                    update(Scan).where(Scan.id == scan_id).values(
                        status="completed",
                        completed_at=datetime.now(timezone.utc),
                    )
                )
                await session.commit()
        except Exception:
            pass
        _publish("_system", 100, "Scan complete", "completed")

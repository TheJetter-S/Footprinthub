# =============================================================================
# FootprintHub — Celery Scan Tasks
# =============================================================================
# Task wrappers that run each module in a Celery worker and publish
# progress updates to Redis Pub/Sub for WebSocket streaming.
# =============================================================================

import json
import asyncio
from typing import Optional
from uuid import UUID

import redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.tasks.celery_app import celery_app

# Redis client for publishing progress (synchronous, used inside Celery worker)
_redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)


def publish_progress(
    scan_id: str,
    module: str,
    percent: int,
    message: str,
    status: str = "running",
) -> None:
    """Publish a progress update to the scan's Redis Pub/Sub channel."""
    try:
        if _redis_client:
            _redis_client.publish(
                f"scan:{scan_id}",
                json.dumps({
                    "module": module,
                    "percent": percent,
                    "message": message,
                    "status": status,
                }),
            )
    except Exception:
        pass  # Redis Pub/Sub optional when running standalone


@celery_app.task(bind=True, name="run_module")
def run_module_task(self, scan_id: str, module_name: str, target: str, mode: str):
    """
    Celery task that runs a single reconnaissance module.

    Args:
        scan_id: UUID of the scan
        module_name: Name of the module to run
        target: Target domain
        mode: "passive" or "active"
    """
    from app.modules.base import ModuleResult

    # Progress callback that publishes to Redis
    def on_progress(percent: int, message: str) -> None:
        publish_progress(scan_id, module_name, percent, message, "running")

    # Publish start
    publish_progress(scan_id, module_name, 0, f"Starting {module_name} module...", "running")

    try:
        # Dynamically load and run the module
        module_instance = _get_module_instance(module_name)
        if module_instance is None:
            publish_progress(scan_id, module_name, 100, f"Module '{module_name}' not found", "error")
            return {"status": "error", "error": f"Module '{module_name}' not found"}

        # Run the async module in the event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                module_instance.execute(target, on_progress=on_progress)
            )
        finally:
            loop.close()

        # Publish completion
        status = "success" if result.status == "success" else "error"
        publish_progress(
            scan_id, module_name, 100,
            f"{module_name} completed ({result.duration_seconds:.1f}s)",
            status,
        )

        # Store result in database (synchronous for Celery)
        _store_result_sync(scan_id, result)

        return result.model_dump()

    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        publish_progress(scan_id, module_name, 100, error_msg, "error")
        return {"status": "error", "error": error_msg}


@celery_app.task(name="dispatch_scan")
def dispatch_scan(scan_id: str, target: str, profile: str):
    """
    Dispatch all module tasks for a scan as a Celery group.
    Called after a scan is created via the API.
    """
    from celery import group
    from app.api.scans import get_modules_for_profile

    modules = get_modules_for_profile(profile)
    task_group = group(
        run_module_task.s(scan_id, module_name, target, mode)
        for module_name, mode in modules
    )

    # Execute the group (all modules run in parallel)
    result = task_group.apply_async()

    # Publish overall scan progress
    publish_progress(
        scan_id, "_orchestrator", 0,
        f"Dispatched {len(modules)} modules",
        "running",
    )

    return {"group_id": str(result.id), "module_count": len(modules)}


def _get_module_instance(module_name: str):
    """
    Dynamically load a module class by name.
    Returns None if the module is not yet implemented.
    """
    # Module registry — will be populated as modules are built in Phase 2-4
    MODULE_REGISTRY = {}

    # Try to import and register modules dynamically
    try:
        if module_name == "dns":
            from app.modules.dns_module import DNSModule
            return DNSModule()
        elif module_name == "subdomains":
            from app.modules.subdomain_module import SubdomainModule
            return SubdomainModule()
        elif module_name == "ip_network":
            from app.modules.ip_network_module import IPNetworkModule
            return IPNetworkModule()
        elif module_name == "web_tech":
            from app.modules.webtech_module import WebTechModule
            return WebTechModule()
        elif module_name == "ssl_tls":
            from app.modules.ssl_module import SSLModule
            return SSLModule()
        elif module_name == "content":
            from app.modules.content_module import ContentModule
            return ContentModule()
        elif module_name == "ports":
            from app.modules.ports_module import PortsModule
            return PortsModule()
        elif module_name == "osint":
            from app.modules.osint_module import OSINTModule
            return OSINTModule()
        elif module_name == "cloud":
            from app.modules.cloud_module import CloudModule
            return CloudModule()
        elif module_name == "reputation":
            from app.modules.reputation_module import ReputationModule
            return ReputationModule()
    except ImportError:
        pass

    return None


def _store_result_sync(scan_id: str, result) -> None:
    """
    Store module result in the database (synchronous, for Celery workers).
    Uses a separate synchronous SQLAlchemy session.
    """
    from sqlalchemy import create_engine, update
    from sqlalchemy.orm import Session
    from app.models.result import ModuleResult
    from app.models.finding import Finding

    try:
        from datetime import datetime, timezone
        from sqlalchemy import select
        from app.models.scan import Scan
        from app.core.risk_engine import RiskEngine
        db_url = settings.DATABASE_URL
        if "+asyncpg" in db_url:
            sync_url = db_url.replace("+asyncpg", "+psycopg2").replace("postgresql+psycopg2", "postgresql")
        elif "+aiosqlite" in db_url:
            sync_url = db_url.replace("+aiosqlite", "")
        else:
            sync_url = db_url

        engine = create_engine(sync_url)
        with Session(engine) as session:
            # Update the module result
            session.execute(
                update(ModuleResult)
                .where(
                    ModuleResult.scan_id == scan_id,
                    ModuleResult.module_name == result.module_name,
                )
                .values(
                    status=result.status,
                    data=result.data,
                    duration_seconds=result.duration_seconds,
                    error_message=result.error_message,
                )
            )

            # Store findings
            for finding in result.findings:
                f = Finding(
                    scan_id=scan_id,
                    module_name=result.module_name,
                    severity=finding.severity.value,
                    title=finding.title,
                    description=finding.description,
                    remediation=finding.remediation,
                )
                session.add(f)

            session.commit()

            # Check if all module results for this scan have finished
            all_results = session.execute(
                select(ModuleResult).where(ModuleResult.scan_id == scan_id)
            ).scalars().all()

            all_done = all(r.status in ["success", "error", "partial"] for r in all_results)
            if all_done and all_results:
                # Aggregate all findings to calculate final risk score
                scan_findings = session.execute(
                    select(Finding).where(Finding.scan_id == scan_id)
                ).scalars().all()

                assessment = RiskEngine.calculate_score(scan_findings)

                session.execute(
                    update(Scan)
                    .where(Scan.id == scan_id)
                    .values(
                        status="completed",
                        risk_score=assessment.score,
                        completed_at=datetime.now(timezone.utc),
                    )
                )
                session.commit()

                publish_progress(
                    scan_id,
                    "_orchestrator",
                    100,
                    f"All modules completed. Risk score: {assessment.score}/100 ({assessment.grade})",
                    "completed",
                )

        engine.dispose()
    except Exception as ex:
        pass  # Graceful failure — don't crash the worker

# =============================================================================
# FootprintHub — Celery Application
# =============================================================================
# Celery instance configured to use Redis as both broker and result backend.
# =============================================================================

from celery import Celery

from app.config import settings

celery_app = Celery(
    "footprinthub",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

# ── Celery Configuration ────────────────────────────────────────────────────
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task behavior
    task_track_started=True,
    task_time_limit=300,       # Hard limit: 5 minutes per task
    task_soft_time_limit=240,  # Soft limit: 4 minutes (raises SoftTimeLimitExceeded)
    task_acks_late=True,       # Acknowledge only after task completes
    worker_prefetch_multiplier=1,

    # Result expiration
    result_expires=86400,  # Results expire after 24 hours

    # Auto-discover tasks in the tasks module
    include=["app.tasks.scan_tasks"],
)

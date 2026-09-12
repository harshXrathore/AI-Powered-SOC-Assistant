"""
Celery application instance.

Purpose:
    Configures the Celery worker used for asynchronous, potentially
    slow, or scheduled work that must not block API request/response
    cycles: Wazuh alert polling (Phase 2), IOC enrichment and incident
    report generation (Phase 3+).

Dependencies:
    Requires Redis (broker + result backend). See docker-compose.yml.

Running:
    Worker:  celery -A app.core.celery_app worker --loglevel=info
    Beat:    celery -A app.core.celery_app beat --loglevel=info
"""

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "soc_assistant",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.services.tasks.wazuh_tasks",
        "app.services.tasks.enrichment_tasks",
        "app.services.tasks.report_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

# Periodic tasks. Enrichment/report schedules are placeholders wired up in
# Phase 3 — the modules exist now (as documented stubs) so `include` above
# doesn't fail on import; they raise NotImplementedError if invoked early.
celery_app.conf.beat_schedule = {
    "poll-wazuh-alerts": {
        "task": "app.services.tasks.wazuh_tasks.sync_wazuh_alerts",
        "schedule": settings.WAZUH_SYNC_INTERVAL_SECONDS,
    },
}

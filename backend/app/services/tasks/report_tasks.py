"""
Incident report generation tasks — Phase 3+.

Purpose:
    Reserved module for Celery tasks that generate PDF/Markdown incident
    reports via LLM calls. Not implemented in Phase 2 — exists only so
    `celery_app.py`'s `include=[...]` resolves at import time.
"""

import structlog

from app.core.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(name="app.services.tasks.report_tasks.generate_incident_report")
def generate_incident_report(alert_id: str) -> None:
    raise NotImplementedError("Incident report generation lands in a later phase.")

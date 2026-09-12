"""
IOC enrichment tasks — Phase 3.

Purpose:
    Reserved module for Celery tasks that enrich IPs/domains/hashes
    against VirusTotal, AbuseIPDB, and AlienVault OTX. Not implemented in
    Phase 2 — this file exists only so `celery_app.py`'s `include=[...]`
    list resolves at import time without needing a Phase-2/Phase-3
    conditional. Every function here raises NotImplementedError if
    called; nothing in Phase 2 invokes them.
"""

import structlog

from app.core.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(name="app.services.tasks.enrichment_tasks.refresh_stale_ioc_cache")
def refresh_stale_ioc_cache() -> None:
    raise NotImplementedError("IOC enrichment lands in Phase 3.")

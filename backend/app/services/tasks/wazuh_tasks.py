"""
Wazuh alert synchronization task.

Purpose:
    Runs on a schedule (see celery_app.py's beat_schedule, default every
    60s) to pull new alerts from the Wazuh Indexer, upsert them into
    Postgres via AlertSyncService, and broadcast newly created alerts to
    connected WebSocket clients over Redis pub/sub.

Duplicate prevention:
    `AlertRepository.upsert_from_wazuh` keys on `wazuh_alert_id` (unique
    DB constraint), so re-processing an already-seen alert updates it in
    place rather than creating a duplicate row. The lookback window
    (WAZUH_SYNC_LOOKBACK_MINUTES, default 5 minutes) intentionally
    overlaps between runs to tolerate clock drift or a slow previous
    run — the upsert makes that overlap safe.

Logging:
    Every run logs new/updated/error counts as structured fields so sync
    health is queryable/alertable from log aggregation.
"""

import asyncio
import json

import redis
import structlog

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.services.alert_sync_service import AlertSyncService
from app.services.wazuh_client import WazuhAPIError, WazuhAuthError, WazuhClient

logger = structlog.get_logger(__name__)

NEW_ALERT_CHANNEL = "soc:new_alerts"


async def _sync_alerts_async() -> dict[str, int]:
    client = WazuhClient()
    redis_client = redis.from_url(settings.REDIS_URL)

    try:
        raw_alerts = await client.get_recent_alerts(
            minutes=settings.WAZUH_SYNC_LOOKBACK_MINUTES
        )
    finally:
        await client.close()

    if not raw_alerts:
        logger.info("wazuh_sync_no_alerts")
        return {"new": 0, "updated": 0, "errors": 0, "total": 0}

    async with AsyncSessionLocal() as session:
        alert_repository = AlertRepository(session)
        asset_repository = AssetRepository(session)
        sync_service = AlertSyncService(alert_repository, asset_repository)

        # Track which wazuh_alert_ids were new *before* syncing so we can
        # broadcast only genuinely new alerts, not re-synced updates.
        new_alert_payloads = []
        for raw_alert in raw_alerts:
            wazuh_id = raw_alert.get("_id")
            existing = await alert_repository.get_by_wazuh_id(str(wazuh_id)) if wazuh_id else None
            if existing is None:
                new_alert_payloads.append(raw_alert)

        stats = await sync_service.sync_alerts(raw_alerts)

    # Broadcast only alerts that were new, after the DB commit succeeded.
    for raw_alert in new_alert_payloads:
        rule = raw_alert.get("rule", {})
        message = {
            "event": "new_alert",
            "wazuh_alert_id": raw_alert.get("_id"),
            "rule_id": rule.get("id"),
            "rule_description": rule.get("description"),
            "level": rule.get("level"),
            "agent_name": raw_alert.get("agent", {}).get("name"),
            "timestamp": raw_alert.get("timestamp"),
        }
        redis_client.publish(NEW_ALERT_CHANNEL, json.dumps(message))

    logger.info(
        "wazuh_sync_completed",
        new=stats["new"],
        updated=stats["updated"],
        errors=stats["errors"],
        total=stats["total"],
    )
    return stats


@celery_app.task(
    name="app.services.tasks.wazuh_tasks.sync_wazuh_alerts",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
)
def sync_wazuh_alerts(self) -> dict[str, int]:
    """
    Celery entrypoint. Wraps the async sync logic with asyncio.run since
    Celery tasks are synchronous by default. Retries on Wazuh
    connectivity failures (auth/API errors) — a single bad poll cycle
    shouldn't require manual intervention.
    """
    try:
        return asyncio.run(_sync_alerts_async())
    except (WazuhAuthError, WazuhAPIError) as exc:
        logger.error("wazuh_sync_failed", error=str(exc), attempt=self.request.retries + 1)
        raise self.retry(exc=exc) from exc

"""
Alert sync service.

Purpose:
    Translates a raw Wazuh alert document (as returned by
    WazuhClient.get_alerts()) into the fields the Alert ORM model expects,
    and performs the upsert via AlertRepository. This is the one place
    that understands Wazuh's JSON shape, so a future Wazuh version
    bump only requires changes here, not in the Celery task or API layer.

Dependencies:
    Called by app/services/tasks/wazuh_tasks.py (Celery) — kept separate
    from the task module so this logic is unit-testable without Celery's
    task-execution machinery in the loop.
"""

from datetime import datetime
from typing import Any

import structlog
from dateutil import parser as date_parser

from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.utils.severity import severity_from_level

logger = structlog.get_logger(__name__)


def _parse_timestamp(raw_timestamp: str | None) -> datetime:
    if raw_timestamp is None:
        return datetime.utcnow()
    return date_parser.isoparse(raw_timestamp)


def _extract_fields(raw_alert: dict[str, Any]) -> dict[str, Any]:
    """
    Pulls the fields this app cares about out of a Wazuh alert document.
    Wazuh's alert JSON nests most useful data under `rule`, `agent`,
    `data`, and top-level `timestamp`/`full_log` — this defensively uses
    `.get()` throughout since field presence varies by rule/decoder.
    """
    rule = raw_alert.get("rule", {})
    agent = raw_alert.get("agent", {})
    data = raw_alert.get("data", {})

    level = int(rule.get("level", 0))

    return {
        "rule_id": str(rule.get("id", "unknown")),
        "rule_description": rule.get("description", "No description"),
        "severity": severity_from_level(level),
        "timestamp": _parse_timestamp(raw_alert.get("timestamp")),
        "source_ip": data.get("srcip"),
        "destination_ip": data.get("dstip"),
        "agent_name": agent.get("name"),
        "log_message": raw_alert.get("full_log"),
        "raw_event": raw_alert,
    }


class AlertSyncService:
    def __init__(self, alert_repository: AlertRepository, asset_repository: AssetRepository) -> None:
        self._alerts = alert_repository
        self._assets = asset_repository

    async def sync_alert(self, raw_alert: dict[str, Any]) -> bool:
        """
        Upserts a single raw Wazuh alert document. Returns True if a new
        Alert row was created, False if an existing one was updated.
        """
        wazuh_alert_id = raw_alert.get("_id") or raw_alert.get("id")
        if wazuh_alert_id is None:
            logger.warning("wazuh_alert_missing_id", raw_alert_keys=list(raw_alert.keys()))
            raise ValueError("Wazuh alert document is missing an _id/id field")

        fields = _extract_fields(raw_alert)

        agent_name = fields.get("agent_name")
        if agent_name:
            asset = await self._assets.get_or_create_by_hostname(
                agent_name, ip_address=fields.get("source_ip")
            )
            fields["asset_id"] = asset.id

        _, was_created = await self._alerts.upsert_from_wazuh(str(wazuh_alert_id), fields)
        return was_created

    async def sync_alerts(self, raw_alerts: list[dict[str, Any]]) -> dict[str, int]:
        """
        Syncs a batch of raw alerts, committing once at the end for
        efficiency. Returns stats for logging: {"new": N, "updated": M,
        "errors": E, "total": N+M+E}.
        """
        stats = {"new": 0, "updated": 0, "errors": 0}

        for raw_alert in raw_alerts:
            try:
                was_created = await self.sync_alert(raw_alert)
                if was_created:
                    stats["new"] += 1
                else:
                    stats["updated"] += 1
            except Exception:
                logger.exception("alert_sync_failed", wazuh_alert_id=raw_alert.get("_id"))
                stats["errors"] += 1

        await self._alerts.commit()
        stats["total"] = stats["new"] + stats["updated"] + stats["errors"]
        return stats

"""
Alert repository.

Purpose:
    All direct SQLAlchemy queries against the Alert table: filtered/paginated
    listing, single lookups, the upsert used by Wazuh sync, and the
    aggregate queries backing the dashboard endpoints.

Architecture:
    `list_alerts` builds one dynamic query from AlertFilterParams rather
    than having a separate method per filter combination — the filter
    surface (severity/status/IP/hostname/rule/date/search) is large
    enough that a query-builder approach stays readable, while a method
    per combination would combinatorially explode.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.enums import AlertSeverity, AlertStatus
from app.schemas.alert import AlertFilterParams

# Columns callers are allowed to sort by — an explicit allowlist prevents
# arbitrary attribute access from a user-controlled sort_by string.
SORTABLE_COLUMNS = {
    "timestamp": Alert.timestamp,
    "severity": Alert.severity,
    "status": Alert.status,
    "created_at": Alert.created_at,
    "rule_id": Alert.rule_id,
}


class AlertRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, alert_id: uuid.UUID) -> Alert | None:
        result = await self._session.execute(select(Alert).where(Alert.id == alert_id))
        return result.scalar_one_or_none()

    async def get_by_wazuh_id(self, wazuh_alert_id: str) -> Alert | None:
        result = await self._session.execute(
            select(Alert).where(Alert.wazuh_alert_id == wazuh_alert_id)
        )
        return result.scalar_one_or_none()

    def _apply_filters(self, query, filters: AlertFilterParams):
        conditions = []
        if filters.severity is not None:
            conditions.append(Alert.severity == filters.severity)
        if filters.status is not None:
            conditions.append(Alert.status == filters.status)
        if filters.source_ip is not None:
            conditions.append(Alert.source_ip == filters.source_ip)
        if filters.destination_ip is not None:
            conditions.append(Alert.destination_ip == filters.destination_ip)
        if filters.agent_name is not None:
            conditions.append(Alert.agent_name.ilike(f"%{filters.agent_name}%"))
        if filters.rule_id is not None:
            conditions.append(Alert.rule_id == filters.rule_id)
        if filters.hostname is not None:
            conditions.append(Alert.agent_name.ilike(f"%{filters.hostname}%"))
        if filters.date_from is not None:
            conditions.append(Alert.timestamp >= filters.date_from)
        if filters.date_to is not None:
            conditions.append(Alert.timestamp <= filters.date_to)
        if filters.search:
            like = f"%{filters.search}%"
            conditions.append(
                or_(
                    Alert.rule_description.ilike(like),
                    Alert.log_message.ilike(like),
                    Alert.source_ip.ilike(like),
                    Alert.destination_ip.ilike(like),
                    Alert.agent_name.ilike(like),
                )
            )
        if conditions:
            query = query.where(and_(*conditions))
        return query

    async def list_alerts(self, filters: AlertFilterParams) -> tuple[list[Alert], int]:
        base_query = select(Alert)
        base_query = self._apply_filters(base_query, filters)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = (await self._session.execute(count_query)).scalar_one()

        sort_column = SORTABLE_COLUMNS.get(filters.sort_by, Alert.timestamp)
        order = desc(sort_column) if filters.sort_order == "desc" else sort_column.asc()

        paginated_query = (
            base_query.order_by(order)
            .offset((filters.page - 1) * filters.page_size)
            .limit(filters.page_size)
        )
        result = await self._session.execute(paginated_query)
        return list(result.scalars().all()), total

    async def get_high_severity(self, limit: int = 50) -> list[Alert]:
        query = (
            select(Alert)
            .where(Alert.severity.in_([AlertSeverity.CRITICAL, AlertSeverity.HIGH]))
            .order_by(desc(Alert.timestamp))
            .limit(limit)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def get_recent(self, limit: int = 50) -> list[Alert]:
        query = select(Alert).order_by(desc(Alert.timestamp)).limit(limit)
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def update_status(self, alert: Alert, status: AlertStatus) -> Alert:
        alert.status = status
        await self._session.commit()
        await self._session.refresh(alert)
        return alert

    async def upsert_from_wazuh(self, wazuh_alert_id: str, values: dict[str, Any]) -> tuple[Alert, bool]:
        """
        Insert a new Alert or update an existing one, keyed on
        wazuh_alert_id. Returns (alert, was_created) so the sync task can
        report accurate "N new, M updated" statistics.
        """
        existing = await self.get_by_wazuh_id(wazuh_alert_id)
        if existing is not None:
            for key, value in values.items():
                setattr(existing, key, value)
            await self._session.flush()
            return existing, False

        alert = Alert(wazuh_alert_id=wazuh_alert_id, **values)
        self._session.add(alert)
        await self._session.flush()
        return alert, True

    async def commit(self) -> None:
        await self._session.commit()

    # ---------- Dashboard aggregate queries ----------

    async def count_total(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(Alert))
        return result.scalar_one()

    async def count_by_severity(self) -> dict[str, int]:
        query = select(Alert.severity, func.count()).group_by(Alert.severity)
        result = await self._session.execute(query)
        counts = {row[0].value: row[1] for row in result.all()}
        return {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
        }

    async def count_last_24h(self) -> int:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        query = select(func.count()).select_from(Alert).where(Alert.timestamp >= since)
        result = await self._session.execute(query)
        return result.scalar_one()

    async def top_attacking_ips(self, limit: int = 10) -> list[tuple[str, int]]:
        query = (
            select(Alert.source_ip, func.count().label("cnt"))
            .where(Alert.source_ip.is_not(None))
            .group_by(Alert.source_ip)
            .order_by(desc("cnt"))
            .limit(limit)
        )
        result = await self._session.execute(query)
        return [(row[0], row[1]) for row in result.all()]

    async def top_rules(self, limit: int = 10) -> list[tuple[str, str, int]]:
        query = (
            select(Alert.rule_id, Alert.rule_description, func.count().label("cnt"))
            .group_by(Alert.rule_id, Alert.rule_description)
            .order_by(desc("cnt"))
            .limit(limit)
        )
        result = await self._session.execute(query)
        return [(row[0], row[1], row[2]) for row in result.all()]

    async def hourly_trend(self, hours: int = 24) -> list[tuple[datetime, int]]:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        bucket = func.date_trunc("hour", Alert.timestamp).label("hour")
        query = (
            select(bucket, func.count().label("cnt"))
            .where(Alert.timestamp >= since)
            .group_by(bucket)
            .order_by(bucket)
        )
        result = await self._session.execute(query)
        return [(row[0], row[1]) for row in result.all()]

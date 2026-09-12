"""
Dashboard service.

Purpose:
    Assembles the several AlertRepository aggregate queries into the
    single DashboardSummaryResponse shape the frontend consumes. Kept as
    a service (rather than inlining in the router) so the same summary
    could later be reused by the AI chat assistant ("what's my alert
    picture right now?") without duplicating query orchestration.
"""

from app.repositories.alert_repository import AlertRepository
from app.schemas.dashboard import (
    DashboardSummaryResponse,
    HourlyTrendPoint,
    SeverityCounts,
    TopIP,
    TopRule,
)


class DashboardService:
    def __init__(self, alert_repository: AlertRepository) -> None:
        self._alerts = alert_repository

    async def get_summary(self) -> DashboardSummaryResponse:
        total = await self._alerts.count_total()
        severity_counts = await self._alerts.count_by_severity()
        last_24h = await self._alerts.count_last_24h()
        top_ips = await self._alerts.top_attacking_ips(limit=10)
        top_rules = await self._alerts.top_rules(limit=10)
        trend = await self._alerts.hourly_trend(hours=24)

        return DashboardSummaryResponse(
            total_alerts=total,
            severity_counts=SeverityCounts(**severity_counts),
            alerts_last_24h=last_24h,
            top_attacking_ips=[TopIP(ip_address=ip, count=count) for ip, count in top_ips],
            top_rules=[
                TopRule(rule_id=rid, rule_description=desc, count=count)
                for rid, desc, count in top_rules
            ],
            alert_trend_by_hour=[
                HourlyTrendPoint(hour=hour, count=count) for hour, count in trend
            ],
        )

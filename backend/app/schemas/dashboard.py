"""Dashboard Pydantic schemas."""

from datetime import datetime

from pydantic import BaseModel


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class TopIP(BaseModel):
    ip_address: str
    count: int


class TopRule(BaseModel):
    rule_id: str
    rule_description: str
    count: int


class HourlyTrendPoint(BaseModel):
    hour: datetime
    count: int


class DashboardSummaryResponse(BaseModel):
    total_alerts: int
    severity_counts: SeverityCounts
    alerts_last_24h: int
    top_attacking_ips: list[TopIP]
    top_rules: list[TopRule]
    alert_trend_by_hour: list[HourlyTrendPoint]

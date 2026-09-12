"""
Dashboard router.

API endpoints:
    GET /api/v1/dashboard/summary -> total/severity counts, 24h volume,
                                      top attacking IPs, top rules, hourly trend
"""

from fastapi import APIRouter, Depends

from app.api.dependencies.auth import require_any_role
from app.api.dependencies.repositories import get_alert_repository
from app.models.user import User
from app.repositories.alert_repository import AlertRepository
from app.schemas.dashboard import DashboardSummaryResponse
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_any_role),
) -> DashboardSummaryResponse:
    service = DashboardService(alert_repository)
    return await service.get_summary()

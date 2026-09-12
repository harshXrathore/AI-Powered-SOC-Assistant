"""
Alert router.

API endpoints:
    GET   /api/v1/alerts              -> paginated, filtered, sorted list
    GET   /api/v1/alerts/high         -> critical + high severity alerts
    GET   /api/v1/alerts/recent       -> most recent alerts regardless of severity
    GET   /api/v1/alerts/search       -> same filter surface as list, semantic alias
    GET   /api/v1/alerts/{id}         -> single alert with full raw_event
    PATCH /api/v1/alerts/{id}/status  -> analyst updates triage status

Access control:
    Read endpoints: any authenticated role (Admin/Analyst/ReadOnly).
    Status updates: Admin or Analyst only — ReadOnly cannot mutate state.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies.auth import require_analyst_or_admin, require_any_role
from app.api.dependencies.repositories import get_alert_repository
from app.models.enums import AlertSeverity, AlertStatus
from app.models.user import User
from app.repositories.alert_repository import AlertRepository
from app.schemas.alert import (
    AlertDetailResponse,
    AlertFilterParams,
    AlertListResponse,
    AlertResponse,
    AlertStatusUpdateRequest,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _paginate_response(items, total: int, page: int, page_size: int) -> AlertListResponse:
    total_pages = (total + page_size - 1) // page_size if page_size else 0
    return AlertListResponse(
        items=[AlertResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    severity: AlertSeverity | None = None,
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    source_ip: str | None = None,
    destination_ip: str | None = None,
    agent_name: str | None = None,
    rule_id: str | None = None,
    hostname: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort_by: str = "timestamp",
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_any_role),
) -> AlertListResponse:
    filters = AlertFilterParams(
        severity=severity,
        status=status_filter,
        source_ip=source_ip,
        destination_ip=destination_ip,
        agent_name=agent_name,
        rule_id=rule_id,
        hostname=hostname,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    items, total = await alert_repository.list_alerts(filters)
    return _paginate_response(items, total, page, page_size)


@router.get("/high", response_model=list[AlertResponse])
async def get_high_severity_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_any_role),
) -> list[AlertResponse]:
    alerts = await alert_repository.get_high_severity(limit=limit)
    return [AlertResponse.model_validate(a) for a in alerts]


@router.get("/recent", response_model=list[AlertResponse])
async def get_recent_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_any_role),
) -> list[AlertResponse]:
    alerts = await alert_repository.get_recent(limit=limit)
    return [AlertResponse.model_validate(a) for a in alerts]


@router.get("/search", response_model=AlertListResponse)
async def search_alerts(
    search: str | None = None,
    severity: AlertSeverity | None = None,
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    source_ip: str | None = None,
    destination_ip: str | None = None,
    agent_name: str | None = None,
    rule_id: str | None = None,
    hostname: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort_by: str = "timestamp",
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_any_role),
) -> AlertListResponse:
    """
    Functionally identical to GET /alerts but with `search` as the
    primary parameter — kept as a distinct, discoverable endpoint since
    the brief calls for an explicit search endpoint, even though the
    underlying filter builder (AlertFilterParams) is shared.
    """
    filters = AlertFilterParams(
        search=search,
        severity=severity,
        status=status_filter,
        source_ip=source_ip,
        destination_ip=destination_ip,
        agent_name=agent_name,
        rule_id=rule_id,
        hostname=hostname,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    items, total = await alert_repository.list_alerts(filters)
    return _paginate_response(items, total, page, page_size)


@router.get("/{alert_id}", response_model=AlertDetailResponse)
async def get_alert(
    alert_id: uuid.UUID,
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_any_role),
) -> AlertDetailResponse:
    alert = await alert_repository.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return AlertDetailResponse.model_validate(alert)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdateRequest,
    alert_repository: AlertRepository = Depends(get_alert_repository),
    _current_user: User = Depends(require_analyst_or_admin),
) -> AlertResponse:
    alert = await alert_repository.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    updated = await alert_repository.update_status(alert, payload.status)
    return AlertResponse.model_validate(updated)

"""
Alert Pydantic schemas.

Purpose:
    Request/response contracts for the alert API. `AlertListResponse`
    wraps results with pagination metadata so the frontend never has to
    guess total counts from response length.
"""

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AlertSeverity, AlertStatus


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    wazuh_alert_id: str
    rule_id: str
    rule_description: str
    severity: AlertSeverity
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    agent_name: str | None
    log_message: str | None
    asset_id: uuid.UUID | None
    status: AlertStatus
    created_at: datetime
    updated_at: datetime


class AlertDetailResponse(AlertResponse):
    """Includes the full raw Wazuh event — only returned on the detail endpoint,
    since it can be large and isn't needed in list views."""
    raw_event: dict[str, Any]


class AlertStatusUpdateRequest(BaseModel):
    status: AlertStatus


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AlertFilterParams(BaseModel):
    """
    Shared query-parameter contract for GET /alerts and GET /alerts/search.
    Kept as its own schema (rather than loose FastAPI Query() params
    scattered in the router) so filter logic is documented and testable
    in one place.
    """
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    agent_name: Optional[str] = None
    rule_id: Optional[str] = None
    hostname: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    search: Optional[str] = None

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=200)
    sort_by: str = Field(default="timestamp")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")

"""Investigation Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import InvestigationStatus


class InvestigationCreateRequest(BaseModel):
    notes: str | None = None
    status: InvestigationStatus = InvestigationStatus.OPEN


class InvestigationUpdateRequest(BaseModel):
    notes: str | None = None
    status: InvestigationStatus | None = None


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    analyst_id: uuid.UUID | None
    notes: str | None
    status: InvestigationStatus
    created_at: datetime

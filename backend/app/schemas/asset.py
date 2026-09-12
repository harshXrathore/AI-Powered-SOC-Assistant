"""Asset Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import AssetCriticality


class AssetCreateRequest(BaseModel):
    hostname: str
    ip_address: str | None = None
    operating_system: str | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    ip_address: str | None
    operating_system: str | None
    criticality: AssetCriticality
    created_at: datetime

"""
Asset model.

Purpose:
    Represents a monitored host/endpoint (typically corresponding to a
    Wazuh agent). Alerts reference an Asset so the risk-scoring engine
    (Phase 5) can factor in asset criticality.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.enums import AssetCriticality


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(AssetCriticality, name="asset_criticality"),
        nullable=False,
        default=AssetCriticality.MEDIUM,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    alerts: Mapped[list["Alert"]] = relationship(back_populates="asset", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Asset {self.hostname} ({self.criticality})>"

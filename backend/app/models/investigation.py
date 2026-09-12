"""
Investigation model.

Purpose:
    Tracks an analyst's work on a specific alert — freeform notes plus a
    workflow status independent of the alert's own status field (an
    alert can be "in_progress" while its investigation has more granular
    history, e.g. reopened after being marked closed).
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.enums import InvestigationStatus


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus, name="investigation_status"),
        nullable=False,
        default=InvestigationStatus.OPEN,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    alert: Mapped["Alert"] = relationship(back_populates="investigations", lazy="selectin")
    analyst: Mapped["User"] = relationship(back_populates="investigations", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Investigation alert={self.alert_id} status={self.status}>"

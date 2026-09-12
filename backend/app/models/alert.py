"""
Alert model.

Purpose:
    Local, queryable copy of a Wazuh alert. Wazuh's indexer is the source
    of truth for raw events, but mirroring alerts into Postgres lets us:
      - query/filter/paginate fast without hitting the Wazuh Indexer API
        on every dashboard load
      - attach analyst workflow state (status, investigations) that
        Wazuh itself has no concept of
      - keep a stable local ID even if the Wazuh deployment is rebuilt

Uniqueness:
    `wazuh_alert_id` is unique — this is the field the sync task uses to
    detect "already stored" vs. "new" alerts (see services/tasks/wazuh_tasks.py).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.enums import AlertSeverity, AlertStatus


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
        Index("ix_alerts_status_timestamp", "status", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Identity in the source system — used for de-duplication on sync.
    wazuh_alert_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)

    rule_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    rule_description: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), nullable=False, index=True
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    log_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"),
        nullable=False,
        default=AlertStatus.NEW,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="alerts", lazy="selectin")
    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="alert", lazy="selectin", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Alert {self.wazuh_alert_id} rule={self.rule_id} severity={self.severity}>"

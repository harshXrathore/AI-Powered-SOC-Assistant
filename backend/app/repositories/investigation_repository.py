"""Investigation repository — data access layer for Investigation model."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.investigation import Investigation
from app.schemas.investigation import InvestigationCreateRequest, InvestigationUpdateRequest


class InvestigationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, investigation_id: uuid.UUID) -> Investigation | None:
        result = await self._session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        return result.scalar_one_or_none()

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[Investigation]:
        result = await self._session.execute(
            select(Investigation)
            .where(Investigation.alert_id == alert_id)
            .order_by(Investigation.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(
        self, alert_id: uuid.UUID, analyst_id: uuid.UUID, data: InvestigationCreateRequest
    ) -> Investigation:
        investigation = Investigation(
            alert_id=alert_id,
            analyst_id=analyst_id,
            notes=data.notes,
            status=data.status,
        )
        self._session.add(investigation)
        await self._session.commit()
        await self._session.refresh(investigation)
        return investigation

    async def update(
        self, investigation: Investigation, data: InvestigationUpdateRequest
    ) -> Investigation:
        if data.notes is not None:
            investigation.notes = data.notes
        if data.status is not None:
            investigation.status = data.status
        await self._session.commit()
        await self._session.refresh(investigation)
        return investigation

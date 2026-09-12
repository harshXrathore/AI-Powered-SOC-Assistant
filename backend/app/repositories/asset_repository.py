"""Asset repository — data access layer for Asset model."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.schemas.asset import AssetCreateRequest


class AssetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, asset_id: uuid.UUID) -> Asset | None:
        result = await self._session.execute(select(Asset).where(Asset.id == asset_id))
        return result.scalar_one_or_none()

    async def get_by_hostname(self, hostname: str) -> Asset | None:
        result = await self._session.execute(select(Asset).where(Asset.hostname == hostname))
        return result.scalar_one_or_none()

    async def create(self, data: AssetCreateRequest) -> Asset:
        asset = Asset(**data.model_dump())
        self._session.add(asset)
        await self._session.commit()
        await self._session.refresh(asset)
        return asset

    async def get_or_create_by_hostname(
        self, hostname: str, ip_address: str | None = None
    ) -> Asset:
        """
        Used by the Wazuh sync task: alerts reference an agent name/hostname
        that may not have an Asset row yet. Rather than dropping the
        asset link or failing sync, we lazily create a minimal Asset
        (default criticality MEDIUM) that an analyst can enrich later.
        """
        existing = await self.get_by_hostname(hostname)
        if existing is not None:
            return existing

        asset = Asset(hostname=hostname, ip_address=ip_address)
        self._session.add(asset)
        await self._session.flush()
        return asset

    async def list_all(self) -> list[Asset]:
        result = await self._session.execute(select(Asset).order_by(Asset.hostname))
        return list(result.scalars().all())

"""
Repository dependency factories.

Purpose:
    Thin `Depends()` wrappers that construct repository instances bound
    to the request-scoped DB session. Keeps routers free of
    `SomeRepository(db)` boilerplate repeated on every endpoint.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.user_repository import UserRepository


def get_alert_repository(db: AsyncSession = Depends(get_db)) -> AlertRepository:
    return AlertRepository(db)


def get_asset_repository(db: AsyncSession = Depends(get_db)) -> AssetRepository:
    return AssetRepository(db)


def get_investigation_repository(db: AsyncSession = Depends(get_db)) -> InvestigationRepository:
    return InvestigationRepository(db)


def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    return UserRepository(db)

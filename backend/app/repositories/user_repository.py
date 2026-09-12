"""
User repository.

Purpose:
    All direct SQLAlchemy queries against the User table live here.
    Services (app/services/auth_service.py) call into this repository
    rather than building queries themselves — keeps query logic in one
    place and services focused on business rules (password checks, token
    issuance) instead of ORM mechanics.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.schemas.user import UserRegisterRequest


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        result = await self._session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> User | None:
        result = await self._session.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        result = await self._session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create(self, data: UserRegisterRequest, hashed_password: str) -> User:
        user = User(
            username=data.username,
            email=data.email,
            hashed_password=hashed_password,
            role=data.role,
        )
        self._session.add(user)
        await self._session.commit()
        await self._session.refresh(user)
        return user

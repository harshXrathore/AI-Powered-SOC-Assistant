"""
Database session management.

Purpose:
    Provides the async SQLAlchemy engine, session factory, declarative base,
    and a FastAPI dependency (`get_db`) that yields a scoped session per
    request and guarantees it is closed/rolled back correctly.
"""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger(__name__)

_engine_kwargs: dict = {
    "echo": (settings.ENVIRONMENT == "development"),
    "pool_pre_ping": True,
}
# SQLite (used in the test suite) doesn't support pool_size/max_overflow —
# those are pool-implementation-specific to Postgres/MySQL-style pools.
if not settings.DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["pool_size"] = 10
    _engine_kwargs["max_overflow"] = 20

engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model in app/models/."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields a request-scoped async session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Create tables on startup in development only, as a convenience.
    Staging/production must use Alembic migrations — see docs/DATABASE.md.
    """
    if settings.ENVIRONMENT != "development":
        logger.info("Skipping create_all outside development; use Alembic migrations.")
        return
    # Import models so they're registered on Base.metadata before create_all.
    from app.models import alert, asset, investigation, user  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

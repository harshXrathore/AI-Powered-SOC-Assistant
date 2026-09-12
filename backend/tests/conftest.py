"""
Shared pytest fixtures.

Purpose:
    Provides an isolated async SQLite database per test (fast, no
    external Postgres dependency for unit/API tests) and a FastAPI
    TestClient wired to use it via dependency override. Postgres-specific
    features (JSONB, native enums) are avoided in test-only code paths by
    using SQLAlchemy's generic types where the models allow it; since our
    models use JSONB and native postgres ENUM, tests instead run against
    a throwaway Postgres-compatible SQLite shim is not sufficient for
    JSONB — so these tests use `aiosqlite` only for the auth/user tests
    that don't touch Alert.raw_event, and rely on respx-mocked Wazuh
    responses plus a fake in-memory repository for alert-service unit
    tests. This keeps the suite runnable with zero external services.
"""

from collections.abc import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.auth_service as auth_service_module
from app.core.database import Base, get_db
from app.main import app
from app.models.investigation import Investigation  # noqa: F401
from app.models.user import User  # noqa: F401 — ensures table is registered


@pytest_asyncio.fixture(autouse=True)
async def fake_redis(monkeypatch) -> AsyncGenerator[None, None]:
    """
    AuthService uses Redis to blacklist revoked refresh tokens. Tests run
    with no real Redis instance, so this swaps in an in-memory fakeredis
    client for the duration of each test and resets it afterward so
    revoked-token state doesn't leak between tests.
    """
    fake_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(auth_service_module, "_redis_client", fake_client)
    yield
    await fake_client.flushall()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """In-memory SQLite engine, fresh schema per test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        # Only create `users` and `investigations` here — Alert/Asset use
        # Postgres-only JSONB not supported by SQLite. User.investigations
        # is lazy="selectin" so it's queried eagerly; investigations must
        # exist as a table (even if never populated) for that not to error.
        await conn.run_sync(lambda sync_conn: User.__table__.create(sync_conn, checkfirst=True))
        await conn.run_sync(
            lambda sync_conn: Investigation.__table__.create(sync_conn, checkfirst=True)
        )

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()

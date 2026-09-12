"""
Auth service.

Purpose:
    Business logic for registration, login, and token refresh. Sits
    between the auth router and UserRepository — handles password
    verification, duplicate-account checks, and token issuance, so the
    router stays a thin HTTP translation layer.

Note on refresh token revocation:
    Phase 2 uses stateless JWT refresh tokens (no server-side session
    table), consistent with "no placeholder implementations" while
    keeping scope bounded — a refresh token is valid until it expires or
    logout blacklists it via Redis (see logout()). A denylist entry is
    checked on every refresh; this gives real logout semantics without a
    full session-table migration.
"""

import uuid

import redis.asyncio as aioredis

from app.core.config import settings
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user import TokenResponse, UserRegisterRequest

_redis_client: aioredis.Redis | None = None


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


class AuthError(Exception):
    """Raised for any auth failure — router maps this to HTTP 401/403/409."""


class AuthService:
    def __init__(self, user_repository: UserRepository) -> None:
        self._users = user_repository

    async def register(self, data: UserRegisterRequest) -> User:
        if await self._users.get_by_username(data.username) is not None:
            raise AuthError("Username already registered")
        if await self._users.get_by_email(data.email) is not None:
            raise AuthError("Email already registered")

        hashed = hash_password(data.password)
        return await self._users.create(data, hashed)

    async def authenticate(self, username: str, password: str) -> User:
        user = await self._users.get_by_username(username)
        if user is None or not verify_password(password, user.hashed_password):
            raise AuthError("Invalid username or password")
        if not user.is_active:
            raise AuthError("Account is deactivated")
        return user

    def issue_tokens(self, user: User) -> TokenResponse:
        access = create_access_token(user.id, user.role.value)
        refresh = create_refresh_token(user.id, user.role.value)
        return TokenResponse(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def refresh_access_token(self, refresh_token: str) -> str:
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except TokenError as exc:
            raise AuthError(str(exc)) from exc

        redis_client = _get_redis()
        if await redis_client.exists(f"revoked_token:{refresh_token}"):
            raise AuthError("Refresh token has been revoked")

        user_id = uuid.UUID(payload["sub"])
        user = await self._users.get_by_id(user_id)
        if user is None or not user.is_active:
            raise AuthError("User no longer active")

        return create_access_token(user.id, user.role.value)

    async def logout(self, refresh_token: str) -> None:
        """
        Blacklists the refresh token in Redis until its natural expiry,
        so a stolen-but-logged-out token can't mint new access tokens.
        """
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except TokenError:
            return  # already invalid — nothing to revoke

        redis_client = _get_redis()
        ttl_seconds = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
        await redis_client.set(f"revoked_token:{refresh_token}", "1", ex=ttl_seconds)
        _ = payload  # payload unused beyond validation

"""
Security primitives: password hashing and JWT encode/decode.

Purpose:
    Isolates all cryptographic operations (bcrypt hashing, JWT signing/
    verification) in one module so the rest of the app never touches
    `jose` or `passlib` directly. Keeps token structure and expiry rules
    consistent across login, refresh, and registration.

Architecture:
    Two token types are issued on login:
      - access token  (short-lived, ~30 min, sent on every request)
      - refresh token (long-lived, ~7 days, used only to mint new access
        tokens via POST /auth/refresh)
    Both are signed HS256 JWTs carrying `sub` (user id), `role`, and a
    `type` claim ("access" | "refresh") so a refresh token can't be used
    as an access token even if replayed against a protected endpoint.

Dependencies:
    passlib[bcrypt] for hashing, python-jose[cryptography] for JWT.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Raised when a JWT is missing, malformed, expired, or the wrong type."""


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _create_token(subject: UUID, role: str, token_type: TokenType, expires_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(subject: UUID, role: str) -> str:
    return _create_token(
        subject,
        role,
        "access",
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(subject: UUID, role: str) -> str:
    return _create_token(
        subject,
        role,
        "refresh",
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str, expected_type: Optional[TokenType] = None) -> dict[str, Any]:
    """
    Decodes and validates a JWT. Raises TokenError on any problem —
    callers translate that into an HTTP 401, keeping this module free of
    any FastAPI/HTTP concerns.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise TokenError(f"Invalid token: {exc}") from exc

    if expected_type is not None and payload.get("type") != expected_type:
        raise TokenError(f"Expected a {expected_type} token, got {payload.get('type')}")

    return payload

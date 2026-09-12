"""
Auth dependencies.

Purpose:
    FastAPI `Depends()` callables that extract and validate the bearer
    token on protected routes, load the corresponding User, and enforce
    role-based access control. Routers declare their requirements
    declaratively, e.g.:

        @router.delete(...)
        async def delete_thing(user: User = Depends(require_role(UserRole.ADMIN))):
            ...

    rather than hand-rolling permission checks inline.
"""

import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import TokenError, decode_token
from app.models.enums import UserRole
from app.models.user import User
from app.repositories.user_repository import UserRepository

# tokenUrl is documentation-only (points Swagger's "Authorize" button at
# the login endpoint) — this project uses JSON bodies, not OAuth2 form data.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token is None:
        raise credentials_exception

    try:
        payload = decode_token(token, expected_type="access")
    except TokenError as exc:
        raise credentials_exception from exc

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise credentials_exception from exc

    user_repository = UserRepository(db)
    user = await user_repository.get_by_id(user_id)
    if user is None or not user.is_active:
        raise credentials_exception

    return user


def require_role(*allowed_roles: UserRole):
    """
    Returns a dependency that only passes if the current user's role is
    one of `allowed_roles`. Admin is not implicitly all-access on
    purpose — each protected endpoint states exactly which roles it
    accepts, which is easier to audit than an implicit hierarchy.
    """

    async def _check_role(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return _check_role


# Common shorthand dependencies used across routers.
require_admin = require_role(UserRole.ADMIN)
require_analyst_or_admin = require_role(UserRole.ADMIN, UserRole.ANALYST)
require_any_role = require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.READONLY)

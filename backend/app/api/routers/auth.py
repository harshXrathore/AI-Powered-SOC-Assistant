"""
Auth router.

API endpoints:
    POST /api/v1/auth/register  -> create a new user account
    POST /api/v1/auth/login     -> authenticate, receive access+refresh tokens
    POST /api/v1/auth/refresh   -> exchange a refresh token for a new access token
    POST /api/v1/auth/logout    -> revoke a refresh token
    GET  /api/v1/auth/me        -> current authenticated user's profile
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.auth import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user import (
    AccessTokenResponse,
    LogoutRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.services.auth_service import AuthError, AuthService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(UserRepository(db))


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> User:
    try:
        user = await auth_service.register(payload)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    logger.info("user_registered", username=user.username, role=user.role.value)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: UserLoginRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    try:
        user = await auth_service.authenticate(payload.username, payload.password)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    logger.info("user_logged_in", username=user.username)
    return auth_service.issue_tokens(user)


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(
    payload: RefreshTokenRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> AccessTokenResponse:
    try:
        access_token = await auth_service.refresh_access_token(payload.refresh_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    from app.core.config import settings

    return AccessTokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: LogoutRequest,
    auth_service: AuthService = Depends(_get_auth_service),
) -> None:
    await auth_service.logout(payload.refresh_token)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user

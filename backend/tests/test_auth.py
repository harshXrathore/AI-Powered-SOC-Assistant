"""
Auth API tests.

Covers registration, duplicate rejection, login success/failure, the
/auth/me protected endpoint, and refresh-token exchange.
"""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _register(client: AsyncClient, username="alice", email="alice@example.com", password="Passw0rd!", role="analyst"):
    return await client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password, "role": role},
    )


async def test_register_creates_user(client: AsyncClient):
    response = await _register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "alice"
    assert body["role"] == "analyst"
    assert "hashed_password" not in body


async def test_register_duplicate_username_rejected(client: AsyncClient):
    await _register(client)
    response = await _register(client, email="different@example.com")
    assert response.status_code == 409


async def test_login_success_returns_tokens(client: AsyncClient):
    await _register(client)
    response = await client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "Passw0rd!"}
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


async def test_login_wrong_password_rejected(client: AsyncClient):
    await _register(client)
    response = await client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "wrong-password"}
    )
    assert response.status_code == 401


async def test_me_requires_authentication(client: AsyncClient):
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


async def test_me_returns_current_user(client: AsyncClient):
    await _register(client)
    login_response = await client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "Passw0rd!"}
    )
    access_token = login_response.json()["access_token"]

    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json()["username"] == "alice"


async def test_refresh_returns_new_access_token(client: AsyncClient):
    await _register(client)
    login_response = await client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "Passw0rd!"}
    )
    refresh_token = login_response.json()["refresh_token"]

    response = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

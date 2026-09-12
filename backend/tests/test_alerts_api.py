"""
Alert API tests.

Overrides get_alert_repository and the role-check dependencies with fakes
so these tests exercise router logic (query param parsing, RBAC, status
codes, response shaping) without needing a real Postgres-backed Alert
table (SQLite can't hold the JSONB/native-enum columns Alert uses).
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dependencies.auth import require_analyst_or_admin, require_any_role
from app.api.dependencies.repositories import get_alert_repository
from app.main import app
from app.models.enums import AlertSeverity, AlertStatus, UserRole

pytestmark = pytest.mark.asyncio


def _fake_alert(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        wazuh_alert_id="wz-001",
        rule_id="5710",
        rule_description="sshd brute force attempt",
        severity=AlertSeverity.HIGH,
        timestamp=datetime.now(timezone.utc),
        source_ip="203.0.113.5",
        destination_ip=None,
        agent_name="web-server-01",
        log_message="Invalid user admin",
        raw_event={"rule": {"id": "5710"}},
        asset_id=None,
        status=AlertStatus.NEW,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class FakeAlertRepository:
    def __init__(self, alerts=None):
        self.alerts = alerts or [_fake_alert()]

    async def list_alerts(self, filters):
        return self.alerts, len(self.alerts)

    async def get_high_severity(self, limit=50):
        return [a for a in self.alerts if a.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)]

    async def get_recent(self, limit=50):
        return self.alerts

    async def get_by_id(self, alert_id):
        return next((a for a in self.alerts if a.id == alert_id), None)

    async def update_status(self, alert, status):
        alert.status = status
        return alert


@pytest.fixture
def fake_analyst_user():
    return SimpleNamespace(id=uuid.uuid4(), username="analyst1", role=UserRole.ANALYST, is_active=True)


@pytest.fixture
def fake_readonly_user():
    return SimpleNamespace(id=uuid.uuid4(), username="viewer1", role=UserRole.READONLY, is_active=True)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


async def _make_client() -> AsyncClient:
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


async def test_list_alerts_returns_paginated_response(fake_analyst_user):
    repo = FakeAlertRepository()
    app.dependency_overrides[get_alert_repository] = lambda: repo
    app.dependency_overrides[require_any_role] = lambda: fake_analyst_user

    async with await _make_client() as client:
        response = await client.get("/api/v1/alerts")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["wazuh_alert_id"] == "wz-001"


async def test_get_alert_detail_includes_raw_event(fake_analyst_user):
    repo = FakeAlertRepository()
    app.dependency_overrides[get_alert_repository] = lambda: repo
    app.dependency_overrides[require_any_role] = lambda: fake_analyst_user

    alert_id = repo.alerts[0].id
    async with await _make_client() as client:
        response = await client.get(f"/api/v1/alerts/{alert_id}")

    assert response.status_code == 200
    assert response.json()["raw_event"] == {"rule": {"id": "5710"}}


async def test_get_alert_detail_404_when_missing(fake_analyst_user):
    repo = FakeAlertRepository()
    app.dependency_overrides[get_alert_repository] = lambda: repo
    app.dependency_overrides[require_any_role] = lambda: fake_analyst_user

    async with await _make_client() as client:
        response = await client.get(f"/api/v1/alerts/{uuid.uuid4()}")

    assert response.status_code == 404


async def test_update_status_allowed_for_analyst(fake_analyst_user):
    repo = FakeAlertRepository()
    app.dependency_overrides[get_alert_repository] = lambda: repo
    app.dependency_overrides[require_analyst_or_admin] = lambda: fake_analyst_user

    alert_id = repo.alerts[0].id
    async with await _make_client() as client:
        response = await client.patch(
            f"/api/v1/alerts/{alert_id}/status", json={"status": "resolved"}
        )

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


async def test_update_status_forbidden_for_readonly(fake_readonly_user):
    """
    require_analyst_or_admin is a real dependency here (not overridden),
    so a ReadOnly user's role check fails with 403 — this proves RBAC is
    enforced, not just documented.
    """
    from app.api.dependencies.auth import get_current_user

    repo = FakeAlertRepository()
    app.dependency_overrides[get_alert_repository] = lambda: repo
    app.dependency_overrides[get_current_user] = lambda: fake_readonly_user

    alert_id = repo.alerts[0].id
    async with await _make_client() as client:
        response = await client.patch(
            f"/api/v1/alerts/{alert_id}/status", json={"status": "resolved"}
        )

    assert response.status_code == 403


async def test_high_severity_endpoint_filters_correctly(fake_analyst_user):
    repo = FakeAlertRepository(
        alerts=[
            _fake_alert(severity=AlertSeverity.LOW, wazuh_alert_id="wz-low"),
            _fake_alert(severity=AlertSeverity.CRITICAL, wazuh_alert_id="wz-crit"),
        ]
    )
    app.dependency_overrides[get_alert_repository] = lambda: repo
    app.dependency_overrides[require_any_role] = lambda: fake_analyst_user

    async with await _make_client() as client:
        response = await client.get("/api/v1/alerts/high")

    body = response.json()
    assert len(body) == 1
    assert body[0]["wazuh_alert_id"] == "wz-crit"

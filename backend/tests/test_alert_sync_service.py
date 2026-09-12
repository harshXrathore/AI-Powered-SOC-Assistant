"""
AlertSyncService unit tests.

Uses lightweight fake repositories instead of real SQLAlchemy sessions —
this service's logic (field extraction, severity bucketing, new-vs-updated
tracking) doesn't depend on actual persistence, so faking the repository
interface keeps these tests fast and DB-free.
"""

import uuid
from types import SimpleNamespace

import pytest

from app.models.enums import AlertSeverity
from app.services.alert_sync_service import AlertSyncService, _extract_fields


class FakeAlertRepository:
    def __init__(self):
        self.stored: dict[str, dict] = {}
        self.committed = False

    async def get_by_wazuh_id(self, wazuh_alert_id: str):
        return self.stored.get(wazuh_alert_id)

    async def upsert_from_wazuh(self, wazuh_alert_id: str, values: dict):
        was_created = wazuh_alert_id not in self.stored
        self.stored[wazuh_alert_id] = values
        fake_alert = SimpleNamespace(id=uuid.uuid4(), wazuh_alert_id=wazuh_alert_id, **values)
        return fake_alert, was_created

    async def commit(self):
        self.committed = True


class FakeAssetRepository:
    def __init__(self):
        self.assets: dict[str, SimpleNamespace] = {}

    async def get_or_create_by_hostname(self, hostname: str, ip_address: str | None = None):
        if hostname not in self.assets:
            self.assets[hostname] = SimpleNamespace(id=uuid.uuid4(), hostname=hostname)
        return self.assets[hostname]


SAMPLE_WAZUH_ALERT = {
    "_id": "wz-001",
    "timestamp": "2026-07-05T10:00:00.000+0000",
    "rule": {"id": "5710", "description": "sshd: Attempt to login using a non-existent user", "level": 5},
    "agent": {"name": "web-server-01"},
    "data": {"srcip": "203.0.113.5"},
    "full_log": "Jul  5 10:00:00 sshd[1234]: Invalid user admin from 203.0.113.5",
}


def test_extract_fields_maps_severity_correctly():
    fields = _extract_fields(SAMPLE_WAZUH_ALERT)
    assert fields["severity"] == AlertSeverity.MEDIUM  # level 5 -> medium
    assert fields["rule_id"] == "5710"
    assert fields["source_ip"] == "203.0.113.5"
    assert fields["agent_name"] == "web-server-01"


def test_extract_fields_critical_level():
    critical_alert = {**SAMPLE_WAZUH_ALERT, "rule": {"id": "100", "description": "x", "level": 14}}
    fields = _extract_fields(critical_alert)
    assert fields["severity"] == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_sync_alert_creates_new_and_links_asset():
    alert_repo = FakeAlertRepository()
    asset_repo = FakeAssetRepository()
    service = AlertSyncService(alert_repo, asset_repo)

    was_created = await service.sync_alert(SAMPLE_WAZUH_ALERT)

    assert was_created is True
    assert "wz-001" in alert_repo.stored
    assert "web-server-01" in asset_repo.assets


@pytest.mark.asyncio
async def test_sync_alert_second_call_is_update_not_create():
    alert_repo = FakeAlertRepository()
    asset_repo = FakeAssetRepository()
    service = AlertSyncService(alert_repo, asset_repo)

    first = await service.sync_alert(SAMPLE_WAZUH_ALERT)
    second = await service.sync_alert(SAMPLE_WAZUH_ALERT)

    assert first is True
    assert second is False  # same wazuh_alert_id -> update, not duplicate


@pytest.mark.asyncio
async def test_sync_alert_missing_id_raises():
    alert_repo = FakeAlertRepository()
    asset_repo = FakeAssetRepository()
    service = AlertSyncService(alert_repo, asset_repo)

    with pytest.raises(ValueError):
        await service.sync_alert({"rule": {"id": "1", "level": 1}})


@pytest.mark.asyncio
async def test_sync_alerts_batch_reports_stats():
    alert_repo = FakeAlertRepository()
    asset_repo = FakeAssetRepository()
    service = AlertSyncService(alert_repo, asset_repo)

    second_alert = {**SAMPLE_WAZUH_ALERT, "_id": "wz-002"}
    stats = await service.sync_alerts([SAMPLE_WAZUH_ALERT, second_alert, SAMPLE_WAZUH_ALERT])

    assert stats["new"] == 2
    assert stats["updated"] == 1
    assert stats["errors"] == 0
    assert stats["total"] == 3
    assert alert_repo.committed is True

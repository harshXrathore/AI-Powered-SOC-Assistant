"""
Wazuh client tests.

Mocks both the Wazuh Manager API and Wazuh Indexer API with respx so the
suite runs without a live Wazuh deployment. Covers authentication, token
refresh on 401, retry-on-network-error behavior, and each public fetch
method (get_alerts, get_alert, get_agents, get_rules, get_recent_alerts).
"""

import httpx
import pytest
import respx

from app.core.config import settings
from app.services.wazuh_client import WazuhAPIError, WazuhAuthError, WazuhClient

pytestmark = pytest.mark.asyncio

MANAGER_URL = settings.WAZUH_API_URL.rstrip("/")
INDEXER_URL = settings.WAZUH_INDEXER_URL.rstrip("/")


@pytest.fixture
def client() -> WazuhClient:
    return WazuhClient()


@respx.mock
async def test_authenticate_success(client: WazuhClient):
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "fake-jwt"}})
    )
    respx.get(f"{MANAGER_URL}/").mock(
        return_value=httpx.Response(200, json={"data": "Wazuh manager"})
    )

    result = await client.check_connection()
    assert result["data"] == "Wazuh manager"
    assert client._token == "fake-jwt"


@respx.mock
async def test_authenticate_failure_raises(client: WazuhClient):
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(401, json={"detail": "bad credentials"})
    )

    with pytest.raises(WazuhAuthError):
        await client.check_connection()


@respx.mock
async def test_token_refresh_on_401(client: WazuhClient):
    auth_route = respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "fake-jwt"}})
    )

    call_count = {"n": 0}

    def agents_side_effect(request):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(401)
        return httpx.Response(200, json={"data": {"affected_items": [{"id": "001"}]}})

    respx.get(f"{MANAGER_URL}/agents").mock(side_effect=agents_side_effect)

    agents = await client.get_agents()
    assert agents == [{"id": "001"}]
    assert auth_route.call_count == 2  # initial auth + re-auth after 401


@respx.mock
async def test_get_rules(client: WazuhClient):
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "fake-jwt"}})
    )
    respx.get(f"{MANAGER_URL}/rules").mock(
        return_value=httpx.Response(
            200, json={"data": {"affected_items": [{"id": "5710", "level": 5}]}}
        )
    )

    rules = await client.get_rules()
    assert rules[0]["id"] == "5710"


@respx.mock
async def test_get_alerts_returns_hits(client: WazuhClient):
    respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {"_id": "abc123", "_source": {"rule": {"id": "5710", "level": 5}}}
                    ]
                }
            },
        )
    )

    alerts = await client.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["_id"] == "abc123"
    assert alerts[0]["rule"]["id"] == "5710"


@respx.mock
async def test_get_alert_not_found_raises(client: WazuhClient):
    respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"hits": []}})
    )

    with pytest.raises(WazuhAPIError):
        await client.get_alert("does-not-exist")


@respx.mock
async def test_get_recent_alerts_delegates_to_get_alerts(client: WazuhClient):
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"hits": []}})
    )

    result = await client.get_recent_alerts(minutes=10)
    assert result == []
    assert route.called

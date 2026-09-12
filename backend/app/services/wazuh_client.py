"""
Wazuh API client.

Purpose:
    Async wrapper around the Wazuh Manager REST API (port 55000) and the
    Wazuh Indexer (Elasticsearch-compatible, port 9200) where alert
    documents actually live. Handles authentication, transparent token
    refresh on 401, retry with backoff on transient network errors, and
    timeout handling.

Architecture:
    - Manager API: agents, rules, and manager status/info.
    - Indexer API: alerts themselves (Wazuh stores alerts as documents in
      the `wazuh-alerts-*` index pattern, not via the Manager API).
    Both share the same retry/timeout wrapper so callers don't repeat
    error-handling boilerplate.

Testing:
    See backend/tests/test_wazuh_client.py — mocks both APIs with respx
    so tests run without a live Wazuh deployment.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings

logger = logging.getLogger(__name__)

RETRYABLE_EXCEPTIONS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout)


class WazuhAuthError(Exception):
    """Raised when authentication with the Wazuh Manager API fails."""


class WazuhAPIError(Exception):
    """Raised for non-2xx responses from either the Manager or Indexer API."""


class WazuhClient:
    def __init__(self) -> None:
        self._base_url = settings.WAZUH_API_URL.rstrip("/")
        self._user = settings.WAZUH_API_USER
        self._password = settings.WAZUH_API_PASSWORD
        self._verify_ssl = settings.WAZUH_VERIFY_SSL
        self._token: Optional[str] = None

        self._manager_client = httpx.AsyncClient(
            base_url=self._base_url,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        self._indexer_client = httpx.AsyncClient(
            base_url=settings.WAZUH_INDEXER_URL.rstrip("/"),
            verify=self._verify_ssl,
            auth=(settings.WAZUH_INDEXER_USER, settings.WAZUH_INDEXER_PASSWORD),
            timeout=httpx.Timeout(15.0, connect=5.0),
        )

    # ---------- Auth ----------

    async def _authenticate(self) -> str:
        """POST /security/user/authenticate — returns a short-lived JWT (~15 min)."""
        response = await self._manager_client.post(
            "/security/user/authenticate",
            auth=(self._user, self._password),
        )
        if response.status_code != 200:
            logger.error(
                "wazuh_auth_failed",
                extra={"status_code": response.status_code, "body": response.text},
            )
            raise WazuhAuthError(
                f"Wazuh authentication failed with status {response.status_code}"
            )
        token = response.json()["data"]["token"]
        self._token = token
        return token

    @retry(
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        reraise=True,
    )
    async def _manager_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """
        Authenticated request against the Manager API with automatic
        token refresh on 401 and retry-with-backoff on transient network
        errors (connection refused, timeouts). Non-network 4xx/5xx errors
        are NOT retried — retrying a malformed request just repeats the
        same failure three times.
        """
        if self._token is None:
            await self._authenticate()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        response = await self._manager_client.request(method, path, headers=headers, **kwargs)

        if response.status_code == 401:
            await self._authenticate()
            headers["Authorization"] = f"Bearer {self._token}"
            response = await self._manager_client.request(method, path, headers=headers, **kwargs)

        if response.status_code >= 500:
            # Raise a retryable-typed exception so tenacity's decorator
            # treats transient 5xx the same as a network-level failure.
            raise httpx.ReadTimeout(f"Wazuh Manager returned {response.status_code}")

        return response

    @retry(
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        reraise=True,
    )
    async def _indexer_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = await self._indexer_client.request(method, path, **kwargs)
        if response.status_code >= 500:
            raise httpx.ReadTimeout(f"Wazuh Indexer returned {response.status_code}")
        return response

    # ---------- Connectivity ----------

    async def check_connection(self) -> dict:
        response = await self._manager_request("GET", "/")
        if response.status_code != 200:
            raise WazuhAPIError(f"Manager API returned {response.status_code}: {response.text}")
        return response.json()

    # ---------- Agents / Rules ----------

    async def get_agents(self, limit: int = 500) -> list[dict[str, Any]]:
        response = await self._manager_request("GET", "/agents", params={"limit": limit})
        if response.status_code != 200:
            raise WazuhAPIError(f"get_agents failed: {response.status_code} {response.text}")
        return response.json()["data"]["affected_items"]

    async def get_rules(self, limit: int = 500) -> list[dict[str, Any]]:
        response = await self._manager_request("GET", "/rules", params={"limit": limit})
        if response.status_code != 200:
            raise WazuhAPIError(f"get_rules failed: {response.status_code} {response.text}")
        return response.json()["data"]["affected_items"]

    # ---------- Alerts (Indexer) ----------

    async def get_alerts(
        self,
        since: Optional[datetime] = None,
        limit: int = 500,
        index_pattern: str = "wazuh-alerts-*",
    ) -> list[dict[str, Any]]:
        """
        Queries the Wazuh Indexer's alert index for alerts at or after
        `since` (defaults to no lower bound), sorted oldest-first so the
        sync task can process them in order and safely resume from the
        last-seen timestamp.
        """
        query: dict[str, Any] = {
            "size": limit,
            "sort": [{"timestamp": {"order": "asc"}}],
        }
        if since is not None:
            query["query"] = {
                "range": {"timestamp": {"gte": since.astimezone(timezone.utc).isoformat()}}
            }
        else:
            query["query"] = {"match_all": {}}

        response = await self._indexer_request("POST", f"/{index_pattern}/_search", json=query)
        if response.status_code != 200:
            raise WazuhAPIError(f"get_alerts failed: {response.status_code} {response.text}")

        hits = response.json()["hits"]["hits"]
        return [hit["_source"] | {"_id": hit["_id"]} for hit in hits]

    async def get_alert(self, alert_id: str, index_pattern: str = "wazuh-alerts-*") -> dict[str, Any]:
        """Fetches a single alert document by its Indexer `_id`."""
        query = {"query": {"term": {"_id": alert_id}}, "size": 1}
        response = await self._indexer_request("POST", f"/{index_pattern}/_search", json=query)
        if response.status_code != 200:
            raise WazuhAPIError(f"get_alert failed: {response.status_code} {response.text}")

        hits = response.json()["hits"]["hits"]
        if not hits:
            raise WazuhAPIError(f"Alert {alert_id} not found")
        return hits[0]["_source"] | {"_id": hits[0]["_id"]}

    async def get_recent_alerts(self, minutes: int = 5, limit: int = 500) -> list[dict[str, Any]]:
        """Convenience wrapper used by the Celery sync task's polling loop."""
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return await self.get_alerts(since=since, limit=limit)

    async def close(self) -> None:
        await self._manager_client.aclose()
        await self._indexer_client.aclose()


async def get_wazuh_client() -> WazuhClient:
    """FastAPI dependency factory — see app/api/dependencies/wazuh.py."""
    return WazuhClient()

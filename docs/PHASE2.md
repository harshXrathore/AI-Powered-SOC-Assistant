# Phase 2 — Backend Foundation

## 1. Authentication flow

```
POST /auth/register  { username, email, password, role }  -> 201 UserResponse
POST /auth/login      { username, password }               -> 200 TokenResponse
                                                                (access_token, refresh_token)
GET  /auth/me         Authorization: Bearer <access_token>  -> 200 UserResponse
POST /auth/refresh    { refresh_token }                     -> 200 AccessTokenResponse
POST /auth/logout     { refresh_token }                     -> 204 (revokes the refresh token)
```

- Passwords are hashed with bcrypt via Passlib (`app/core/security.py`) — never stored or
  logged in plaintext.
- **Access tokens** (HS256 JWT, 30 min default) are sent as `Authorization: Bearer <token>`
  on every protected request.
- **Refresh tokens** (7 days default) are only ever sent to `/auth/refresh` to mint a new
  access token. Both token types carry a `type` claim (`access` | `refresh`) so one can't be
  used in place of the other even if a client mixes them up.
- **Logout** blacklists the refresh token in Redis until its natural expiry — this gives real
  revocation semantics without a server-side session table.
- **Roles**: `admin`, `analyst`, `readonly`. Every protected endpoint states exactly which
  roles it accepts via `Depends(require_role(...))` — see `app/api/dependencies/auth.py`.
  There is no implicit "admin can do everything" — it's explicit per-endpoint.

## 2. Database schema

| Table            | Purpose                                             | Key relationships                          |
|-------------------|------------------------------------------------------|---------------------------------------------|
| `users`           | Accounts + role                                      | 1—N `investigations.analyst_id`             |
| `assets`          | Monitored hosts (mirrors Wazuh agents)               | 1—N `alerts.asset_id`                       |
| `alerts`          | Local copy of Wazuh alerts + analyst workflow state  | N—1 `assets`, 1—N `investigations`          |
| `investigations`  | Analyst notes/status per alert                       | N—1 `alerts`, N—1 `users`                   |

`alerts.wazuh_alert_id` is unique — this is the de-duplication key the sync task relies on.
Composite indexes on `(severity, timestamp)` and `(status, timestamp)` back the dashboard's
aggregate queries and the alert list's default sort.

## 3. API endpoints

### Alerts

| Method | Path                        | Roles              | Notes |
|--------|------------------------------|----------------------|-------|
| GET    | `/alerts`                   | any                  | Paginated, filtered, sorted |
| GET    | `/alerts/high`               | any                  | Critical + High only |
| GET    | `/alerts/recent`             | any                  | Most recent regardless of severity |
| GET    | `/alerts/search`             | any                  | Same filters as `/alerts`, `search` is primary param |
| GET    | `/alerts/{id}`               | any                  | Includes full `raw_event` |
| PATCH  | `/alerts/{id}/status`        | admin, analyst       | ReadOnly gets 403 |

Filter/sort parameters (shared across list/search): `severity`, `status`, `source_ip`,
`destination_ip`, `agent_name`, `rule_id`, `hostname`, `date_from`, `date_to`, `search`,
`page`, `page_size` (max 200), `sort_by` (`timestamp`|`severity`|`status`|`created_at`|`rule_id`),
`sort_order` (`asc`|`desc`).

### Dashboard

| Method | Path                | Returns |
|--------|----------------------|---------|
| GET    | `/dashboard/summary` | total alerts, severity counts, alerts in last 24h, top 10 attacking IPs, top 10 rules, hourly trend (24h) |

## 4. WebSocket endpoint

```
WS /api/v1/ws/alerts?token=<access_token>
```

- Token is passed as a query parameter (browsers can't set custom headers during the
  WebSocket handshake) and validated the same way as REST access tokens. An invalid/expired
  token closes the connection with code `4401`.
- Pushes a JSON message for every **newly created** alert (not updates to existing ones):
  `{"event": "new_alert", "wazuh_alert_id", "rule_id", "rule_description", "level", "agent_name", "timestamp"}`.
- On reconnect, the client isn't replayed history — call `GET /alerts/recent` after
  reconnecting to catch up on anything missed while offline.

## 5. Wazuh synchronization process

1. Celery Beat triggers `sync_wazuh_alerts` every `WAZUH_SYNC_INTERVAL_SECONDS` (default 60s).
2. The task calls `WazuhClient.get_recent_alerts(minutes=WAZUH_SYNC_LOOKBACK_MINUTES)` —
   the lookback window (default 5 min) intentionally overlaps between runs to tolerate clock
   drift or a slow previous run.
3. `AlertSyncService` extracts the relevant fields from each raw Wazuh alert document,
   maps the numeric rule level to a severity bucket (`app/utils/severity.py`), lazily
   creates an `Asset` row for the reporting agent if one doesn't exist yet, and upserts the
   `Alert` row keyed on `wazuh_alert_id`.
4. Alerts that were newly created (not updates) are published to a Redis channel
   (`soc:new_alerts`); a background listener inside the FastAPI process
   (`app/services/redis_listener.py`) forwards them to every connected WebSocket client.
5. The task logs `new`, `updated`, `errors`, and `total` counts as structured fields.

## 6. Running migrations

```bash
cd backend

# Apply all migrations (creates users/assets/alerts/investigations tables + enums)
alembic upgrade head

# After changing a model, generate a new migration
alembic revision --autogenerate -m "describe the change"

# Roll back one migration
alembic downgrade -1

# Roll back everything
alembic downgrade base
```

`alembic/env.py` reads `DATABASE_URL_SYNC` (a `psycopg2` URL) rather than the app's async
`DATABASE_URL` — Alembic's autogenerate machinery needs a synchronous engine.

## 7. Testing

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

- `test_auth.py` — registration, login, `/auth/me`, refresh, against an in-memory SQLite DB.
- `test_alerts_api.py` — alert endpoints with a fake repository via dependency override
  (proves RBAC, pagination shape, 404 handling, status updates) without needing Postgres.
- `test_alert_sync_service.py` — Wazuh alert field extraction, severity bucketing, and
  new-vs-updated tracking, with fake in-memory repositories.
- `test_wazuh_client.py` — authentication, 401 token-refresh, and every fetch method
  (`get_alerts`, `get_alert`, `get_agents`, `get_rules`, `get_recent_alerts`), all mocked
  with `respx` — no live Wazuh deployment required.

## 8. Verifying alert synchronization manually

```bash
# 1. Confirm Wazuh connectivity (see docs/WAZUH_CONNECTION.md)
curl -k https://<manager-host>:55000 -u wazuh-wui:<password>

# 2. Run the sync task once, directly, without waiting for Celery Beat's schedule
docker compose exec backend python -c "
from app.services.tasks.wazuh_tasks import sync_wazuh_alerts
print(sync_wazuh_alerts.apply().get())
"

# 3. Confirm alerts landed in Postgres
docker compose exec postgres psql -U soc_admin -d soc_assistant \
  -c "SELECT wazuh_alert_id, rule_id, severity, status FROM alerts ORDER BY created_at DESC LIMIT 10;"

# 4. Confirm the API sees them
curl -H "Authorization: Bearer <access_token>" http://localhost:8000/api/v1/alerts/recent
```

## 9. Testing the WebSocket stream

```bash
# Get an access token first
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "password": "yourpassword"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Connect with websocat (or any WS client) and leave it open
websocat "ws://localhost:8000/api/v1/ws/alerts?token=$TOKEN"

# In another terminal, trigger a sync manually (see section 8) or wait up to 60s
# for Celery Beat — any newly created alert should appear as a JSON message
# in the websocat session within a few seconds of the sync task completing.
```

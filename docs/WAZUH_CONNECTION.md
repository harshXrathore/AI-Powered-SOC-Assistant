# Connecting to Wazuh

This project does not deploy Wazuh itself — it connects to a Wazuh Manager
you already have running (lab, home SOC, or enterprise instance).

## 1. Requirements

- A running Wazuh Manager (4.x) with the API enabled on port `55000`
  (enabled by default).
- An API user. The default `wazuh-wui` account works for read access; for
  anything beyond Phase 1 connectivity checks, create a dedicated
  least-privilege API user instead of reusing `wazuh-wui`.
- Network reachability from wherever `docker compose` runs to the Wazuh
  Manager's host and port.

## 2. Get credentials

If you don't already have API credentials:

```bash
# Run on the Wazuh Manager host
sudo tar -O -xvf /var/ossec/etc/client.keys 2>/dev/null   # not the API password
cat /var/ossec/api/configuration/api.yaml                  # check API config
```

The default API account is `wazuh-wui`; its password is generated at
install time and stored in the manager's internal users database. Reset it
with `wazuh-apid` tooling or the Wazuh dashboard's API console if you don't
have it recorded.

## 3. Configure this project

In `backend/.env`:

```bash
WAZUH_API_URL=https://<manager-host>:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=<your-password>
WAZUH_VERIFY_SSL=false          # true if you've installed a trusted cert
WAZUH_INDEXER_URL=https://<indexer-host>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<your-password>
```

`WAZUH_VERIFY_SSL=false` is fine for a lab environment using Wazuh's
self-signed certs. Set it to `true` and supply a proper CA bundle before
using this against anything production-facing.

## 4. Verify the connection

Once `docker compose up` is running:

```bash
curl -k https://<manager-host>:55000 \
  -u wazuh-wui:<password>
```

should return a JSON banner with the Wazuh API version. That confirms the
credentials and network path work outside this app too, which is the
fastest way to rule out a firewall/credential issue vs. an app bug.

Inside the app, `app/services/wazuh_client.py`'s `check_connection()`
performs the same authenticated request — this will be wired to
`/api/v1/health/ready` in Phase 2 so readiness reflects real Wazuh
connectivity, not just the database.

## 5. Phase 2 preview

Phase 2 adds:
- `GET /alerts` polling against the Wazuh Indexer (alerts live in the
  indexer/Elasticsearch, not the Manager API itself).
- Alert deduplication and storage in Postgres.
- A Celery Beat task (`poll_new_alerts`, already scheduled in
  `celery_app.py`) that runs this on a 60-second interval.

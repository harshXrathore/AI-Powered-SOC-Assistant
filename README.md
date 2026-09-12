# AI SOC Assistant

AI-powered Security Operations Center assistant: alert investigation,
MITRE ATT&CK mapping, IOC enrichment, AI risk scoring, and generated
incident reports — built on top of an existing Wazuh SIEM deployment.

**Status:** Phase 2 — authentication (JWT + RBAC), database models + Alembic
migrations, Wazuh alert ingestion, alert/dashboard REST APIs, and a live
WebSocket alert stream. See `docs/ARCHITECTURE.md` for the Phase 1 base,
`docs/PHASE2.md` for everything added in this phase, and
`docs/WAZUH_CONNECTION.md` for pointing this at your own Wazuh manager.

## Quickstart

```bash
cp .env.example .env
cp .env.example backend/.env
# edit backend/.env with real Wazuh + API credentials

docker compose up --build
```

| Service        | URL                                    |
|----------------|-----------------------------------------|
| Frontend       | http://localhost:5173                   |
| Backend docs   | http://localhost:8000/docs              |
| Health check   | http://localhost:8000/api/v1/health     |
| Via Nginx      | http://localhost                        |

## Tech stack

Backend: FastAPI · SQLAlchemy (async) · PostgreSQL · Redis · Celery · LangChain
Frontend: React · TypeScript · Vite · Tailwind CSS · React Query
Security: Wazuh · MITRE ATT&CK · VirusTotal · AbuseIPDB · AlienVault OTX

## Database migrations

```bash
cd backend
alembic upgrade head          # apply all migrations
alembic revision --autogenerate -m "message"   # after changing a model
```

## Running tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

## Roadmap

- **Phase 1** ✅ Architecture, Docker Compose, base app configuration
- **Phase 2** ✅ Auth (JWT + RBAC), DB models + Alembic, Wazuh alert ingestion,
  alert/dashboard APIs, WebSocket live stream
- **Phase 3** IOC enrichment (VirusTotal/AbuseIPDB/OTX) + Redis caching
- **Phase 4** MITRE ATT&CK mapping + AI alert explanation
- **Phase 5** Risk-scoring engine
- **Phase 6** AI investigation chat assistant
- **Phase 7** Incident report generator (PDF/Markdown export)
- **Phase 8** Live dashboard UI (WebSocket alert stream, charts, timeline)

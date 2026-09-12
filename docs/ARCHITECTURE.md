# AI SOC Assistant — Architecture (Phase 1)

## 1. Purpose

An AI-powered assistant that sits on top of an existing Wazuh SIEM deployment
and helps a SOC analyst triage alerts faster: plain-language explanations,
MITRE ATT&CK mapping, IOC enrichment, AI-assisted risk scoring, and generated
incident reports.

## 2. High-level architecture

```
                                   ┌─────────────────────┐
                                   │   Wazuh Manager       │
                                   │   + Indexer (ELK)     │  (external, existing)
                                   └──────────┬───────────┘
                                              │ REST API (55000) / Indexer API (9200)
                                              ▼
┌────────────┐   HTTP/WS   ┌──────────────────────────────┐   SQL   ┌──────────────┐
│  React SPA │◄───────────►│         FastAPI Backend        │◄───────►│  PostgreSQL   │
│  (Vite)    │             │  - REST API (/api/v1/*)        │        └──────────────┘
└────────────┘             │  - WebSocket (/ws) live feed   │
                            │  - Wazuh polling client        │   Redis (broker)
                            │  - AI orchestration (LangChain)│◄───────►┌──────────────┐
                            │  - TI enrichment clients       │        │ Celery Worker │
                            └──────────────┬─────────────────┘        │ + Beat        │
                                           │                          └──────┬────────┘
                     ┌─────────────────────┼───────────────────────┐        │
                     ▼                     ▼                       ▼        ▼
              VirusTotal API        AbuseIPDB API           AlienVault OTX  (scheduled
                                                                              polling /
                                                                              enrichment)
                     │
                     ▼
              Anthropic / OpenAI API (alert explanation, risk scoring,
                                       report generation, chat assistant)
```

Nginx sits in front of both the FastAPI backend and the Vite frontend as a
single reverse-proxy entry point (port 80), routing `/api/*` and `/ws/*` to
the backend and everything else to the SPA.

## 3. Why this shape

- **Wazuh is treated as external.** Most analysts already have Wazuh running
  in a lab or production environment; this project connects to it via its
  REST API rather than bundling a second SIEM deployment inside the compose
  file. Keeps the stack focused on the AI/analysis layer, which is the
  actual portfolio differentiator.
- **Celery, not just FastAPI background tasks.** IOC enrichment (3 external
  APIs per lookup), LLM calls, and PDF report rendering are slow and
  rate-limited. Offloading them to Celery keeps the API responsive and adds
  retry/backoff semantics for free.
- **Async SQLAlchemy end-to-end.** The whole request path — Wazuh polling,
  TI enrichment, DB writes — is I/O bound, so async avoids thread-pool
  contention under load.
- **Redis does double duty** as the Celery broker/result backend and as a
  short-TTL cache for IOC reputation lookups, avoiding redundant external
  API calls (VirusTotal/AbuseIPDB rate limits are tight on free tiers).

## 4. Folder structure

```
soc-assistant/
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env                       # local only, gitignored
│   └── app/
│       ├── main.py                # FastAPI entrypoint
│       ├── core/
│       │   ├── config.py          # pydantic-settings
│       │   ├── database.py        # async engine/session
│       │   ├── celery_app.py      # Celery instance + beat schedule
│       │   └── logging_config.py  # structlog setup
│       ├── api/
│       │   ├── routers/           # one router per resource (Phase 2+)
│       │   └── dependencies/      # shared FastAPI Depends()
│       ├── models/                # SQLAlchemy ORM models (Phase 2)
│       ├── schemas/                # Pydantic request/response schemas
│       ├── services/
│       │   ├── wazuh_client.py    # Wazuh API auth + requests
│       │   └── tasks/             # Celery task modules (Phase 2+)
│       ├── prompts/                # LLM prompt templates
│       └── utils/
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── components/
│       ├── pages/
│       ├── hooks/
│       ├── services/apiClient.ts
│       ├── store/                  # zustand stores (Phase 2+)
│       └── types/
├── database/init/                  # Postgres bootstrap SQL
├── docker/nginx/nginx.conf
└── docs/
```

## 5. What Phase 1 delivers

- Full folder structure for backend, frontend, database, and infra.
- `docker-compose.yml` wiring Postgres, Redis, FastAPI, Celery
  worker + beat, Vite dev server, and Nginx.
- FastAPI app boots with CORS, structured logging, global exception
  handling, and a `/api/v1/health` + `/api/v1/health/ready` liveness/
  readiness pair.
- Typed, validated settings loaded from environment (`app/core/config.py`).
- Async SQLAlchemy engine/session wiring, ready for models in Phase 2.
- Celery app configured with a beat schedule referencing Phase 2 task
  modules (not yet implemented — intentionally stubbed).
- Wazuh API client with authentication + token refresh + a
  `check_connection()` method, ready for the alert-polling logic in Phase 2.
- React + TypeScript + Vite + Tailwind frontend that renders a single page
  proving end-to-end connectivity (calls `/api/v1/health`).
- Postgres init script for required extensions (`uuid-ossp`, `pg_trgm`).

## 6. What is explicitly NOT in Phase 1

- No database models/migrations yet (Alembic setup is Phase 2).
- No auth (JWT issuance, RBAC) — stubs only, real implementation Phase 2.
- No alert ingestion/polling logic — client can authenticate and connect,
  parsing and storing alerts comes in Phase 2.
- No IOC enrichment, MITRE mapping, risk scoring, or AI endpoints yet.
- No frontend dashboard, alert list, or chat UI beyond the connectivity
  check page.

## 7. How to run Phase 1

```bash
cd soc-assistant
cp .env.example .env
cp .env.example backend/.env   # then fill in real Wazuh/API credentials

docker compose up --build
```

- Backend: http://localhost:8000/docs
- Frontend: http://localhost:5173 (or http://localhost via Nginx on port 80)
- Health check: http://localhost:8000/api/v1/health/ready

## 8. How to test Phase 1

```bash
# Backend boots and responds
curl http://localhost:8000/api/v1/health

# DB connectivity
curl http://localhost:8000/api/v1/health/ready

# Frontend proves it can reach the backend through the proxy
open http://localhost:5173
```

No automated tests yet — `backend/tests/` is scaffolded (with `__init__.py`)
and will gain real coverage starting Phase 2 once there's business logic to
test beyond configuration wiring.

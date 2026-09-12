# 🛡️ AI Security Operations Center (SOC) Assistant

> An AI-powered Security Operations Center platform designed to help SOC analysts monitor, investigate, prioritize, and respond to security alerts through intelligent automation.

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-Frontend-61DAFB?logo=react)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-336791?logo=postgresql)](https://www.postgresql.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-3A86FF)](https://wazuh.com/)
[![Redis](https://img.shields.io/badge/Redis-Cache%20%26%20Messaging-DC382D?logo=redis)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](#-license)

---

## 📌 Overview

The **AI Security Operations Center (SOC) Assistant** is a cybersecurity platform that combines SIEM monitoring, security automation, threat intelligence, and Artificial Intelligence to assist security analysts during alert investigation.

Traditional SOC environments can generate thousands of security alerts every day. Analysts must manually investigate logs, identify Indicators of Compromise (IOCs), determine attack techniques, assess severity, and prepare incident reports.

This project aims to reduce that workload by providing a centralized platform capable of:

* 📊 Monitoring security alerts
* 🔎 Investigating suspicious events
* 🧠 Explaining security alerts using AI
* 🎯 Mapping attacks to MITRE ATT&CK
* 🌐 Enriching Indicators of Compromise
* ⚠️ Prioritizing security incidents
* 📝 Generating incident reports
* 💬 Providing an AI-powered SOC investigation assistant

---

# 🎯 Project Goals

The primary objectives are to build a practical SOC platform that demonstrates real-world cybersecurity and software engineering concepts.

### Security Goals

* Centralize security event monitoring
* Reduce alert investigation time
* Improve alert prioritization
* Automate repetitive SOC tasks
* Provide contextual threat intelligence
* Assist analysts during incident response

### Engineering Goals

* Build a scalable backend architecture
* Implement asynchronous APIs
* Integrate external security platforms
* Support real-time alert streaming
* Maintain clean separation of concerns
* Provide secure authentication and authorization

---

# 🏗️ Architecture

```text
                         ┌──────────────────┐
                         │   Wazuh Agents   │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Wazuh Manager  │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Elastic / Wazuh  │
                         │     Indexer      │
                         └────────┬─────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   Wazuh Integration    │
                    │       Service          │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     FastAPI Backend     │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
        ┌───────────┐      ┌───────────┐     ┌────────────┐
        │PostgreSQL │      │   Redis   │     │   Celery   │
        │ Database  │      │ Messaging │     │ Background │
        └───────────┘      └───────────┘     │   Tasks    │
                                             └────────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │  WebSocket Layer  │
                       └─────────┬─────────┘
                                 │
                                 ▼
                       ┌───────────────────┐
                       │   React Dashboard │
                       └───────────────────┘
```

---

# 🚀 Current Features

## 1. Security Alert Monitoring

The platform integrates with Wazuh to retrieve security alerts and make them available through the SOC dashboard.

Supported alert information includes:

* Alert ID
* Rule ID
* Rule description
* Severity
* Timestamp
* Source IP
* Destination IP
* Agent
* Host information
* Raw security event

---

## 2. Wazuh Integration

The backend provides an asynchronous Wazuh client supporting:

* Wazuh Manager API authentication
* Token management
* Token refresh
* Alert retrieval
* Agent retrieval
* Rule retrieval
* Recent alert retrieval
* Timeout handling
* Retry mechanisms
* API error handling

---

## 3. Alert Synchronization

A background synchronization service periodically retrieves new Wazuh alerts and stores them in PostgreSQL.

The synchronization process prevents duplicate alerts and maintains a local copy for investigation and analysis.

```text
Wazuh
   │
   ▼
Alert Collector
   │
   ▼
Validation
   │
   ▼
Duplicate Check
   │
   ▼
PostgreSQL
```

---

## 4. Real-Time Alert Updates

The platform supports WebSocket-based communication between the backend and frontend.

When new alerts become available, connected dashboard clients can receive updates without manually refreshing the page.

```text
Wazuh
  ↓
Alert Sync
  ↓
Redis
  ↓
WebSocket
  ↓
React Dashboard
```

---

## 5. Authentication & Authorization

The application implements secure authentication using:

* JWT access tokens
* Refresh tokens
* Password hashing
* Role-Based Access Control (RBAC)

Supported roles:

| Role     | Access                           |
| -------- | -------------------------------- |
| Admin    | Full system access               |
| Analyst  | Alert investigation and analysis |
| ReadOnly | View-only access                 |

---

## 6. Alert Investigation

Analysts can investigate individual security alerts through dedicated APIs.

Investigation information can include:

* Alert details
* Analyst assignment
* Investigation status
* Analyst notes
* Priority
* Investigation timeline

---

## 7. Dashboard Analytics

The dashboard API provides security statistics including:

* Total alerts
* Critical alerts
* High severity alerts
* Medium severity alerts
* Low severity alerts
* Recent alerts
* Top attacking IP addresses
* Top alert rules
* Alert trends

---

# 🧠 AI Intelligence Layer

The next development stage introduces the AI-powered intelligence layer.

Planned capabilities include:

### AI Alert Analysis

The AI assistant will analyze security alerts and provide:

* Executive summary
* Technical explanation
* Possible attack method
* Root cause analysis
* Potential impact
* Recommended actions

### MITRE ATT&CK Mapping

Security alerts will be mapped to:

* MITRE tactics
* MITRE techniques
* Sub-techniques
* Attack stages
* Confidence scores

### Threat Intelligence

The platform will enrich IOCs using services such as:

* VirusTotal
* AbuseIPDB
* AlienVault OTX

Supported IOC types:

```text
IPv4
IPv6
Domain
URL
MD5
SHA1
SHA256
```

### AI SOC Chat Assistant

Analysts will be able to ask questions such as:

```text
Explain Alert #105.

Why is this alert dangerous?

Is this IP malicious?

Which MITRE technique is involved?

What should I do next?

Summarize this investigation.

Generate an incident report.
```

---

# 🛠️ Technology Stack

## Backend

* Python 3.12
* FastAPI
* SQLAlchemy 2.0
* Pydantic
* Alembic
* Celery
* Redis
* HTTPX

## Frontend

* React
* TypeScript
* Vite
* Tailwind CSS
* React Query
* WebSockets

## Database

* PostgreSQL
* JSONB
* SQLAlchemy ORM

## Security

* Wazuh
* MITRE ATT&CK
* Sigma Rules
* Threat Intelligence APIs

## AI

* LangChain
* OpenAI / Claude

## Infrastructure

* Docker
* Docker Compose
* Nginx

---

# 📂 Project Structure

```text
AI-SOC-Assistant/
│
├── backend/
│   ├── api/
│   ├── core/
│   ├── models/
│   ├── repositories/
│   ├── schemas/
│   ├── services/
│   ├── tests/
│   └── main.py
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── services/
│
├── docker/
│   └── nginx/
│
├── database/
│
├── docs/
│
├── docker-compose.yml
├── .env.example
└── README.md
```

---

# ⚙️ Installation

## Prerequisites

Install:

* Python 3.12+
* Node.js 20+
* PostgreSQL
* Redis
* Git

Optional:

* Docker
* Wazuh Server

---

# 🔧 Backend Setup

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/AI-SOC-Assistant.git

cd AI-SOC-Assistant
```

Create a virtual environment:

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

---

# 🔐 Environment Configuration

Create a `.env` file.

Example:

```env
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/ai_soc

REDIS_URL=redis://localhost:6379/0

JWT_SECRET_KEY=change-this-secret

WAZUH_API_URL=https://your-wazuh-server:55000
WAZUH_INDEXER_URL=https://your-wazuh-server:9200

WAZUH_USERNAME=your_username
WAZUH_PASSWORD=your_password

OPENAI_API_KEY=your_api_key
ANTHROPIC_API_KEY=your_api_key

VIRUSTOTAL_API_KEY=your_api_key
ABUSEIPDB_API_KEY=your_api_key
OTX_API_KEY=your_api_key
```

> Never commit `.env` or API keys to GitHub.

---

# 🗄️ Database Setup

Create the PostgreSQL database:

```sql
CREATE DATABASE ai_soc;
```

Run migrations:

```bash
alembic upgrade head
```

---

# ▶️ Run Backend

From the project root:

```bash
uvicorn backend.main:app --reload
```

API:

```text
http://localhost:8000
```

Swagger documentation:

```text
http://localhost:8000/docs
```

---

# ▶️ Run Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will normally be available at:

```text
http://localhost:5173
```

---

# 🔄 Run Celery

Start the Celery worker:

```bash
celery -A backend.celery_app worker --loglevel=info
```

Start Celery Beat if scheduled tasks are configured:

```bash
celery -A backend.celery_app beat --loglevel=info
```

---

# 🐳 Docker

Docker Compose support is also available.

Run:

```bash
docker compose up --build
```

Stop:

```bash
docker compose down
```

---

# 🔌 API Endpoints

## Authentication

```text
POST /auth/register
POST /auth/login
POST /auth/refresh
POST /auth/logout
GET  /auth/me
```

## Alerts

```text
GET   /alerts
GET   /alerts/{id}
GET   /alerts/recent
GET   /alerts/high
GET   /alerts/search
PATCH /alerts/{id}/status
```

## Dashboard

```text
GET /dashboard/stats
GET /dashboard/trends
GET /dashboard/top-ips
GET /dashboard/top-rules
```

## Health

```text
GET /health
GET /health/ready
```

## WebSocket

```text
WS /ws/alerts
```

---

# 🔍 Example SOC Workflow

```text
1. Wazuh detects suspicious activity
             ↓
2. Alert is generated
             ↓
3. SOC Assistant retrieves the alert
             ↓
4. Alert is stored in PostgreSQL
             ↓
5. WebSocket broadcasts the new alert
             ↓
6. Analyst opens the alert
             ↓
7. IOC extraction is performed
             ↓
8. Threat intelligence enrichment
             ↓
9. MITRE ATT&CK mapping
             ↓
10. AI analyzes the alert
             ↓
11. Risk score is calculated
             ↓
12. Analyst receives recommendations
             ↓
13. Investigation is documented
             ↓
14. Incident report is generated
```

---

# 🧪 Testing

Run backend tests:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=backend
```

The test suite covers areas such as:

* Authentication
* Wazuh client
* Alert synchronization
* Alert APIs
* Database interactions

---

# 🔒 Security Considerations

This project is designed with security best practices in mind.

Implemented/planned controls include:

* JWT authentication
* RBAC
* Password hashing
* Environment-based secrets
* Input validation
* API error handling
* Request timeouts
* Retry limits
* Database constraints
* Audit-friendly investigation records

### Important

The AI assistant should **never automatically execute destructive response actions** based solely on an LLM recommendation.

Recommended architecture:

```text
AI Recommendation
       ↓
Analyst Review
       ↓
Approval
       ↓
Response Playbook
       ↓
Execution
```

This keeps the human analyst in the loop.

---

# 📈 Roadmap

## Phase 1 — Architecture & Infrastructure

* [x] Project architecture
* [x] FastAPI foundation
* [x] React foundation
* [x] PostgreSQL
* [x] Redis
* [x] Celery
* [x] Docker support

## Phase 2 — SOC Core

* [x] JWT authentication
* [x] RBAC
* [x] Wazuh integration
* [x] Alert synchronization
* [x] Alert APIs
* [x] Dashboard APIs
* [x] WebSocket alerts
* [x] Investigation foundation
* [x] Testing

## Phase 3 — AI Intelligence

* [ ] MITRE ATT&CK integration
* [ ] IOC extraction
* [ ] VirusTotal integration
* [ ] AbuseIPDB integration
* [ ] AlienVault OTX integration
* [ ] AI alert explanation
* [ ] AI investigation assistant
* [ ] Risk scoring
* [ ] Investigation workspace
* [ ] AI chat history

## Phase 4 — SOC Automation

* [ ] Automated incident reports
* [ ] SOAR-style playbooks
* [ ] Analyst approval workflows
* [ ] Automated enrichment
* [ ] Threat hunting
* [ ] Advanced detection rules
* [ ] Security response automation

---

# 🎓 Skills Demonstrated

This project demonstrates practical experience in:

### Cybersecurity

* Security Operations Center (SOC)
* SIEM
* Wazuh
* Threat Detection
* Log Analysis
* Incident Response
* Threat Intelligence
* MITRE ATT&CK
* IOC Analysis
* Security Automation

### AI Engineering

* LLM Integration
* LangChain
* Prompt Engineering
* AI-assisted Security Analysis
* Retrieval-Augmented Generation (planned)

### Software Engineering

* Python
* FastAPI
* REST APIs
* Async Programming
* WebSockets
* React
* TypeScript
* SQLAlchemy
* PostgreSQL
* Redis
* Celery
* Docker
* Automated Testing
* Clean Architecture
* Repository Pattern

---

# 🚀 Future Enhancements

Potential future integrations include:

* MISP
* GreyNoise
* URLhaus
* Shodan
* Microsoft Defender
* CrowdStrike
* Splunk
* Elastic Security
* TheHive
* Cortex
* OpenCTI

Additional capabilities:

* Threat hunting queries
* Attack-chain visualization
* MITRE ATT&CK Navigator
* Detection engineering
* Automated phishing analysis
* Malware hash analysis
* Executive SOC dashboards
* Multi-tenant architecture

---

# ⚠️ Disclaimer

This project is intended for **educational, research, defensive security, and authorized SOC environments**.

Do not use the system to monitor, investigate, or interact with systems without proper authorization.

Threat intelligence results should be independently validated before taking security actions.

---

# 👨‍💻 Author

**Harsh Rathore**

Cybersecurity | SOC | Threat Intelligence | AI Security

---

# 📜 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.

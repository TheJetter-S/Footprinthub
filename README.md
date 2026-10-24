# FootprintHub

> All-in-one web-based footprinting & reconnaissance platform for authorized security assessments.

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![React](https://img.shields.io/badge/react-18-blue)

## Overview

FootprintHub lets you enter a domain and automatically collects reconnaissance data across **10 categories** — DNS, subdomains, IP/network, web technology, SSL/TLS, website content, ports/services, OSINT, cloud, and reputation — and displays everything in one unified dashboard with a risk score and actionable findings.

## Features

- 🔍 **10 Recon Modules** — DNS, Subdomains, IP/Network, Web Tech, SSL/TLS, Content, Ports, OSINT, Cloud, Reputation
- 📊 **Risk Scoring** — Automated 0-100 risk score with severity-ranked findings
- 🔄 **Real-time Progress** — WebSocket-powered live updates per module
- 🛡️ **Scan Profiles** — Passive (default), Standard, and Full (with active checks)
- 📈 **Interactive Dashboard** — Tabbed results, findings table, relationship graph
- 📋 **Scan History** — View past scans, compare results, track changes
- 📥 **Export** — PDF, JSON, CSV reports
- 🌗 **Dark/Light Mode** — Professional UI with glassmorphism design
- 🔐 **Security First** — JWT auth, SSRF protection, rate limiting, authorization gate

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 20+ (for local frontend development)
- Python 3.11+ (for local backend development)

### Using Docker (Recommended)

```bash
# 1. Clone the repository
git clone <repo-url>
cd FootprintHub

# 2. Create your environment file
cp .env.example .env
# Edit .env with your API keys and secrets

# 3. Start all services
docker-compose up --build

# 4. Access the application
#    Frontend: http://localhost:3000
#    Backend API: http://localhost:8000/docs
```

### Local Development

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Start PostgreSQL and Redis (via Docker or locally)
# Run database migrations
alembic upgrade head

# Start the server
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Celery Worker:**
```bash
cd backend
celery -A app.tasks.celery_app worker --loglevel=info
```

## Architecture

```
┌────────────┐     ┌──────────────┐     ┌─────────────┐
│   React    │────▶│   FastAPI    │────▶│   Celery    │
│  Frontend  │◀────│   Backend    │◀────│   Workers   │
│  (Vite)    │ WS  │  (Uvicorn)   │     │             │
└────────────┘     └──────┬───────┘     └──────┬──────┘
                          │                     │
                   ┌──────┴──────┐       ┌─────┴──────┐
                   │ PostgreSQL  │       │   Redis    │
                   │  (Storage)  │       │ (Queue +   │
                   │             │       │  Cache)    │
                   └─────────────┘       └────────────┘
```

## Project Structure

```
FootprintHub/
├── docker-compose.yml
├── .env.example
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/
│   └── app/
│       ├── main.py           # FastAPI application
│       ├── config.py          # Pydantic settings
│       ├── core/              # Security, SSRF, rate limiting
│       ├── models/            # SQLAlchemy models
│       ├── schemas/           # Pydantic schemas
│       ├── api/               # REST + WebSocket routes
│       ├── modules/           # Recon modules (plugin system)
│       ├── tasks/             # Celery task definitions
│       └── tests/             # Pytest test suite
└── frontend/
    ├── Dockerfile
    ├── package.json
    └── src/
        ├── App.tsx
        ├── api/               # API client
        ├── pages/             # Route pages
        └── components/        # UI components
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Login |
| GET | `/api/v1/auth/me` | Current user |
| POST | `/api/v1/scans/` | Start scan |
| GET | `/api/v1/scans/` | List scans |
| GET | `/api/v1/scans/{id}` | Scan details |
| GET | `/api/v1/scans/{id}/results` | Module results |
| GET | `/api/v1/scans/{id}/findings` | Findings |
| WS | `/ws/scans/{id}` | Live progress |

## Security

- **Authorization Gate** — Users must confirm domain ownership before scanning
- **SSRF Protection** — Blocks private IPs, localhost, metadata endpoints
- **Rate Limiting** — Redis-backed sliding window per user/IP
- **JWT Authentication** — Access + refresh token flow
- **Input Validation** — Domain sanitization, no shell injection
- **Honest User-Agent** — All outbound requests identify as FootprintHub

## License

MIT — For authorized security testing only.

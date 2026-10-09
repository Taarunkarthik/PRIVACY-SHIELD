# PrivacyShield

PrivacyShield is a PostgreSQL privacy platform being built in seven tested phases. It will discover schema relationships, identify sampled PII, offer local AI recommendations, and deploy human-approved masking views while preserving source data.

**Development branch:** [`dev/privacyshield`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/tree/dev/privacyshield). All application code, migrations, infrastructure, tests, and documentation live in this repository.

## Current delivery

Phase 1 provides the control-plane schema, authenticated API, React dashboard shell, Docker topology, synthetic target database, worker foundation, and initial tests. Discovery, scanning, AI classification, policy enforcement, and their user workflows are later phases. Navigation to those pages must clearly identify capabilities that are not yet available; demonstration counts must never be presented as scanned findings.

Phase 1 is implemented and its local backend, real-service, HTTP, and frontend checks have passed. Browser review and GitHub delivery verification are tracked separately; no successful push or CI run is claimed here. See [verification evidence](docs/verification.md) and [the delivery roadmap](docs/roadmap.md) for current status.

## Local setup

Prerequisites: Git, Python 3.12 or a compatible Python launcher for the setup script, and Docker Desktop running Linux containers. Native Node or PostgreSQL installation is unnecessary for the Docker application. The frontend binds to `http://localhost:8080`; internal database, Redis, and Ollama ports are not published by default.

```powershell
git clone https://github.com/Taarunkarthik/PRIVACY-SHIELD.git
Set-Location PRIVACY-SHIELD
git switch dev/privacyshield
python scripts/setup.py
docker compose up --build -d
docker compose ps
```

For an existing checkout, inspect `git status --short --branch`, `git remote -v`, and branch history before modifying it. Preserve local changes and existing remote commits.

The setup script creates local secrets in the ignored `.env` file. Never commit that file or copy its contents into tickets, logs, or chat. `.env.example` documents configuration using placeholders only.

Bootstrap the administrator interactively after the API is healthy:

```powershell
docker compose exec api python -m app.cli create-admin --email admin@example.com
```

Enter a strong unique password at the hidden prompt, then open [the local dashboard](http://localhost:8080). There is no committed default administrator password. Authentication uses server-side sessions and CSRF protection.

**Windows storage:** use Docker Desktop's supported storage controls to locate Linux disk images and named volumes on D: before the first build. Preserve existing Docker data. Do not move, delete, or unregister Docker/WSL distributions manually. See [operations and troubleshooting](docs/operations.md).

## Verification

With the Compose services already running, run the repository's Docker acceptance checks:

```powershell
python scripts/check.py --integration
```

This validates Compose, lints/tests the backend, migrates a separate `privacyshield_test` database, exercises real PostgreSQL/Redis/Celery, and checks actual scanner/reader target permissions. It preserves the application database and retains test fixtures in the isolated test database. It does not start or build the application.

Add `--frontend` when Node 24/npm are installed on the host to include frontend installation, type checking, tests, and a production build:

```powershell
python scripts/check.py --integration --frontend
```

For development outside containers:

```powershell
Set-Location backend
uv sync --locked --extra dev
uv run ruff check .
uv run pytest -m "not integration"
Set-Location ../frontend
npm ci
npm run typecheck
npm test
npm run build
```

Integration tests require migrated PostgreSQL, Redis, and a **separate Linux Celery worker**. A mocked broker or eager Celery execution does not satisfy that gate. [GitHub Actions](.github/workflows/ci.yml) runs backend and frontend checks, migrations, and real control-database/Redis/worker tests. Target-database role checks run through the local `--integration` gate; the CI services job does not provision the synthetic target. A successful local build alone does not establish integration success.

## Architecture and documentation

The backend is a FastAPI modular monolith shared by API and Celery processes. A dedicated PostgreSQL database stores control-plane metadata. A second PostgreSQL service holds exclusively synthetic customer, account, transaction, and support data. Redis carries jobs; PostgreSQL stores authoritative job state. Ollama is an optional profile during the foundation phase.

| Directory | Responsibility |
| --- | --- |
| `backend/` | FastAPI, SQLAlchemy models, Alembic migrations, workers, tests |
| `frontend/` | React, TypeScript, routes, dashboard, component tests |
| `infra/` | PostgreSQL provisioning and frontend reverse proxy |
| `scripts/` | Local secret setup and verification |
| `docs/` | Architecture, normalized database design, roadmap, operations |

- [Architecture and trust boundaries](docs/architecture.md)
- [Database design, ER diagram, and transaction boundaries](docs/database-design.md)
- [Seven-phase roadmap and acceptance criteria](docs/roadmap.md)
- [Setup, testing, demo, and troubleshooting](docs/operations.md)
- [Phase 1 verification evidence and limitations](docs/verification.md)

## Security and delivery rules

Use only databases you are authorized to inspect. The bundled target is synthetic. PAN and Aadhaar detection in later phases identifies **candidates**, not verified identities. Findings will describe bounded samples rather than assert full-table coverage.

The foundation includes credential-encryption utilities; the discovery phase will expose connection management with encrypted storage and write-only password inputs. Raw source samples, keys, and credentials must not appear in logs, task payloads, AI input, or committed files. AI recommendations will be advisory and unable to execute SQL. Policy deployment will use predefined SQL templates and a separate explicit approval action.

Commit tested phases to `dev/privacyshield`; do not force-push or merge into `main` without approval. Confirm each remote SHA after pushing and report features, changed files, tests, and the GitHub commit link. Never label an unverified phase complete.

# PrivacyShield

PrivacyShield is a PostgreSQL privacy platform being built in seven tested phases. It will discover schema relationships, identify sampled PII, offer local AI recommendations, and deploy human-approved masking views while preserving source data.

**Development branch:** [`dev/privacyshield`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/tree/dev/privacyshield). All application code, migrations, infrastructure, tests, and documentation live in this repository.

## Current delivery

All seven phases are delivered: the control-plane schema, authenticated API, React dashboard, Docker topology, synthetic target database, encrypted connection management, schema discovery, asynchronous PII scanning, local AI recommendations, human-approved masking policies deployed as security-barrier views, operator settings, a filtered audit timeline, and concurrency/recovery hardening. Every phase passed local acceptance and GitHub delivery verification. Pages for capabilities that are not yet available say so; demonstration counts must never be presented as scanned findings.

The latest verified commit is [`964686a`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/commit/964686a6301fb3bf2a5bd3b5ddc1f40cd8c622ac). See [Phase 7 verification evidence](docs/verification-phase7.md) and [the delivery roadmap](docs/roadmap.md) for current status and measured limitations.

After Phase 7, branch `feat/demo-readiness` adds format-aware masks for email, phone and ID numbers, a before/after policy preview on invented values, evidence of what the reader role sees through a deployed view, suggested rules from scan findings, dashboard breakdowns, random row sampling, checksum rules for Aadhaar and PAN, and a labelled accuracy benchmark. These commits passed the local suite described in the [demo-readiness verification record](docs/verification-demo-readiness.md) and [GitHub Actions run 38116499292](https://github.com/Taarunkarthik/PRIVACY-SHIELD/actions/runs/38116499292).

The submission build adds five things on top of that: a tamper-evident hash chain over the audit log, masking per audience (one policy can give general readers, support staff and analysts differently masked views of the same table), value-shape evidence and detector triage for AI classification, a single-container deployment that runs on free hosting without Redis or a worker, and a redesigned interface. What was run, and what was not, is in the [submission-build verification record](docs/verification-submission-build.md).

The submission target is **12 October 2026**, with working code and a reproducible demonstration. The seven phase gates remain in place within the three-day work window; the schedule is a target, not a guarantee of completion.

## Local setup

Prerequisites: Git, Python 3.12 or a compatible Python launcher for the setup script, and Docker Desktop running Linux containers. Native Node or PostgreSQL installation is unnecessary for the Docker application. The frontend binds to `http://localhost:8080`; internal database, Redis, and Ollama ports are not published by default.

```powershell
git clone https://github.com/Taarunkarthik/PRIVACY-SHIELD.git
Set-Location PRIVACY-SHIELD
git switch dev/privacyshield
python scripts/setup.py
docker compose up --build -d --wait
docker compose ps
```

For an existing checkout, inspect `git status --short --branch`, `git remote -v`, and branch history before modifying it. Preserve local changes and existing remote commits.

The setup script creates local secrets in the ignored `.env` file. Never commit that file or copy its contents into tickets, logs, or chat. `.env.example` documents configuration using placeholders only.

Bootstrap the administrator interactively after the API is healthy:

```powershell
docker compose exec api python -m app.cli create-admin --email admin@example.com
```

Enter a strong unique password at the hidden prompt, then open [the local dashboard](http://localhost:8080). There is no committed default administrator password. Authentication uses server-side sessions and CSRF protection.

**Hosted option:** the repository includes a Render Blueprint (`render.yaml`) for
the free plan: one web service that serves the API, the frontend and the
background jobs from the repository-root `Dockerfile`, and one Postgres
instance. It needs no Redis and no worker. The earlier multi-service layout,
which needs paid plans, is kept as `render.paid.yaml`. See
[Deploying on Render](docs/deploy-render.md).

**Windows storage:** use Docker Desktop's supported storage controls to locate Linux disk images and named volumes on D: before the first build. Preserve existing Docker data. Do not move, delete, or unregister Docker/WSL distributions manually. See [operations and troubleshooting](docs/operations.md).

## Verification

With the Compose services already running, run the repository's Docker acceptance checks:

```powershell
python scripts/check.py --integration
```

This validates Compose, lints/tests the backend, migrates a separate `privacyshield_test` database, exercises real PostgreSQL/Redis/Celery, and checks actual scanner/reader target permissions. It starts a temporary Linux worker on an isolated queue and a controlled HTTP AI double, then removes both. The AI double tests orchestration and failure handling; it does not establish real model quality. The [separate AI smoke and demo](docs/classification.md) use actual Ollama. Checks preserve the application database and retain test fixtures in the isolated test database. They do not start or build the application.

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

Integration tests require migrated PostgreSQL, Redis, and a **separate Linux Celery worker**. A mocked broker or eager Celery execution does not satisfy that gate. The [GitHub Actions workflow](.github/workflows/ci.yml) also provisions a separate synthetic target PostgreSQL service using the repository's initialization scripts. [Phase 2 CI](https://github.com/Taarunkarthik/PRIVACY-SHIELD/actions/runs/37968356823) passed against these real services. A successful local build alone does not establish integration success.

## Architecture and documentation

The backend is a FastAPI modular monolith shared by API and Celery processes. A dedicated PostgreSQL database stores control-plane metadata. A second PostgreSQL service holds exclusively synthetic customer, account, transaction, and support data. Redis carries jobs; PostgreSQL stores authoritative job state. With `JOB_RUNNER=inline` the API process runs the jobs itself and Redis is not used, which is how the single-container hosted deployment works. Enable the optional `ai` profile for local Ollama recommendations.

| Directory | Responsibility |
| --- | --- |
| `backend/` | FastAPI, SQLAlchemy models, Alembic migrations, workers, tests |
| `frontend/` | React, TypeScript, routes, dashboard, reverse proxy, UI tests |
| `infra/` | PostgreSQL role provisioning and synthetic source fixtures |
| `scripts/` | Local secret setup and verification |
| `docs/` | Architecture, normalized database design, roadmap, operations |

- [Architecture and trust boundaries](docs/architecture.md)
- [Database design, ER diagram, and transaction boundaries](docs/database-design.md)
- [Three-day delivery target and seven phase gates](docs/roadmap.md)
- [Connection and discovery contract](docs/discovery.md)
- [Bounded PII scanning and demo](docs/scanning.md)
- [Local AI classification and actual model checks](docs/classification.md)
- [Masking policies, approval, and deployment](docs/masking.md)
- [Masking audiences: one policy, a different view per database role](docs/masking-audiences.md)
- [Audit hash chain: what it detects and what it cannot](docs/audit-chain.md)
- [Detection accuracy: measured precision, recall and known false positives](docs/detection-accuracy.md)
- [Deploying on Render](docs/deploy-render.md)
- [Render deployment verification](docs/verification-render.md)
- [Setup, testing, demo, and troubleshooting](docs/operations.md)
- [Phase 1 verification evidence and limitations](docs/verification.md)
- [Phase 2 verification evidence](docs/verification-phase2.md)
- [Phase 3 verification evidence](docs/verification-phase3.md)
- [Phase 4 verification evidence](docs/verification-phase4.md)
- [Phase 5 verification evidence](docs/verification-phase5.md)
- [Phase 6 verification evidence](docs/verification-phase6.md)
- [Phase 7 verification evidence](docs/verification-phase7.md)
- [Demo-readiness verification record](docs/verification-demo-readiness.md)
- [Submission-build verification record](docs/verification-submission-build.md)

## Security and delivery rules

Use only databases you are authorized to inspect. The bundled target is synthetic. PAN and Aadhaar detection identifies **candidates**, not verified identities. Findings describe bounded samples rather than assert full-table coverage.

The connection API uses encrypted credential storage and write-only password inputs. Raw source samples, keys, and credentials must not appear in logs, task payloads, AI input, or committed files. AI recommendations will be advisory and unable to execute SQL. Policy deployment will use predefined SQL templates and a separate explicit approval action.

Commit tested phases to `dev/privacyshield`; do not force-push or merge into `main` without approval. Confirm each remote SHA after pushing and report features, changed files, tests, and the GitHub commit link. Never label an unverified phase complete.

# Render deployment verification record

PrivacyShield gained a Render deployment path: a Blueprint (`render.yaml`) plus a
startup bootstrap that replaces the Docker entrypoint init scripts on managed
infrastructure. This record separates what was verified locally from what still
requires a live Render account.

## What was added

| Artifact | Purpose |
| --- | --- |
| `render.yaml` | Blueprint: API web service, Celery worker, nginx frontend, Key Value (Redis), and two Postgres databases |
| `backend/app/render_bootstrap.py` | Idempotent, advisory-locked provisioning (control + target roles, schemas, `pgcrypto`, fixtures) and migration runner |
| `backend/scripts/render/start-api.sh`, `start-worker.sh` | Render start commands: bootstrap, then serve |
| `frontend/nginx.conf.template` + `frontend/docker-entrypoint.sh` | Port/upstream templating so nginx works under Compose and Render |
| `backend/app/core/config.py`, `dependencies.py`, `main.py` | `FRONTEND_ORIGIN`, host-list parsing from a single value, and same-origin `Origin` handling behind a proxy |
| `docs/deploy-render.md` | Operator runbook |

The least-privilege role model is preserved: the bootstrap creates
`ps_migrator`/`ps_app` on the control database and
`ps_scanner`/`ps_deployer`/`ps_view_owner`/`ps_reader` on the target database,
mirroring `infra/postgres/*-init.sh`. If a managed instance forbids role
creation or ownership transfer, the control plane falls back to the instance
owner with a logged warning (recorded as a limitation).

## Verified locally

| Check | Result | Evidence |
| --- | --- | --- |
| Render Blueprint schema | Passed | `render.yaml` validates against `https://render.com/schema/render.yaml.json` |
| Bootstrap against real PostgreSQL | Passed | `python -m app.render_bootstrap` ran to completion against the local control and target databases, creating roles, schemas, `pgcrypto`, fixtures, and applying migrations |
| Bootstrap idempotency | Passed | Re-running over the already-provisioned databases succeeds unchanged |
| Frontend container and proxy | Passed | Rebuilt the frontend image; `/health` returns `ok` and `/api/v1/health/ready` proxies to `{"status":"ok"}` |
| Backend Ruff / unit tests | Passed | 171 unit tests |
| Full gate (`scripts/check.py --integration --frontend`) | Passed | 88 real integration tests, worker smoke, target role boundaries, 49 component tests, typecheck, production build |

## Not yet verified

- **A live Render account.** The Blueprint is structurally valid and the
  bootstrap SQL has executed against real PostgreSQL, but the end-to-end deploy
  (build, private networking, health checks, first-run provisioning under timing
  pressure) has not been exercised on Render. Treat the first deploy as a
  verification step.
- **Managed-role privileges:** whether the Render Postgres instance user may
  `CREATE ROLE` and transfer ownership. The control plane degrades gracefully;
  the target's least-privilege roles are required for scanning/masking.
- **Reference properties:** `fromService ... property: connectionString` for Key
  Value and `fromDatabase ... property: connectionString` are per the documented
  schema; confirm values resolve on first sync.

## GitHub delivery

- Commit [`96fe2ef`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/commit/96fe2efeab67c6f5042c65cdb2107bff8e5c4225)
  on `dev/privacyshield`; the remote SHA matched the local commit.
- [GitHub Actions run `38074879168`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/actions/runs/38074879168)
  passed: backend (real PostgreSQL/target/Redis/worker) and frontend jobs.

## Limitations

- Free plans spin down and free Postgres/Key Value are size- and
  durability-limited; paid plans are recommended for a durable demo.
- All resources must share a region (`oregon`).
- The AI phase needs a hosted `OLLAMA_BASE_URL` or a separate Ollama service.
- No metrics endpoint; observability is the health endpoints and log stream.

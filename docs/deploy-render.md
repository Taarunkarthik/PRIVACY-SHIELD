# Deploying PrivacyShield on Render

`render.yaml` at the repository root is a [Render Blueprint](https://render.com/docs/infrastructure-as-code)
that deploys the full stack without Docker Compose:

| Resource | Render type | Purpose |
| --- | --- | --- |
| `privacyshield-api` | Web (Docker) | FastAPI, health check `/api/v1/health/ready` |
| `privacyshield-worker` | Worker (Docker) | Celery worker + beat |
| `privacyshield-web` | Web (Docker) | nginx reverse proxy + React build |
| `privacyshield-redis` | Key Value | Job broker (`noeviction`) |
| `privacyshield-control` | Postgres | Control-plane metadata |
| `privacyshield-target` | Postgres | Synthetic enterprise data |

The API and worker start through `backend/scripts/render/start-*.sh`, which run
`app.render_bootstrap`: an idempotent, advisory-locked step that creates the
least-privilege database roles, schemas, the `pgcrypto` extension, and the
synthetic fixtures (replacing the Docker `*-init.sh` scripts), derives the
runtime connection URLs, and applies Alembic migrations. It is safe to run
concurrently and on every deploy.

> **Status:** this manifest is validated structurally and the bootstrap has been
> exercised against real PostgreSQL, but the deployment has **not** been run
> against a live Render account. Treat the first deploy as a verification step.

## Deploy

1. Push the repository to GitHub (this project lives on `dev/privacyshield`).
2. In the Render Dashboard, **New → Blueprint**, connect the repo, and pick the
   `dev/privacyshield` branch (the Blueprint pins this branch for every service).
3. Render creates the databases, Key Value, and services, generates the shared
   secrets in the `privacyshield-secrets` environment group, and deploys.
4. Wait for `privacyshield-api` to become healthy; the worker starts after the
   same bootstrap.

## After the first deploy

- **Create an administrator.** Open the `privacyshield-api` service **Shell** and run:
  ```shell
  python -m app.cli create-admin --email you@example.com
  ```
- **Register the synthetic target.** In the Render Dashboard open
  `privacyshield-target` → *Connect* and copy the **internal host**. In the app,
  *Connections → New connection*:
  - Host: the target internal host, Port: `5432`, Database: `enterprise_demo`
  - SSL mode: `require`
  - Scanner: `ps_scanner` + the `SCANNER_PASSWORD` value from the
    `privacyshield-secrets` group
  - Deployer: `ps_deployer` + the `DEPLOYER_PASSWORD` value
  Then *Discover* and *Scan* as usual. (The target host is also written to the
  API's `TARGET_ALLOWED_HOSTS` by the bootstrap.)
- **AI classification (optional).** The adapter is a plain HTTP client. Provide a
  hosted Ollama endpoint by setting `OLLAMA_BASE_URL` on the API and worker, or
  add a private Ollama service with a persistent disk. With no endpoint,
  classification fails safely and findings remain for manual review.

## Limitations and known risks

- **Role provisioning requires privileges:** the bootstrap needs `CREATE ROLE`
  (and, best effort, ownership transfer) on the Render Postgres instances. If the
  managed user cannot create roles, the target's least-privilege roles cannot be
  created and target scanning/masking will not work. The control database falls
  back to running as the instance owner and logs a warning.
- **Free plans:** free web services spin down when idle (cold starts), free
  Postgres instances are size-limited and expire, and free Key Value has no
  persistence — queued jobs may be lost on restart. Use paid plans for a durable
  demonstration; the two `1c-2g` compute services are the main cost.
- **Region:** all resources must share a region (currently `oregon`) for private
  networking.
- **Branch:** services pin `dev/privacyshield`; change the field when merging.
- **No metrics endpoint:** observability is the health endpoints and redacted
  logs, visible in the Render Dashboard.

## Troubleshooting

- **`508 Loop Detected` on the login page.** The frontend proxies `/api/*` to
  the API. A loop happens when the proxy is routed back to the frontend, which
  occurs if the upstream host is wrong or the forwarded `Host` header names the
  frontend. The nginx config routes using the upstream's own host
  (`Host $api_host_header`) and passes the browser host as `X-Forwarded-Host`,
  so the same-origin check still works. If you still see a loop, confirm the
  frontend service's `API_HOST` is the API's **internal/private** hostname (the
  API service's *Info → Internal* host, not its `.onrender.com` URL) and
  `API_PORT` matches the API's port.
- **`502` from the API proxy.** The frontend cannot reach the API's private
  hostname; check that both services are in the same region and that `API_HOST`
  / `API_PORT` are set on the frontend service.
- **`403` on sign-in.** The API rejected the request origin; ensure the browser
  talks to the frontend's URL (same origin) and that `COOKIE_SECURE=true`.

## Local alternative

The same application still runs locally with `docker compose up -d --build --wait`;
see the [README](../README.md) and [operations runbook](operations.md).

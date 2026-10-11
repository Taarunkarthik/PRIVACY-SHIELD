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
- A concurrent commit on the branch (`c7553a3`, a root Dockerfile) referenced
  the renamed `frontend/nginx.conf`; it was reconciled by rebase (no
  force-push) and repaired to use the templated config. Final verified HEAD is
  [`b629518`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/commit/b629518c5770cee3a8bcd858d2db68f68277ff69);
  [run `38075060446`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/actions/runs/38075060446) passed.

## Limitations

- Free plans spin down and free Postgres/Key Value are size- and
  durability-limited; paid plans are recommended for a durable demo.
- All resources must share a region (`oregon`).
- The AI phase needs a hosted `OLLAMA_BASE_URL` or a separate Ollama service.
- No metrics endpoint; observability is the health endpoints and log stream.

---

## 11 October 2026: free single-service path

Branch `feat/free-hosting`. The sections above describe the earlier
multi-service Blueprint, now `render.paid.yaml`; they are kept as written. This
section records the change that makes the deployment fit Render's free plan:
one web service and one Postgres instance, with no worker, no Redis and no
shell.

### What was added

| Artifact | Purpose |
| --- | --- |
| `Dockerfile` (repository root) | All-in-one image: built frontend in `/app/static`, backend without dev extras, `JOB_RUNNER=inline`, starts `start-all.sh` |
| `backend/scripts/render/start-all.sh` | Bootstrap, load runtime environment, seed, drop provisioning credentials, `exec uvicorn` on `$PORT` |
| `backend/app/workers/inline.py` | In-process job runner: one worker thread, 15-second sweep, soft and hard time limits, clean shutdown |
| `backend/app/frontend.py` | The API serves the frontend when `STATIC_DIR` is set, with nginx's security headers |
| `backend/app/render_bootstrap.py` | One-instance layout (`TARGET_ADMIN_URL` optional), non-superuser admin, secrets derived from `APP_SECRET` |
| `backend/app/render_seed.py` | Administrator from `ADMIN_EMAIL`/`ADMIN_PASSWORD`; "Synthetic enterprise" connection |
| `render.yaml`, `render.paid.yaml` | Free Blueprint; previous Blueprint kept under a new name |
| `.github/workflows/ci.yml` | Job `image` builds and runs the root image; job `backend` gains a pristine PostgreSQL service |
| `scripts/check_hosted.py` | Checks a deployed or local all-in-one service over HTTP |

### Defects found in the existing Render path

These were present before this change and would have stopped a first deploy.
None had been observed because the bootstrap had only been run as a superuser
and never on Render.

1. **`ALTER ROLE ... NOSUPERUSER NOBYPASSRLS` is refused for a non-superuser**,
   even though it only restates the default (`permission denied to alter role`,
   "Only roles with the SUPERUSER attribute may change the SUPERUSER
   attribute"). Every role was altered that way, so the bootstrap stopped at the
   first role. The same applies to `NOCREATEDB` for an admin without `CREATEDB`.
2. **`CREATE SCHEMA ... AUTHORIZATION ps_view_owner` and `ALTER TABLE ... OWNER TO
   ps_view_owner` need membership.** On PostgreSQL 16 a non-superuser that
   creates a role receives `ADMIN OPTION` on it but may not act as it
   (`must be able to SET ROLE "ps_view_owner"`). The admin now grants itself
   membership of the roles it must assign ownership to.
3. **The runtime environment was written without `export`.** `start-api.sh` and
   `start-worker.sh` source that file and then `exec` the server, which would
   not have inherited `DATABASE_URL`. The file now uses `export`, is created
   with mode `0600`, and quotes values for the shell.
4. **`apply_migrations` required `/app`**; it now runs from wherever the package
   is installed.
5. **A generated `CREDENTIAL_ENCRYPTION_KEY` is not necessarily a Fernet key.**
   Render's `generateValue` is base64; Fernet needs the url-safe alphabet. The
   key is now derived from `APP_SECRET`, in `render.paid.yaml` as well.
6. **Eight simultaneous sign-in attempts used 736 MB** in one process (Argon2,
   64 MB each). Hashing is now limited to two at a time; the same burst peaks at
   354 MB.

### Verified on real PostgreSQL 16 with a non-superuser admin

"Pristine server" means a PostgreSQL 16.15 cluster created for the purpose,
with none of the `ps_*` roles, plus an admin created as
`CREATE ROLE ... LOGIN CREATEDB CREATEROLE` (not a superuser) that owns one
database. This is the closest local equivalent of a new Render instance. The
shared test clusters cannot be used for this: a superuser already created
`ps_app` and `ps_migrator` there, and a different user cannot manage them (the
bootstrap now reports exactly that and stops).

| Check | Result | Evidence |
| --- | --- | --- |
| Bootstrap with `CONTROL_ADMIN_URL` only | Passed | Creates six roles, `enterprise_demo` with 4 tables of 100 rows, `pgcrypto`, pseudonym key; transfers the control database and `public` schema to `ps_migrator`; applies 5 migrations |
| Second run | Passed | Exit 0, no "creating" line; roles, role attributes and settings, memberships, database owners and ACLs, schema and relation owners and ACLs, extensions, row counts, pseudonym key and migration version compared before and after: identical |
| Reader boundary | Passed | `ps_reader`: `SELECT` on `enterprise.customers` refused (42501), private keys refused, cannot create in the masked schema |
| Scanner boundary | Passed | `ps_scanner` reads 100 rows; `UPDATE`, `INSERT`, `DELETE` and DDL refused, also after switching `default_transaction_read_only` off |
| Deployer boundary | Passed | `ps_deployer` reads nothing until `SET ROLE ps_view_owner`; cannot write source tables as view owner |
| Audit rows append-only | Passed | `ps_app` inserts; `UPDATE`, `DELETE`, `TRUNCATE`, `ALTER`, `DROP`, `CREATE TABLE` refused |
| One instance, two databases | Passed | Target roles cannot connect to the control database; `ps_app` and `ps_migrator` cannot connect to `enterprise_demo` |
| Admin without `CREATEDB` | Passed | Ownership transfer refused; migrations run as the admin; application still `ps_app`; audit rows still append-only. Lost: the separate migration credential. `enterprise_demo` cannot be created and the log says why |
| `start-all.sh`, first start | Passed | Log shows bootstrap, "Administrator created", "Demo connection registered", "Serving frontend from ..., jobs run in-process"; `/health` is `ok`; readiness reports `redis: not_used`, `jobs: ok` |
| Sign-in through the hosted origin | Passed | `Origin: https://<name>.onrender.com` accepted, another origin refused with 403; session cookie is `Secure` and `HttpOnly` |
| Scan interrupted by `SIGKILL` | Passed | Row left `RUNNING`, attempt 1; after restart the sweep runs it again; `COMPLETED`, attempt 2 |
| Restart | Passed | "Administrator already exists", "Demo connection already registered"; a changed `ADMIN_PASSWORD` does not reset the account; the earlier session stays valid (same derived key) |
| Scan, AI classification, policy deployment in one process | Passed | All complete over HTTP with `REDIS_URL` pointing at a closed port; the masked view shows `[REDACTED]` to `ps_reader`, who still cannot read the base table |
| No secret in output | Passed | `APP_SECRET`, admin database password, administrator password and all six derived secrets absent from every log; no source value logged |
| Clean stop | Passed | `SIGTERM` ends the process with "Application shutdown complete." |

These are automated in `backend/tests/integration/test_free_hosting.py` and
`backend/tests/integration/test_inline_runner.py`. The second file runs the
inline-mode server against the shared test databases next to the Celery worker
and proves from the server's own log and from attempt counts that the server,
not the worker, ran each job.

### Image, without Docker

Docker is not available where this was written, so the image was not built.
What was done instead, with the same commands the `Dockerfile` runs, in an
empty directory:

- `uv sync --locked --no-install-project`, the spaCy model load check,
  `uv sync --locked`, `python -m compileall app migrations`: all succeeded.
  `pytest` and `ruff` are absent from that environment; `alembic` and `uvicorn`
  are present.
- The real frontend was built with `npm ci` and `npm run build` (Node 22 here,
  Node 24 in the image) and copied to `static/`.
- `start-all.sh` was started from that directory with only the variables a
  deployment sets, against the pristine server. `scripts/check_hosted.py --scan`
  passed: frontend, hashed assets with correct content types, security headers,
  JSON 404 for unknown API paths, sign-in, demo connection, and a completed scan.

### Memory

`ps -o rss=` of the server process started as above (production dependencies,
real frontend, demo database of 4 tables with 100 rows each, sample limit 1000):

| State | Resident memory |
| --- | --- |
| Idle after startup | 98,488 kB (about 98 MB) |
| After three real scans and a deployment | 231,356 kB (about 231 MB) |
| Highest during 8 simultaneous sign-in attempts after those scans | 354 MB |

Memory did not grow between the first and third scan. A scan of the demo
database used 11 to 14 CPU-seconds on the development machine; on a 0.1-CPU
instance that is roughly two minutes.

### Test results

| Suite | Result |
| --- | --- |
| `ruff check .` | Passed |
| Unit (`pytest -m "not integration"`) | 294 passed (218 before this change) |
| Integration (`pytest -m integration`, real PostgreSQL, Redis, Celery worker, model double) | 103 passed (99 before this change) |
| The same hosting tests with `TEST_PRISTINE_POSTGRES_URL` (the path CI uses) | Passed; the server was left with no added roles or databases |

### Not verified

- **The image build.** `docker build -f Dockerfile .` has not run anywhere yet.
  The `image` job in GitHub Actions builds it, starts it against a PostgreSQL
  service with a non-superuser admin, and runs `scripts/check_hosted.py --scan`.
  Until that job has passed, treat the image as unbuilt.
- **Anything on Render.** Not deployed. Specifically unconfirmed: that Render's
  database user has `CREATEDB` and `CREATEROLE` and owns its database (Render's
  documentation says additional databases and users can be created; if
  ownership transfer is refused the fallback above applies); that
  `sslmode=require` works on the internal URL; that a Blueprint adopts the
  existing `PRIVACY-SHIELD` service by name; the dashboard labels quoted in
  `deploy-render.md`; start-up and scan times on the free CPU share.
- **PostgreSQL 17 and 18.** Tested on 16 only. `render.yaml` pins 16.
- **`render.yaml`** was checked field by field against Render's published JSON
  schema and Blueprint reference, not validated by a tool and not applied.
- **`render.paid.yaml`** still has not been deployed.
- **The browser.** The served frontend was checked with HTTP requests, not in a
  browser against this server. The frontend source is unchanged.
- **Real Ollama** in this mode. Classification was run against the controlled
  HTTP double, as in the existing integration tests.

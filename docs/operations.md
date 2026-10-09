# Local operations and troubleshooting

## Prepare Windows and Docker

Run from `D:\DBMS PROJECT\PRIVACY-SHIELD` in PowerShell. Inspect existing files and Git history before changing branches. This project uses Docker Linux containers; Celery is verified in Linux, not as a native Windows worker.

Start Docker Desktop normally. Confirm the engine is available:

```powershell
docker version
docker info --format '{{.OSType}}'
docker compose version
```

Expected: both client and server versions, Linux as the operating-system type, and a Compose version. A named-pipe connection error means the engine is not ready; it does not mean the application build failed.

Use Docker Desktop's supported settings to select a D: location for the Linux disk image before downloading images or models. Docker Desktop may require a restart and enough free destination space for existing data. Preserve existing volumes and distributions. Do not use `wsl --unregister`, delete disk images, or move a live disk manually. If the installed edition does not expose a supported move control, report the limitation and resolve storage before large downloads.

Images, named-volume contents, and Ollama models live in Docker-managed storage. Keeping the repository on D: by itself does **not** move Docker storage. Verify the Docker storage location separately.

## Configure and start

```powershell
python scripts/setup.py
docker compose config --quiet
docker compose up --build -d
docker compose ps -a
docker compose logs --tail 100 api worker
```

The setup script writes random local secrets to `.env` without printing them. Keep `.env` private and retain its encryption key: replacing it can make stored connection credentials unreadable. `.env.example` contains placeholders and must not be used as working credentials.

Avoid posting `docker compose config` output: the unredacted command can expand secret environment values. Use `--quiet` to validate syntax without displaying them. Logs should already redact secrets, but inspect excerpts before sharing.

Initialization services should exit successfully; persistent services should be running or healthy. Database migrations run before the API. The browser entry point is [http://localhost:8080](http://localhost:8080). Database, Redis, and Ollama ports remain private to Docker's network.

Create the administrator after startup:

```powershell
docker compose exec api python -m app.cli create-admin --email admin@example.com
```

The CLI prompts for the password without echoing it. `--password-file` is available for private automation; do not commit that file or include a password as a command-line argument. No default administrator is shipped.

Use a syntactically valid address such as `admin@example.com`; email delivery is not required for bootstrap. Reserved `.test` and `.local` domains are rejected by the configured email validator.

Interactive API documentation is available at [http://localhost:8080/api/docs](http://localhost:8080/api/docs). That page loads Swagger UI JavaScript/CSS from jsDelivr and a favicon from FastAPI's website; its CSP exception is limited to the documentation page. The application dashboard uses local assets. The documentation's static asset URLs contain no credentials or source samples. For offline use, the OpenAPI specification is served locally at [http://localhost:8080/api/openapi.json](http://localhost:8080/api/openapi.json).

## Foundation demo

1. Sign in with the bootstrapped account. A failed login should reveal no credential details.
2. Open Overview. Counts come from metadata and may be zero because scan and policy workflows are not yet implemented.
3. Navigate the nine application pages. Unavailable modules must explicitly identify their planned phase rather than show invented scan results.
4. Sign out. Reusing the prior session must fail.
5. Run acceptance checks, including real database permissions and worker execution.

The target seed contains synthetic customers, accounts, transactions, and support records, with relationships, JSONB, and free-text examples. It is provisioned independently from control-plane metadata. Phase 1 does not register it as a scanned connection or claim PII findings.

## Tests

Start the Compose services first. The check script requires Docker and an existing generated `.env`; it does not build or start containers:

```powershell
python scripts/check.py --integration
```

Without options, the script validates Compose and runs backend Ruff and unit tests in the running API container. `--integration` additionally creates `privacyshield_test` if absent, applies migrations there, checks migration/model agreement, runs the real integration tests, exercises the existing Celery worker, and logs in to the synthetic target as scanner and reader to check privilege boundaries. Test fixtures are retained in the isolated database, while the worker smoke task only reads the application database. Neither path truncates existing application tables.

To include all frontend checks, install Node 24/npm on the host and run:

```powershell
python scripts/check.py --integration --frontend
```

`--frontend` runs `npm ci`, type checking, component tests, and a production build using host npm. The default Docker-only checks do not run these frontend commands. GitHub Actions runs frontend checks separately. The Phase 2 workflow adds a separate target PostgreSQL service and initializes it from the same target role/data scripts used by Compose; acceptance of that new workflow remains pending until its run passes.

After bootstrapping an administrator, verify the actual browser-facing HTTP proxy and authentication endpoints using a private file containing that account's password:

```powershell
python scripts/check_http.py --email admin@example.com --password-file .secrets/admin-password.txt
```

The `.secrets/` directory is ignored by Git. Use a protected local file for an account you control; never print its contents or pass the password as a command-line argument. This check verifies proxy security headers, PostgreSQL/Redis readiness, login, dashboard responses, CSRF rejection, logout, and session revocation. It creates normal login/logout audit events and does not scan or modify target data. `--base-url` supports an alternate local endpoint whose origin is configured in the API.

See [the verification record](verification.md) for the latest measured results. Component tests mock network responses; they do not replace real HTTP or browser checks.

For the real browser workflow, set only the path to the protected password file, then run from `frontend/`:

```powershell
$env:PS_E2E_ADMIN_EMAIL = 'admin@example.com'
$env:PS_E2E_PASSWORD_FILE = (Resolve-Path '.secrets/admin-password.txt').Path
$env:PS_E2E_BROWSER_CHANNEL = 'msedge'
Set-Location frontend
npm run test:e2e
```

This example uses installed Microsoft Edge. Alternatively, install Playwright Chromium with `npx playwright install chromium` and omit `PS_E2E_BROWSER_CHANNEL`. `PS_E2E_BASE_URL` defaults to `http://localhost:8080`. Traces and video are disabled; screenshots are written only to ignored test artifacts. The published Phase 1 browser check verifies all nine routes, live API metrics, session persistence, desktop/mobile layout, and logout. CI's `npm test` remains the mocked component suite and does not need an administrator secret.

Backend development commands (from `backend/`):

```powershell
uv sync --locked --extra dev
uv run ruff check .
uv run pytest -m "not integration"
```

For manual integration execution, environment variables must point to a disposable PostgreSQL database and Redis instance, not a customer's database. `DATABASE_URL` uses `ps_app`; `MIGRATION_DATABASE_URL` uses `ps_migrator`. `CREDENTIAL_ENCRYPTION_KEY` must be a valid Fernet key. `REDIS_URL` points to the same broker for API/tests and worker. Allowed origins are a JSON array, and local HTTP uses `COOKIE_SECURE=false`.

```text
uv run alembic upgrade head
uv run celery -A app.workers.celery_app:celery_app worker --loglevel=INFO
uv run pytest -m integration
```

Run the worker in a separate Linux process, then run integration tests in another process. The `privacyshield.smoke` task checks the database and returns an `ok` result through the real broker. Never run integration fixtures against data you need to preserve.

Frontend development commands (from `frontend/`):

```powershell
npm ci
npm run typecheck
npm test
npm run build
```

The committed lockfiles define reproducible dependencies. Use Node 24 and Python 3.12. Update a lockfile intentionally when changing dependencies; do not silently bypass it to make CI pass.

## Troubleshooting

| Symptom | Check and recovery |
| --- | --- |
| Docker engine unavailable | Start Docker Desktop, wait for engine readiness, rerun `docker version`; stop the acceptance gate if unavailable. |
| Port 8080 already in use | Identify the owning process or adjust the documented frontend port configuration; update the allowed origin to match. |
| Login fails after bootstrap | Confirm email and password, API health, and session cookie delivery. Local HTTP cannot send cookies configured as Secure. |
| Unsafe request returns CSRF error | Obtain a fresh session identity/CSRF token and send `X-CSRF-Token`; do not disable the protection. |
| Readiness fails | Inspect database/Redis health and migration-service logs; do not treat process liveness as readiness. |
| Database authentication fails after editing `.env` | Existing volumes retain their initialized passwords; restore matching configuration or rotate roles deliberately. Restarting does not reinitialize persisted credentials. |
| Migration lacks permissions | Use `ps_migrator` for migrations and `ps_app` only at runtime; never grant runtime superuser to bypass a failure. |
| Worker test times out | Confirm worker is a separate Linux process, broker URLs match, migrations completed, and the task is registered. |
| Frontend build fails after dependency changes | Reconcile `package.json` and its lockfile; use `npm ci` to reproduce the failure. |
| Ollama memory/download issues | AI is optional during foundation. Later use `qwen2.5:1.5b`, limit concurrency, and retain models in D:-backed Docker storage. |
| GitHub push authentication fails | Run `gh auth login --web` securely; never paste a personal access token into chat. |
| Remote branch changed | Fetch and inspect the divergence, preserve both histories, resolve normally, and push without force. |

## Shutdown and preservation

```powershell
docker compose stop
```

Stopping preserves containers and volumes. `docker compose down` removes containers/networks but normally retains named volumes. **Do not add `--volumes` unless you explicitly intend to erase local metadata, source fixtures, and models.** Back up important data and the matching credential encryption key before destructive resets or upgrades.

## GitHub delivery

Inspect the staged diff and secret scan before committing. Use an explicit list of intended files rather than indiscriminate staging when unrelated work is present.

```powershell
git diff --cached --check
git diff --cached --stat
git commit -m "feat: initialize PrivacyShield architecture"
git push -u origin dev/privacyshield
git rev-parse HEAD
git ls-remote origin refs/heads/dev/privacyshield
gh run list --branch dev/privacyshield --limit 5
```

The local and remote hashes must match. Inspect the relevant Actions run and report its actual result. When repository access is unavailable, preserve local work and report the exact blocked command; do not claim GitHub accepted the commit.

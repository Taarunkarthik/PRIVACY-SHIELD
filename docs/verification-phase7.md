# Phase 7 verification record

Phase 7 (readiness) adds real-browser workflow coverage, a bounded latency
benchmark, and a clean-install runbook. It is verified against the running local
stack; GitHub delivery verification is recorded after the push.

## Environment

- Windows host, Docker Desktop Linux containers; full stack up
  (`frontend`, `api`, `worker`, `control-db`, `target-db`, `redis`).
- Browser specs run with the installed Microsoft Edge channel
  (`PS_E2E_BROWSER_CHANNEL=msedge`), so no browser download is required.

## Browser workflows (Playwright)

Run with the stack up and an administrator password file:

```powershell
$env:PS_E2E_ADMIN_EMAIL = "admin@example.com"
$env:PS_E2E_PASSWORD_FILE = "$PWD\.secrets\admin-password.txt"
$env:PS_E2E_BROWSER_CHANNEL = "msedge"
Set-Location frontend; npx playwright test auth.spec.ts discovery.spec.ts scans.spec.ts policies.spec.ts settings.spec.ts
```

| Spec | Result | Covers |
| --- | --- | --- |
| `auth.spec.ts` | Passed | Sign-in, live totals, all nine routes, desktop/mobile layout, sign-out, revoked session; every route now renders its real page |
| `discovery.spec.ts` | Passed | Real connection test and schema discovery without exposing source values |
| `scans.spec.ts` | Passed | Real worker scan with sanitized sampled findings |
| `policies.spec.ts` | Passed | Masking policy list/status, compiled **Preview**, and the approvals/deployments pages |
| `settings.spec.ts` | Passed | Administrator sees editable workspace settings with no page errors |

`classifications.spec.ts` is excluded from this run because it requires the
optional Ollama model; Phase 4 records the real-model classification evidence.

## Measured benchmark

`python scripts/benchmark.py --email admin@example.com --password-file .secrets\admin-password.txt --base-url http://127.0.0.1:8080 --samples 15`
(observe-only: it never creates jobs and never prints credentials):

| Measurement | Result |
| --- | --- |
| Readiness (`/health/ready`) | min 3.7 ms, median 15.0 ms, max 80.7 ms |
| Login (incl. Argon2 verify) | 184.2 ms |
| Dashboard (`/dashboard/summary`) | min 7.5 ms, median 8.5 ms, max 33.3 ms |
| Most recent scan | 0.70 s |
| Most recent deployment | 0.07 s |
| Most recent classification | not measured (no jobs; Ollama off) |

Use `127.0.0.1`, not `localhost`, when measuring on Windows: resolving
`localhost` to `::1` before `127.0.0.1` added ~2 s per request in this
environment. The loopback IP must be present in `ALLOWED_ORIGINS` for
authenticated requests.

## Clean-install runbook

```powershell
git clone https://github.com/Taarunkarthik/PRIVACY-SHIELD.git
Set-Location PRIVACY-SHIELD
git switch dev/privacyshield
python scripts/setup.py                 # writes ignored .env secrets
docker compose up -d --build --wait     # migrates and starts six services
docker compose exec api python -m app.cli create-admin --email admin@example.com
# open http://localhost:8080 and sign in
python scripts/check.py --integration --frontend   # full acceptance gate
```

Reproducible demos: `python scripts/scan_demo.py`, `python scripts/classify_demo.py`
(with `--profile ai`), and `python scripts/policy_demo.py`.

## Limitations

- The browser specs are a documented local step; CI runs backend and frontend
  unit/build jobs only. A full-stack Playwright CI job is not yet added.
- `classifications.spec.ts` requires the optional Ollama profile.
- No metrics endpoint; observability is the health endpoints and redacted error
  logging.
- Throughput for full-table scans, large classifications, and many concurrent
  deployments is not measured; the recorded numbers cover the synthetic fixture.

# Pre-submission hardening verification record

Work added on `dev/privacyshield` after the submission build, as six reviewed
commits. Nothing here changes the product's workflow or the database schema; it
closes small gaps before the project is finished.

- **Repository hygiene** — an MIT `LICENSE`, a `SECURITY.md` reporting policy, a
  `.github/dependabot.yml` for pip, npm and GitHub Actions, and a corrected
  submission date in [roadmap.md](roadmap.md).
- **One-command demo** — `scripts/demo.py` runs connect, discover, scan, mask and
  deploy in one step and prints a before/after view of the protected table.
- **Render resilience** — an error boundary in the React app, so one unexpected
  render error shows a recovery panel instead of a blank workspace.
- **Governance** — a per-user rate limit on scan and classification job
  creation, and an optional separation-of-duties rule for policy approval.
- **Detection safety** — custom patterns that are prone to catastrophic
  backtracking are rejected before they are stored.
- **Housekeeping** — expired and long-revoked sessions are pruned by the job
  sweep and by Celery beat.

This record says what was run, on what, and what was not.

## Environment

- Windows 11 with Docker Desktop, Linux containers. Docker client and server
  `29.8.2`, Docker Compose `v5.5.1`, Node `24.14.0`.
- The full Compose stack, rebuilt from the six commits and healthy: `control-db`,
  `target-db`, `redis`, `migrate` (exited 0), `api`, `worker` and `frontend`.
  Images are rebuilt because the backend and frontend code is baked into them,
  not bind-mounted.
- **Not Render or Vercel.** Nothing was deployed to a hosted account.
- **Not a real model.** The `ai` Compose profile was left off, so no Ollama
  server was reachable.

## Results

| Check | Result |
| --- | --- |
| `ruff check .` on the host and in the rebuilt API container | Passed |
| Backend unit tests (`pytest -m "not integration"`) in the API container | 545 passed, 2 skipped |
| Backend unit tests on the Windows host | 529 passed, 18 skipped (the skips are POSIX-shell-only tests) |
| `python scripts/check.py --integration` against real PostgreSQL, Redis and a separate Linux worker | 146 passed, 4 skipped, 0 failed; exit code 0 |
| Real worker smoke test through the broker | Passed |
| Real target role boundaries (scanner cannot write or read keys; reader cannot reach source data) | Passed |
| Frontend `tsc -b` | Passed |
| Frontend component tests (`vitest run`) | 97 passed, 10 files |
| Frontend production build | Passed |
| `python scripts/demo.py` end to end | `DEMO COMPLETE`: 24 sampled results across 7 categories, policy version 5 deployed in 2.1 s, before/after masked columns printed |

The 4 skipped integration checks are the pristine-server cases that need a
separate empty PostgreSQL cluster (`TEST_PRISTINE_POSTGRES_URL`), as in the
earlier records.

## What each change is covered by

- **Rate limit.** Unit tests in `backend/tests/test_rate_limit.py` exercise the
  limiter directly (it allows up to the limit, then returns `429` with
  `Retry-After`; the window expires; distinct users are independent). The default
  is 60 jobs per minute per user, generous enough that the single-admin demo and
  the existing tests are unaffected.
- **Separation of duties.** A pure `ensure_can_approve` helper is covered by
  `backend/tests/test_policy_separation.py`. It is **off by default**, because
  the demo runs with a single administrator who must approve their own policy.
- **ReDoS guard.** `backend/tests/test_safe_regex.py` asserts that ordinary
  patterns (including the project's own Aadhaar and PAN shapes) are accepted and
  that classic nested-quantifier patterns are rejected. Two cases were added to
  `backend/tests/test_settings.py`.
- **Session pruning.** `backend/tests/test_maintenance.py` checks the delete
  predicates against a fake session and confirms the function is wired into both
  the inline `SWEEPERS` and the Celery `beat_schedule`.
- **Error boundary.** `frontend/tests/ErrorBoundary.test.tsx` renders a child
  that throws and asserts the fallback appears and the raw error is not shown.
- **Demo script.** Run against the live stack here; the output is recorded above.

## Environment note (not a code issue)

The target database volume was initialised before the masking-audiences feature,
so it lacked the `ps_support` and `ps_analyst` roles and six
`test_masking_audiences.py` checks failed on the first run. The project's own
documented, idempotent remedy was applied once:

```powershell
Get-Content -Raw infra\postgres\add-audience-roles.sql | docker compose exec -T target-db psql -U postgres -d enterprise_demo -v ON_ERROR_STOP=1 -f -
```

All six then passed. This is a pre-existing local-volume drift, unrelated to
these commits, and is already listed under [Known limits](#known-limits).

## Not verified

- **GitHub Actions for these commits.** Nothing has run in CI yet.
- **Browser specs (`npm run test:e2e`).** Not run in this record; the mocked
  component suite and the production build were. The specs need the Vite dev
  server and an administrator secret.
- **`scripts/check_http.py`.** Not run here.
- **The real Ollama model.** No model path changed, and the `ai` profile was
  off, so classification quality was not exercised.
- **Render and Vercel.** Not deployed.
- **Multi-process behaviour of the limiter.** The job rate limit and the login
  throttle are in-process, so a deployment with several API processes counts
  each separately. Only the single-process local layout was exercised.

## Known limits

- The job rate limit and the login throttle are per-process, in-memory
  limiters; they bound one process, not a fleet.
- The ReDoS guard is a conservative heuristic, not a proof. It rejects the
  classic exponential shapes; it does not certify that an accepted pattern is
  linear.
- Separation of duties is opt-in (`REQUIRE_SEPARATE_APPROVER=true`). With it on,
  an administrator cannot approve a policy they created.
- Session pruning rides the 15-second sweep cadence rather than an hourly one,
  matching the other sweepers.
- `retention_days` remains a stored, validated setting that is not yet enforced
  by a pruning job; this was deliberately left out of scope.
- A target database initialised before the masking-audiences feature still needs
  [the audience role setup](masking-audiences.md#role-setup) once.

# Phase 6 verification record

Phase 6 passed the full local acceptance gate: expanded permission and
immutability checks, bounded operator settings, a filtered audit timeline, and
concurrency/recovery tests. GitHub delivery verification is recorded after the
push.

## Environment

- Windows host, Docker Desktop Linux containers; backend and frontend images
  rebuilt from the current tree before the gate.
- `python scripts/check.py --integration --frontend` with a fresh isolated
  `privacyshield_test` database, a separate Linux Celery worker on an isolated
  queue, and a controlled HTTP model double.

## Results

| Check | Result | What the evidence establishes |
| --- | --- | --- |
| Backend Ruff | Passed | Settings, audit filters, service, models, and tests lint clean |
| Backend unit tests | **171 passed** | +30 settings/schema/detection-hook tests |
| Alembic upgrade and `alembic check` | Passed | `0004_settings` applies; live schema matches models; no drift |
| Real integration tests | **88 passed** | Real PostgreSQL/Redis/Linux worker, including 31 new Phase 6 tests |
| Real worker smoke | Passed | Separate Linux Celery worker completed a task against PostgreSQL |
| Target role boundaries | Passed | Scanner cannot write or read keys; reader cannot read source/keys or assume the owner role |
| Frontend type check, tests, build | **49 passed** | Includes 7 settings and 3 audit-timeline tests |

## New coverage

- **Settings API** (`tests/test_settings.py`, `tests/integration/test_settings.py`):
  singleton upsert with defaults, `GET` for any authenticated user, `PATCH`
  restricted to `ADMIN`, bounded validation (regex compiles, ≤20 patterns,
  name ≤60, regex ≤200, category allowlist), 403/422/409 mapping, and no secret
  exposure.
- **Audit timeline filtering**: `GET /api/v1/audit-events` gained optional
  `subject_type`, `since`, and `until` filters alongside the existing
  `event_type`/`actor_id`; the React timeline sends them and degrades gracefully
  if ignored.
- **Audit immutability** (`tests/integration/test_audit_security.py`): the
  runtime role `ps_app` holds only `SELECT, INSERT` on `audit_events`; `UPDATE`,
  `DELETE`, and `TRUNCATE` raise `DBAPIError`, while append still works. Already
  enforced by the Phase 1 grants — no new grant change was required.
- **Concurrency and recovery** (`tests/integration/test_recovery_concurrency.py`):
  a stale approval decision cannot overwrite an applied decision; concurrent
  decisions serialize on the row lock; an interrupted worker leaves durable
  state; and an uncertain-outcome deployment reconciles from the target receipt
  without re-applying DDL.
- **Custom detection patterns**: normalized `custom_patterns` table plus a
  bounded `compile_custom_patterns` / `detect_pii(patterns=)` hook. An empty
  pattern set is byte-for-byte the prior behavior (asserted).

## Limitations and follow-up

- The scan pipeline (`run_scan`) does not yet load enabled custom patterns from
  the control database. Wiring it surfaces new `CUSTOM_*` labels in
  `scan_results.category_counts`, which the Phase 4 classification contract
  rejects; enabling it needs a deliberate classification-contract change. The
  storage, API, and bounded hook are complete and unit-tested.
- No metrics endpoint yet; observability is the existing health endpoints and
  redacted error logging.
- Passing runs still emit `httpx`/TestClient and SQLAlchemy `distinct(...)`
  deprecation warnings; review before dependency upgrades.
- Deployment onto row-level-security tables remains deferred (Phase 5).

## GitHub delivery

Recorded after the push: commit, matching remote SHA, and a passing GitHub
Actions run.

# Phase 5 verification record

Phase 5 passed the full local acceptance gate, including a real target-side
deployment that proves reader isolation and unchanged source data. Commit,
push, remote-SHA verification, and matching GitHub Actions remain the delivery
gate; those rows are recorded after the push.

## Environment

- Windows host with Docker Desktop Linux containers; images rebuilt from the
  current tree before the gate.
- `python scripts/check.py --integration --frontend` with a fresh, isolated
  `privacyshield_test` database, a separate Linux Celery worker on an isolated
  queue, and a controlled HTTP model double. The AI double covers orchestration
  only; real model quality is Phase 4 evidence.
- No source database was mutated. Deployment DDL targets only
  `privacyshield_masked`; source rows in `enterprise` were compared before and
  after.

## Results

| Check | Result | What the evidence establishes |
| --- | --- | --- |
| Compose configuration | Passed | Validated service, health, and dependency wiring |
| Backend Ruff | Passed | Policy compiler, service, execution, API, and schemas lint clean |
| Backend unit tests | **141 passed** | Includes 16 new compiler/state-machine tests |
| Alembic upgrade and `alembic check` | Passed | Migration applies; live schema matches models; no drift |
| Real integration tests | **57 passed** | Real PostgreSQL/Redis/Linux worker; includes 8 new policy tests |
| Reader view isolation (real) | Passed | `ps_reader` sees pseudonymized email, `[REDACTED]` name, `NULL` phone; deterministic pseudonyms; base table reads denied |
| Source preservation (real) | Passed | `ps_scanner` reads the original synthetic values after deployment |
| Idempotent deployment | Passed | Duplicate deployment with the same idempotency key returns one record; re-running a completed deployment is a no-op |
| RBAC and transitions | Passed | Analysts cannot approve; invalid transitions return 409; unknown columns return 422 |
| Separate worker smoke | Passed | A real Linux Celery worker completed a task against PostgreSQL |
| Target role boundaries | Passed | Scanner cannot write or read keys; reader cannot read source/keys or assume the owner role |
| Frontend type check, tests, build | **39 passed**, build passed | Includes 4 new policy component tests; production build succeeds |

## New coverage

- Unit (`tests/test_policy_compiler.py`): security-barrier view compilation,
  typed `NULL` for unresolved columns, REDACT/PARTIAL null handling, keyed-HMAC
  pseudonym output as text, deterministic and bounded view names, rejection of
  injected domains and untrusted data types, deterministic plan fingerprints.
- Integration (`tests/integration/test_policy_lifecycle.py`): DRAFT →
  PENDING_APPROVAL → APPROVED → DEPLOYED and the REJECTED branch, analyst/auditor
  RBAC, invalid transitions, unknown-column rejection, idempotent deploy, and
  compiled preview.
- Integration (`tests/integration/test_policy_deployment.py`): real deployer
  `SET LOCAL ROLE ps_view_owner` DDL, receipt-backed idempotency, reader view
  isolation, and unchanged source values.
- Frontend (`tests/Policies.test.tsx`): list/status, submit → approve → deploy
  with CSRF, compiled preview, and read-only auditor behavior.

## Limitations and follow-up

- Deployment onto tables with row-level security enabled is deferred.
- Pseudonymized values depend on target-side keys; a missing domain key yields
  `NULL` (fail closed).
- Sensitive JSONB and free text use whole-column nullification; path-level
  projection is future work.
- The lifecycle and deployment checks are real-service tests, not browser
  workflows. A dedicated Playwright policy workflow is planned for Phase 7.
- Deployment reconciliation is proven by receipt idempotency and re-run safety;
  a live mid-deployment crash injection is not yet automated.

## GitHub delivery

Pending: successful push, matching remote SHA, and a passing GitHub Actions run
are required before Phase 5 is claimed complete.

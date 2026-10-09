# Phase 2 verification record

Phase 2 connection management and schema discovery passed the complete local gate: backend, frontend, final Docker builds, HTTP checks, the registration demo, both browser workflows, and API replacement through the unchanged frontend. Commit/push and GitHub Actions verification remain pending. Do not interpret this record as a remotely delivered Phase 2 release until those results are recorded.

## Confirmed results

| Check | Result | Evidence and limits |
| --- | --- | --- |
| Backend unit tests | **29 passed** | Request validation, credential encryption/redaction, source-scope validation, deterministic fingerprints, and foundation behavior |
| Real backend integration tests | **29 passed** | 18 foundation cases plus 11 discovery cases using real control and target PostgreSQL, Redis, and a separate Celery worker |
| Alembic upgrade and schema check | Passed | Existing migration applies and SQLAlchemy models match the live schema |
| Worker smoke | Passed | Actual Redis delivery to the separate Linux worker, with a PostgreSQL read |
| Scanner and reader role probes | Passed | Scanner can read synthetic fixtures but cannot write after disabling its read-only default; reader cannot read source data/keys or assume the view-owner role |
| Unknown row-estimate regression | Passed after the full gate | Actual PostgreSQL fixture with a populated, unanalysed table preserves `reltuples = -1`; a targeted real integration rerun passed |
| CI target provisioning probe | Passed locally | A separate disposable PostgreSQL container used the repository init/data scripts; SCRAM rejected an incorrect password and accepted the generated scanner credential for 100 synthetic rows |
| Final backend/frontend Docker builds | Passed | Both completed with exit status `0`; the frontend production build ran successfully inside Docker |
| nginx configuration | Passed | `nginx -t` accepted the final configuration |
| Frontend unit tests and type checking | **18 passed; type checking passed** | Includes quoted-name identity regression; HTTP is mocked in component tests |
| Real HTTP registration/discovery demo | Passed | `register_demo.py` registered or reused `Synthetic enterprise`, discovered four tables, and verified JSONB plus a composite foreign key |
| Real HTTP foundation regression | Passed | `check_http.py` verified readiness, proxy security headers, login, dashboard, CSRF rejection, logout, and revoked-session denial |
| Real browser workflows | **2 passed in 47 seconds** | Actual discovery found four tables and the composite foreign key; authentication/navigation/session persistence, mobile layout, and logout also passed against the rebuilt service |
| API replacement through frontend proxy | Passed | Force-recreated only the API, left the frontend running, waited for API health, then passed the actual HTTP readiness/auth/headers/CSRF/logout check |
| Staged-file secret/index review | Passed | Reviewed 95 indexed files, including 35 Phase 2 changed files; rerun if subsequent edits change the staged content |

The full backend gate was `python scripts/check.py --integration`. Discovery cases cover encrypted credentials and write-only responses; duplicate names and pagination; actual table/column/JSONB/primary-key/composite-foreign-key metadata; immutable snapshots; role permissions; deactivation and credential updates; host and schema restrictions; sanitized connection failures; rejection of privileged or owner-capable scanners; read-only transactions and limits; and quoted identifiers with inherited write/ownership checks.

The isolated target fixture uses unique test-owned schemas/roles and removes those exact objects afterward. Existing enterprise fixture data is not modified by discovery. Source queries read PostgreSQL catalogs, not customer rows.

## Final checks still pending

| Check | Status |
| --- | --- |
| Phase 2 commit and remote SHA | Pending |
| Phase 2 GitHub Actions | Pending; Phase 1's successful run is not evidence for the new target-service workflow |

The proxy fix uses Docker's resolver with a variable upstream so replacing the API container does not leave nginx using the removed container's address. Its live replacement check passed after waiting for the recreated API to become healthy. A request made immediately during startup returned a transient `502`; use Compose's `--wait` when verifying a restart. This test confirms recovery after replacement, not zero-downtime deployment.

## Correctness fixes from review

- Schema Explorer uses an unambiguous `(schema, table)` identity instead of a dot-joined key. PostgreSQL identifiers may themselves contain dots; `a.b`/`c` and `a`/`b.c` must select different tables.
- PostgreSQL's unknown row estimate remains `-1` and is displayed as unavailable, rather than reported as zero.
- The schema input explains the actual `enterprise`/`public` default. Other source schemas must be explicitly selected.

## Current limits

- This phase inventories metadata only. PII sampling, Presidio, AI classification, masking, approval, and deployment remain later capabilities.
- Discovery is synchronous, bounded to 20 requested schemas, 500 tables, 10,000 columns, and 5,000 primary/foreign-key constraints. Each catalog statement has a 10-second timeout.
- Row counts are estimates and may be unavailable. Fingerprints intentionally exclude volatile estimates and object identifiers.
- Saved snapshots retain historical metadata. Changing a connection's endpoint does not establish that an older snapshot describes the new endpoint; rediscover before using it for later scanning or policy work.
- Browser credentials are transient inputs, and API responses omit passwords and ciphertext. This does not replace future production security testing or TLS deployment work.

After final checks pass, review staged files, commit only intended Phase 2 changes, push to `dev/privacyshield`, verify the remote SHA, and inspect the matching Actions run before marking this phase complete.

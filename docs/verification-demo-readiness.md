# Demo-readiness verification record

Work added after Phase 7 on branch `feat/demo-readiness`: format-aware masking,
a before/after policy preview, deployed-output evidence, suggested rules,
dashboard breakdowns, random sampling, checksum rules for Aadhaar and PAN, and a
labelled accuracy benchmark. This record says what was run, on what, and what
was not.

## Environment

- Linux, Python 3.12.3, Node 22, PostgreSQL 16 and Redis installed natively.
  Two PostgreSQL clusters (control plane on 5432, target on 5433) provisioned
  with the repository's `infra/postgres/control-init.sh`, `target-init.sh` and
  `demo.sql`, password authentication on TCP, mirroring the GitHub Actions job.
- A separate Celery worker process and the repository's HTTP Ollama double for
  the integration tests.
- **Not Docker Compose.** The Compose stack, the nginx frontend image and the
  Render Blueprint were not built or started for this record.

## Results

| Check | Result |
| --- | --- |
| `ruff check .` | Passed |
| Backend unit tests (`pytest -m "not integration"`) | 218 passed |
| `alembic upgrade head` from an empty database, then `alembic check` | Passed; no drift between models and migrations |
| Migration 0005 downgrade and re-upgrade on an empty database | Passed |
| Integration tests against real PostgreSQL, Redis and a separate worker | 99 passed, run twice: on fresh databases and again on the used ones |
| Frontend `tsc -b` | Passed |
| Frontend component tests (`vitest run`) | 54 passed |
| Frontend production build | Passed |
| Browser specs `auth`, `discovery`, `scans`, `policies`, `settings` | 5 passed, Chromium against the Vite dev server and the real API and worker |
| Accuracy benchmark | Recall 1.00, precision 0.77 on 40 labelled columns; see [detection accuracy](detection-accuracy.md) |

Before this work the suite was 171 unit, 88 integration and 49 component tests,
all passing in the same environment.

## Independent review

The diff was reviewed twice by a reviewer that had not seen it being written.
Defects it found and that were fixed before this record:

- `MASK_EMAIL` showed everything after the `@`, so `a@b.com;9876543210` leaked
  the trailing text. The host part must now be a dotted host name.
- The sample preview returned real pseudonyms, made with the target's secret
  key, for known example inputs. It now shows an unkeyed stand-in.
- `KEEP` was suggested for columns whose values were skipped, truncated, or
  empty in every sampled row.
- Random sampling converted every row of a table before choosing the sample.
  Rows are now chosen first and only those are converted.
- Dashboard coverage and "currently deployed version" were resolved per
  connection record instead of per target table.
- Dashboard risk used only the most frequent category in a column.
- Migration 0005 broke `alembic history`.

All but two have a test that fails without the fix. The sampling change was
confirmed from the query plan (`EXPLAIN VERBOSE` shows the conversions above the
`LIMIT`), and the migration by running `alembic history` and `alembic heads`.

## Found in existing code

- **A newer policy version could not deploy** when it changed a column's output
  type, for example a `numeric` column kept in version 1 and redacted in
  version 2. `CREATE OR REPLACE VIEW` refuses that. The view is now recreated in
  the same transaction. Covered by
  `test_new_version_can_change_a_columns_output_type`.
- **`scans.spec.ts` could read the previous scan's panel.** After starting a
  scan the status panel shows the previously selected scan for a moment, and the
  spec could read its "Completed" status. It failed about half the time against
  the dev server. The spec now waits for the new scan's heading first; it then
  passed six consecutive runs. The spec was not run against the code before this
  branch, so whether it also failed there is not established.
- **The policy editor keyed tables by name only**, so two tables with one name
  in different schemas could not be told apart. It now uses schema and name.

## Not verified

- **GitHub Actions.** Nothing has run in CI for these commits.
- **Docker Compose and Windows.** Run `python scripts/check.py --integration
  --frontend` after pulling; that is the project's own gate.
- **Real Ollama model.** No code on the model path changed, but the smoke test
  and `classifications.spec.ts` were not run.
- **Render.** Not deployed.
- **Large tables.** The page-sampling path was exercised by lowering its size
  threshold in a test. No table over 32 MB was scanned, and no scan was timed.
- **Node 24.** The frontend was tested on Node 22; the project specifies 24.

## After pulling

```powershell
git switch dev/privacyshield
git pull
docker compose up -d --build --wait      # rebuilds images; the migrate service applies 0005
python scripts/check.py --integration --frontend
```

Existing scans, policies and deployed views keep working. Run a new scan to get
the random sample and the checksum rules. To try the new masks, create a policy
from **Masking Policies → New policy → Apply suggestions**.

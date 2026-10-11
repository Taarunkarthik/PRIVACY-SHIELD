# Submission-build verification record

Work added on branch `feat/submission-build`, on top of the demo-readiness
commit `6750112`:

- a tamper-evident hash chain over the audit log ([audit-chain.md](audit-chain.md));
- masking per audience: one policy, a differently masked view for general
  readers, support staff and analysts ([masking-audiences.md](masking-audiences.md));
- value shapes and detector triage for AI classification
  ([classification.md](classification.md));
- a single-container deployment that needs one PostgreSQL instance and no Redis
  or worker ([deploy-render.md](deploy-render.md));
- a redesigned interface.

The five were built separately, merged, and then tested and reviewed together.
This record says what was run on the merged result, on what, and what was not.

## Environment

- Linux, Python 3.12, Node 22, PostgreSQL 16 and Redis installed natively. Two
  PostgreSQL clusters (control plane and target) provisioned with the
  repository's `infra/postgres/control-init.sh`, `target-init.sh` and
  `demo.sql`, password authentication on TCP, as in the GitHub Actions job.
- A separate Celery worker process with beat, and the repository's HTTP Ollama
  double, for the integration tests.
- For the hosted layout, a throwaway PostgreSQL cluster with none of
  PrivacyShield's roles, entered through a non-superuser admin, which is what a
  managed database provides.
- **Not Docker.** No image was built here: not the Compose images and not the
  all-in-one image in the repository root.
- **Not Render.** Nothing was deployed to a live account.
- **Not a real model.** No Ollama server was reachable.

## Results

| Check | Result |
| --- | --- |
| `ruff check .` | Passed |
| Backend unit tests (`pytest -m "not integration"`) | 491 passed |
| `alembic upgrade head` from an empty database, then `alembic check` | Passed; one head (`0007_policy_audiences`), no drift |
| Downgrade to `0005_format_masks`, upgrade to head, `alembic check` | Passed |
| Integration tests against real PostgreSQL, Redis and a separate worker | 133 passed. 132 of them were run twice, on fresh databases and again on the used ones; the last, for the Vercel start wrapper, was added afterwards and run with the full suite once |
| Frontend `tsc -b` | Passed |
| Frontend component tests (`vitest run`) | 82 passed |
| Frontend production build | Passed |
| Browser specs `auth`, `classifications`, `discovery`, `policies`, `scans`, `settings` | 6 passed, Chromium against the Vite dev server and the real API and worker. The classification spec ran against the HTTP model double |
| Manual pass in Chromium at 1440x900 and 1280x720 | Sign-in, overview, a three-audience policy (rules, preview and protected output per audience), the new-policy dialog, log integrity check, classification and scans. No console errors other than the expected `401` before sign-in |

Before this work the suite was 218 unit, 99 integration and 54 component tests.

The integration suite includes the hosted layout end to end: the start script
bootstraps an empty server as a non-superuser, serves the frontend and API from
one process, runs a scan, a classification and a deployment with no Redis, and
recovers a scan from a process that was killed mid-job.

A three-audience policy on `enterprise.customers` was deployed through the API
and read back through each role's view: `ps_reader`, `ps_support` and
`ps_analyst` each saw their own masking, and none could read the source table.
The audit chain then verified as intact with every event sealed.

## What joining the five needed

- Migration `0007_policy_audiences` was written against `0005`; it now follows
  `0006_audit_chain`, so there is one head.
- The single-container deployment has no Celery beat, which is what sealed
  audit events into the chain. The in-process job sweep now does it. The hosted
  integration test checks the database for sealed rows before it calls the
  verify endpoint, because that endpoint seals on its own and would hide a
  sweep that never ran.
- The interface for audiences did not exist. It was added to the Policies page
  and its dialog, with tests.

## Independent review

The merged diff was reviewed by two reviewers that had not seen it being
written, one for the backend and deployment and one for the frontend. Neither
found a breach of the project's security rules. What they found and what was
done:

- **Value shapes showed more than the documentation said.** No letter or digit
  survived, but a sign at the end of a value did (`HIV+` and `HIV-` had
  different shapes), a shape could describe a single row, and shapes were
  computed for numbers and dates, where they add only sign and magnitude. Now
  a sign at either end is written `?`, a shape is stored only when five or more
  sampled values have it, and only character columns get shapes. Shapes stored
  by an earlier build are filtered by the same rules before they are sent to
  the model. The documentation states what remains visible.
- **Verifying the audit chain could use up the connection pool.** Ten
  concurrent requests on a log of 300,000 events made another request time
  out. One verification now runs at a time per process; a second request gets
  `429`. An out-of-range anchor index returned `503`; it is now rejected.
- **The hosted bootstrap could log part of the admin database password** if the
  URL was typed by hand with an unescaped `/`, `?` or `#` in the password. The
  error no longer quotes the URL.
- **A slow model call could end the single-container service.** One call can
  block for 120 seconds, but the hard time limit was 60 seconds after the soft
  one, and in that layout the hard limit exits the process. The gap is now 150
  seconds.
- **Policies page.** Selecting a policy by any route other than a click (a
  newly created policy, Back, Forward) left the page on the previous tab with
  "could not be loaded". A failed create showed its error behind the dialog.
  Escape did not close the dialog. A key domain left over from an abandoned
  pseudonym rule won over the general reader's when rules were copied. The
  audience table ran role names into the headings. All fixed.
- **The animated background repainted 30 times a second on every page.** Behind
  the application it now runs at half the rate and one canvas pixel per CSS
  pixel. It still stops when the tab is hidden, when paused, and under
  `prefers-reduced-motion`.
- Smaller layout fixes at 390 px and at 1280x720.

Each behavioural fix has a test. Two of the new frontend tests were checked by
removing the safeguard they cover and watching them fail.

A third reviewer then read the fixes alone. It found that shapes already
stored by the previous build would have been rejected by the stricter check
(now filtered instead), a second form of malformed admin URL, and three small
problems in the Policies dialog; all are fixed. It ran the shape function
against its validator on 18 million generated values without a mismatch, and
the same check was repeated here on 1.7 million values after the last change.

## Not verified

- **The all-in-one Docker image has not been built.** The `image` job in
  `.github/workflows/ci.yml` builds it and runs `scripts/check_hosted.py`
  against it. Its first run on GitHub is the check.
- **Nothing has run on Render.** The bootstrap was run against a PostgreSQL 16
  server with the kind of restricted admin user Render provides, not against
  Render itself.
- **Prompt v4 and value shapes have not been run against the real model.**
  Without shapes the request is byte for byte the one prompt v3 sent. If the
  model answers worse with them, set `AI_SEND_SHAPES=false`. The two smoke
  commands are in [classification.md](classification.md).
- **PostgreSQL 17 and 18** were not tested; the hosted database is pinned to 16.
- **Vercel.** `Dockerfile.vercel` and its start wrapper are experimental. The
  wrapper is tested against a real PostgreSQL server, but nothing has been
  built or run on Vercel or on a Neon database. See
  [deploy-vercel.md](deploy-vercel.md).
- **Docker Compose** was not started with this build. The Compose images are
  unchanged apart from the code they contain.

## Known limits

- A target database initialised before this build does not have the
  `ps_support` and `ps_analyst` roles. A policy with rules for those audiences
  fails to deploy there with `AUDIENCE_ROLE_MISSING` until the roles are
  created; the SQL is in [masking-audiences.md](masking-audiences.md#role-setup).
  Reader-only policies are unaffected.
- The audit chain is not keyed. Someone who can write to the database as its
  owner can rebuild it after a change. Comparing against a head hash saved
  outside the system detects that; see [audit-chain.md](audit-chain.md).
- Behind a proxy, sign-in attempts are counted for all visitors together: more
  than ten in five minutes makes sign-in answer "Try again later" for everyone
  until the window passes.
- Dashboard coverage counts a column as masked by what general readers see.
- Shape counts are aggregates. In a text column whose values differ only in
  form (`Yes` and `No`), the stored counts are that column's distribution.

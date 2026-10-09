# Delivery roadmap

Each phase is gated on relevant tests, a reviewed commit, a successful push to `dev/privacyshield`, and remote-SHA confirmation. Phase 1 is **implemented with local backend, frontend, real-service, and HTTP checks passed**. Browser review, commit/push confirmation, and GitHub Actions results are pending. Later phases have not started. See [the verification record](verification.md) for evidence and limitations.

The seven weeks below are sequencing estimates, not statements that work ran for those durations. An eighth week is reserved for fixes and demonstration preparation.

| Phase | Deliverables | Acceptance gate | Status |
| --- | --- | --- | --- |
| 1 — Foundation | Monorepo, Compose, normalized models/migrations, authentication/RBAC, dashboard shell, synthetic target, CI | Clean startup; migration; login/logout/CSRF; protected endpoints; frontend tests/build; separate real Celery worker smoke | Implemented; local checks passed; browser and GitHub delivery pending |
| 2 — Discovery | Encrypted connection management; least-privilege provisioning; catalog discovery; Schema Explorer | Discover tables, PK/FK and composite relationships; reject scanner writes; redact credentials | Not started |
| 3 — Scanning | Presidio and Indian candidate recognizers; bounded JSONB/text sampling; async jobs; results | Real async scan detects synthetic scalar/JSONB/text fixtures; enforce sampling/timeouts; no retained raw samples | Not started |
| 4 — Classification | Ollama adapter; structured response validation; classifications UI/evaluation | Real `qwen2.5:1.5b` smoke; reject malformed/unknown fields and injection attempts; manual review during outages | Not started |
| 5 — Masking and Approval | Compiler, previews, immutable policy versions, approval, deployment/reconciliation | Reader sees approved views only; unchanged source data; idempotent deployment; schema drift blocks deployment | Not started |
| 6 — Security and Audit | Permissions matrix; audit timeline; redaction; concurrency/recovery | Audit immutability; stale/concurrent decisions; inherited privilege checks; interruption and uncertain-outcome recovery | Not started |
| 7 — Readiness | Browser workflow tests; measured benchmarks; observability; deployment/demo docs | Clean-install full workflow; published measured limitations and repeatable commands | Not started |

## Phase 1 acceptance evidence

- Passed: locked dependency installation, backend Ruff, 13 unit tests, and 18 real integration tests.
- Passed: PostgreSQL migration/model agreement, constraints, runtime grants, sessions, CSRF, and real Redis/Celery delivery.
- Passed: real scanner/reader logins against the synthetic target, including denied scanner writes after disabling the read-only default.
- Passed: frontend type checking, 9 component tests using mocked HTTP, production build, and npm audit with zero reported vulnerabilities at verification time.
- Passed: Compose startup, successful migration exit, and actual HTTP proxy/readiness/login/dashboard/CSRF/logout checks.
- Pending: browser interaction review, final staged-file secret review, descriptive commit, remote branch SHA/commit link, and GitHub Actions result.

If a required service is unavailable, record that gate as blocked. Do not substitute mocked tests or proceed into the next phase as though acceptance succeeded.

## Per-phase delivery report

Every phase report must identify the actual commit hash and branch, summarize changed files and features, distinguish mocked tests from real-service checks, report failures or blocked checks, and include the GitHub commit URL. Only a remote-ref check can confirm the pushed commit. A local commit alone is not a push.

Use descriptive messages such as `feat: initialize PrivacyShield architecture`, `feat: implement PostgreSQL schema discovery`, and `feat: integrate PII scanning engine`. Stage intended project files only. Never force-push, overwrite unrelated work, or merge into `main` without explicit approval.

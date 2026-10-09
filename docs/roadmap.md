# Delivery roadmap

Each phase is gated on relevant tests, a reviewed commit, a successful push to `dev/privacyshield`, and remote-SHA confirmation. Phases 1 and 2 are **complete**, including real services, browser review, remote commit verification, and passing GitHub Actions. Phase 3 is in progress; Phases 4–7 have not started. See the phase verification records for evidence and limitations.

## Three-day submission target

The target submission date is **12 October 2026**. Deliverables are the repository's working source code and reproducible demonstration; a separate report and slide deck are not required. The compressed sequence below is an estimate, not a promise that an unverified feature will be delivered by its target day. Preserve the seven test-and-push gates even when multiple phases fit into a day.

| Work day | Target work |
| --- | --- |
| Day 1 | Foundation, connection/discovery, and bounded scanning |
| Day 2 | Local AI classification, masking compiler, approval, and deployment |
| Day 3 | Security/recovery checks, complete browser demonstration, setup/runbook documentation, and fixes |

## Phase gates

| Phase | Deliverables | Acceptance gate | Status |
| --- | --- | --- | --- |
| 1 — Foundation | Monorepo, Compose, normalized models/migrations, authentication/RBAC, dashboard shell, synthetic target, CI | Clean startup; migration; login/logout/CSRF; protected endpoints; frontend tests/build; separate real Celery worker smoke | Complete — `4f1efd2`, CI passed |
| 2 — Discovery | Encrypted connection management; least-privilege provisioning; catalog discovery; Schema Explorer | Discover tables, PK/FK and composite relationships; reject scanner writes; redact credentials | Complete — `c0c0100`, CI passed |
| 3 — Scanning | Presidio and Indian candidate recognizers; bounded JSONB/text sampling; async jobs; results | Real async scan detects synthetic scalar/JSONB/text fixtures; enforce sampling/timeouts; no retained raw samples | Local gate passed; push/CI pending |
| 4 — Classification | Ollama adapter; structured response validation; classifications UI/evaluation | Real `qwen2.5:1.5b` smoke; reject malformed/unknown fields and injection attempts; manual review during outages | Not started |
| 5 — Masking and Approval | Compiler, previews, immutable policy versions, approval, deployment/reconciliation | Reader sees approved views only; unchanged source data; idempotent deployment; schema drift blocks deployment | Not started |
| 6 — Security and Audit | Permissions matrix; audit timeline; operator settings/custom patterns; redaction; concurrency/recovery | Audit immutability; bounded custom-pattern configuration; stale/concurrent decisions; inherited privilege checks; interruption and uncertain-outcome recovery | Not started |
| 7 — Readiness | Browser workflow tests; measured benchmarks; observability; deployment/demo docs | Clean-install full workflow; published measured limitations and repeatable commands | Not started |

## Phase 1 acceptance evidence

- Passed: locked dependency installation, backend Ruff, 13 unit tests, and 18 real integration tests.
- Passed: PostgreSQL migration/model agreement, constraints, runtime grants, sessions, CSRF, and real Redis/Celery delivery.
- Passed: real scanner/reader logins against the synthetic target, including denied scanner writes after disabling the read-only default.
- Passed: frontend type checking, 9 component tests using mocked HTTP, production build, and npm audit with zero reported vulnerabilities at verification time.
- Passed: Compose startup, successful migration exit, and actual HTTP proxy/readiness/login/dashboard/CSRF/logout checks.
- Passed: real browser interaction review, staged-file review, [commit `4f1efd2`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/commit/4f1efd225888f90178540db75d4fbb2439fea90a), matching remote branch SHA, and [GitHub Actions run `37965293246`](https://github.com/Taarunkarthik/PRIVACY-SHIELD/actions/runs/37965293246).

If a required service is unavailable, record that gate as blocked. Do not substitute mocked tests or proceed into the next phase as though acceptance succeeded.

The [Phase 2 verification record](verification-phase2.md) records 29 backend unit, 29 real integration, 18 frontend, and 2 real browser tests passed, plus final Docker builds, HTTP checks, the registration demo, and API-replacement proxy recovery. Commit `c0c0100` was pushed and its remote SHA verified; GitHub Actions run `37968356823` passed.

## Per-phase delivery report

Every phase report must identify the actual commit hash and branch, summarize changed files and features, distinguish mocked tests from real-service checks, report failures or blocked checks, and include the GitHub commit URL. Only a remote-ref check can confirm the pushed commit. A local commit alone is not a push.

Use descriptive messages such as `feat: initialize PrivacyShield architecture`, `feat: implement PostgreSQL schema discovery`, and `feat: integrate PII scanning engine`. Stage intended project files only. Never force-push, overwrite unrelated work, or merge into `main` without explicit approval.

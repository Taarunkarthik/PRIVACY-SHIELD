# Phase 3 verification record

Phase 3 passed the complete local gate. Commit, push, remote-SHA verification, and matching CI remain pending.

## Confirmed checks

| Check | Result | Evidence and limits |
| --- | --- | --- |
| Full native backend unit suite | 64 passed | Includes 31 actual Presidio/spaCy fixture tests; 38 integration tests require a separate service run after the final review additions |
| Actual Presidio fixtures | 31 passed | Bundled model identity, blocked-network cold start, scalar/text email, Indian phone, person, PAN/Aadhaar candidates, IBAN/card, metadata hints, benign input, bounds, injection-like input, no raw output/logs |
| Backend Ruff and dependency lock | Passed | Python 3.12 package compatibility and locked dependencies checked |
| Scan migration | Passed on isolated test database | `0002_scan_recovery` adds bounded attempt state and connection fingerprint |
| Stale worker attempt regression | Passed on real PostgreSQL | An earlier attempt cannot update a newer attempt's progress, results, failure, or audit; a released advisory lease is invalid |
| Frontend type checking and component/hook tests | 27 passed | Mocked HTTP tests cover roles, sample bounds, saved snapshots, CSRF, coverage, failed/incomplete scans, and polling lifecycle |
| Final backend and frontend builds/startup | Passed | Pinned model loaded in Linux; final source and UI built, migration exited successfully, services healthy |
| Full Linux backend unit suite | **64 passed** | Actual detector fixtures included; no mocked model replaces them |
| Full real integration suite | **38 passed in 47.85 seconds** | Separate test database and Linux worker/queue, API-submitted scans, source role boundaries, RLS, bounded cells/JSON, PII keys, drift, duplicate delivery, recovery and stale attempts |
| Migration/model agreement | Passed | Both application and isolated test database upgraded; Alembic detected no model drift |
| Actual scan demo | Passed | API-submitted 100-row-per-table scan completed in 49.0 seconds while other checks ran; 24 aggregate records, seven categories, scalar/JSONB/free-text and PAN/Aadhaar candidates; no raw fixture samples returned |
| Full real browser suite | **3 passed in 55.0 seconds** | Authentication/navigation, discovery, and real worker scanning; desktop/mobile screenshots reviewed without clipping or raw values |
| Worker and target-role probes | Passed | Separate worker processed tasks; scanner reads but cannot write; reader cannot access sources/keys or assume view-owner role |
| Staged-file review | Passed | 113 indexed files checked for forbidden paths, local secrets, and secret patterns; 41 Phase 3 files changed |

## Pending acceptance

- Commit, push, matching remote SHA, and matching GitHub Actions result.

The first Linux dependency build experienced slow package downloads and retries. Direct HTTPS probes succeeded. The final Dockerfile limits concurrent downloads and uses a persistent BuildKit package cache; both final images built successfully. Native tests were followed by the actual Linux integration gate.

The observed demo timing is not a general throughput claim. Sampling and detector limitations are documented in [scanning.md](scanning.md). Operator-configurable custom patterns are scheduled with settings in Phase 6; the current scanner includes the fixed reviewed recognizers described there.

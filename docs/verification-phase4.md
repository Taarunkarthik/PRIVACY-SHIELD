# Phase 4 verification record

Phase 4 passed local acceptance, including real model inference, complete service checks and browser workflows. Commit, push, remote-SHA verification and matching GitHub Actions remain the delivery gate.

| Check | Result | Evidence and limits |
| --- | --- | --- |
| Backend unit suite | 125 passed in final Linux run (6.68 seconds) | Includes 61 adapter tests with controlled HTTP responses; real model checked separately |
| Ruff and lock consistency | Passed | Strict models, malformed URLs, response limits, JSON ambiguity, enum/identity/approval validation |
| Frontend type checking, tests and build | 35 tests passed | 103.95-second mocked-HTTP component suite; production build 54.91 seconds |
| Final Docker builds and startup | Passed | API/worker/frontend rebuilt; successful migration and healthy services |
| Classification migration | Passed on application and isolated test databases | `0003_classification_jobs`; existing classifications retained; Alembic found no model drift |
| Actual HTTP auth and reverse proxy | Passed | Readiness, security headers, login, dashboard, CSRF rejection and logout |
| Full Linux integration suite | 49 tests passed in 37.18 seconds | Real PostgreSQL/Redis/Linux worker with isolated controlled HTTP model double; 11 classification cases cover roles/CSRF, selection/lineage, valid/partial/malformed/outage results, duplicate delivery and stale-attempt recovery |
| Worker and target permissions | Passed | Separate main worker smoke; scanner cannot write/read keys; reader cannot read source/keys or assume owner role |
| Actual Ollama adapter smoke | Passed with final v3 prompt in 46.71 seconds | Real `qwen2.5:1.5b` model ID `65ec06548149`, 100% CPU, 3 GiB container limit. 855 prompt tokens and 110 generated tokens; 4,096 context; same email/protective-action/approval acceptance checks |
| Actual API classification demo | Passed in 28.5 seconds | Job `b860df38-0681-402c-b385-634f239ec789` classified the real synthetic scan's customer email finding through API → Redis → separate worker → local model → PostgreSQL; accepted protective recommendation requires human approval |
| Full real browser suite | 4 tests passed in 1.1 minutes | Authentication, real AI classification (39.8 seconds), discovery, real scanning; recommendation survives reload; desktop/mobile screenshots reviewed without overflow |
| Staged review | Passed | 43 intended project files changed; complete tracked-file secret check passed |
| GitHub delivery | Pending | Successful push, matching remote SHA and CI required |

The classification worker uses one metadata-only column per model call and preserves independently accepted results. A job may report partial failure without erasing deterministic scan evidence. See [the classification contract and limits](classification.md).

The first actual model run exposed a semantic error: valid JSON identified an email category but recommended `KEEP`. That run failed acceptance. The strengthened prompt explains candidate evidence explicitly, and both the output grammar and independent validation reject `NONE` or `KEEP` when detector counts are nonzero. No unsafe recommendation was deployed. New regression tests cover that contradiction; structural JSON validity alone is insufficient evidence of useful classification. The final v3 prompt removes redundant schema text while retaining the full constrained response schema and independent validation. It reduced the observed first-request time from 83.81 to 46.71 seconds; full-table AI throughput has not been measured.

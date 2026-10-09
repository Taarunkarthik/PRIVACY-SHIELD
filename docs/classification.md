# Local advisory classification

Phase 4 adds a local Ollama adapter, durable classification jobs, and the AI Classification page. All 61 adapter fault-injection tests passed. Local acceptance also passed with the real model: direct inference, an API/worker job (28.5 seconds), and the four-test browser suite including actual classification. See [verification evidence](verification-phase4.md) for results and delivery status. Mocked output is not evidence of model accuracy.

## Enable the local model

Start the base application and initialize an administrator as described in the [README setup instructions](../README.md). Docker Desktop must be running. From the repository root:

```powershell
docker compose up -d --build
docker compose --profile ai up -d ollama
docker compose --profile ai run --rm ollama-pull
docker compose --profile ai exec ollama list
docker compose exec -T api python -c "from app.services.classification.adapter import smoke_test; print(smoke_test())"
```

The one-shot pull service downloads `qwen2.5:1.5b` into the persistent `ollama-data` volume. Its first download requires network access; classification uses the local service afterward. Ollama's port remains internal to Docker. The Compose service allows one loaded model and one inference at a time, with a 3 GiB memory limit and two CPUs. Existing Docker data and the model volume use Docker Desktop's configured disk location on D:.

The smoke helper sends a fabricated email-column description and aggregate counts, with no actual email address or source records. Success prints an `ok` summary, model name, prompt version, category, and the required-approval flag. It must classify the fixture as `EMAIL_ADDRESS` and recommend an action other than `KEEP`; connection success alone does not pass this test.

On 10 October 2026, the actual local `qwen2.5:1.5b` model (digest prefix `65ec06548149`) passed this smoke test with prompt v3 in 46.71 seconds after a prompt/context change. Ollama reported 855 prompt tokens, 110 output tokens, 30.76 seconds of prompt evaluation, and 12.21 seconds of generation. This is one fabricated fixture on the local CPU setup, not an accuracy benchmark or a latency guarantee for a multi-column job.

To exercise authentication, the API, Redis delivery, a separate worker, persisted results, and the real model together:

```powershell
python scripts/register_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
python scripts/classify_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
```

Use an existing administrator and a locally protected password file; there is no committed default password. The script scans ten synthetic rows per table, selects the customer email finding, requests classification, and checks its accepted recommendation. To reuse a completed synthetic scan, append `--scan-id <scan-uuid>`. The script prints job identifiers, status, and timing, never the password or source samples.

## Workflow and API

An administrator or analyst submits `POST /api/v1/scans/{scan_id}/classify`. The scan must be complete. The optional body is `{"result_ids": ["<result-uuid>"]}` with one to fifty unique result IDs belonging to that scan. An omitted selection chooses the first fifty whole-column results in schema/table/column order, including results with zero detector matches. JSON paths can be selected explicitly. Auditors can review jobs and recommendations but cannot request classification.

The API returns `202` with a durable job identifier. `GET /api/v1/classification-jobs`, `GET /api/v1/classification-jobs/{job_id}`, and `GET /api/v1/classifications` expose progress and accepted decisions. List endpoints use `page` and `page_size` with a maximum page size of 100. The UI shows original scan findings separately, so model outages do not hide detection evidence.

Classification states are `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`, and `FAILED`. Each accepted decision is independently validated and committed with its audit event. `PARTIAL` means some selected results have accepted recommendations and others still require manual review. `FAILED` means none were accepted. Neither state means the source data is safe. Responses that fail validation produce no fabricated replacement recommendation.

## Metadata-only adapter contract

`classify_columns(columns, base_url=..., model=...)` accepts at most eight column descriptions and returns typed decisions in input order. The worker currently calls it with one column per request to keep CPU latency and identity binding predictable. Its allowlisted input contains only:

- Result UUID and exact schema, table, column, and sanitized JSON path.
- PostgreSQL data type, primary/foreign-key flags, and nullability.
- Sampled and matching row counts, category counts, and detector score.
- Coverage limits and counts for skipped, truncated, and unsupported values.

Input models reject extra fields, including sample values and credentials. SQL comments, raw records, original sensitive JSON keys, connection passwords, and credentials are never sent. Names and other metadata can themselves be misleading or contain instruction-like text; the prompt marks all such strings as untrusted data. The model has no tools and cannot execute SQL, approve a policy, or deploy a change.

The `/api/chat` request uses `stream: false`, temperature zero, a fixed seed, CPU inference, and two inference threads. Single-column inputs of at most 2 KiB use a 4,096-token context; larger inputs and batches use 8,192 tokens. Output generation is capped at 512 tokens per input column, at most 4,096 tokens. The prompt version is `privacyshield-classify-v3`. The prompt gives compact field/category/action guidance while the separate `format` parameter retains the full constrained JSON schema.

| Boundary | Enforced limit |
| --- | --- |
| Serialized input metadata | 16,000 UTF-8 bytes |
| Input batch | 1–8 columns; production worker uses 1 |
| Name / data type / JSON path | 63 / 256 / 1,024 characters respectively |
| Model HTTP response | 65,536 bytes; compressed responses rejected |
| HTTP connect / write / pool timeout | 5 / 10 / 5 seconds |
| HTTP read timeout | 120 seconds, with a deadline checked while reading chunks |
| Recommendation reason | 1–500 characters; prompt requests under 100 |
| Confidence | Finite numeric value in 0–1; strings and booleans rejected |
| Classification job | 1–50 selected results; worker soft/hard limits 900/960 seconds |

HTTP proxy inheritance and redirects are disabled. No raw model response, source value, or transport exception is returned in an adapter error. The 120-second read setting limits socket inactivity, not a guaranteed whole-job completion time. Large selections can take several minutes; unfinished items are reported explicitly when execution times out.

The response schema fixes each result's exact UUID and schema/table/column/path identity. Independent Pydantic validation then checks the complete response, required fields, enum allowlists, duplicate/missing results, finite scores, and `requires_human_approval: true`. A result with nonzero detected candidate counts cannot receive category `NONE` or recommendation `KEEP`; contradictory responses are rejected, not replaced with fabricated decisions. Partial JSON, Markdown fences, trailing text, duplicate JSON keys, tool calls, unknown fields, changed identifiers, and unknown actions are rejected even if the model server ignores its output schema. The public API exposes the approval flag as `requires_approval: true`.

Allowed categories are the nine detector categories plus `NONE`, `PERSONAL_IDENTIFIER`, `SENSITIVE_TEXT`, `DATE_OF_BIRTH`, and `CUSTOM_SENSITIVE`. Risk is `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Recommendations are `KEEP`, `REDACT`, `PARTIAL`, `PSEUDONYMIZE`, `NULLIFY`, or `RESTRICT`. These labels are suggestions for a future explicit policy decision, not executable SQL.

## Durable records and recovery

`classification_jobs` records the selected scan, requester, model/prompt provenance, status, bounded attempts, and result counts. `classification_job_items` records the selected results and each item's pending/completed/failed outcome. Composite foreign keys require job items to belong to the same scan as their job. `pii_classifications` retains accepted category/risk/recommendation/score/reason with a unique job/result pair, bounded reason, and a database constraint requiring approval.

The API commits a queued job before attempting broker publication. Periodic dispatch retries interrupted queued/running jobs. Advisory locks, lock-session checks, row locks, and attempt-number checks prevent an older worker attempt from overwriting a newer one. Accepted items survive interruption; a recovered worker resumes pending items. Three execution attempts exhaust automatic recovery. A changed prompt version prevents an old job from silently mixing prompt contracts.

Errors use fixed codes. `OLLAMA_UNAVAILABLE`, `OLLAMA_TIMEOUT`, `OLLAMA_HTTP_ERROR`, and `AI_MODEL_MISMATCH` stop further requests for that job. `AI_INVALID_RESPONSE`, `AI_RESPONSE_TOO_LARGE`, `AI_INPUT_INVALID`, and `AI_INPUT_TOO_LARGE` identify rejected evidence or output. Original scan results remain available for manual review; after resolving the problem, request a new classification job.

## Interpretation and verification

The 1.5B model is a small advisory classifier. The fixtures use English metadata; accuracy across other languages and industry-specific schemas has not been measured. It can miss sensitive fields, misread abbreviations, and confidently recommend an unsuitable action. Its numeric score and the detector's numeric score are heuristic signals, not calibrated probabilities. PAN and Aadhaar labels denote candidates, never verified identities. Zero sampled matches or a `NONE` recommendation cannot certify the absence of PII.

Strict schema validation limits output structure and available actions. It cannot prove that a permitted category or recommendation is correct, nor make all prompt injection ineffective. Review the discovered schema, detector counts, coverage limitations, key relationships, and model rationale before selecting protection. A policy still needs a separate explicit approval and deployment workflow.

Run the adapter fixtures and full service checks separately:

```powershell
Set-Location backend
uv run pytest tests/test_classification_adapter.py -q
Set-Location ..
python scripts/check.py --integration
```

Adapter fixtures inject malformed JSON, identity changes, unsupported actions, approval bypasses, metadata instructions, oversized bodies, timeouts, and unavailable servers. The integration runner uses real PostgreSQL, Redis, and a separate Linux worker with a controlled HTTP Ollama double for deterministic orchestration, partial-result, and failure checks. That double is not the real model and is never enabled in the application stack. The separate smoke helper and `classify_demo.py` must pass against actual local Ollama before the Phase 4 gate is complete.

Primary references: [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs), [chat API](https://docs.ollama.com/api/chat), [generation parameters](https://docs.ollama.com/modelfile), and [HTTPX timeout semantics](https://www.python-httpx.org/advanced/timeouts/).

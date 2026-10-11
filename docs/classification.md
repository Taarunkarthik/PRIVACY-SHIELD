# Local advisory classification

Phase 4 adds a local Ollama adapter, durable classification jobs, and the AI Classification page. All 61 adapter fault-injection tests passed. Local acceptance also passed with the real model: direct inference, an API/worker job (28.5 seconds), and the four-test browser suite including actual classification. See [verification evidence](verification-phase4.md) for results and delivery status. Mocked output is not evidence of model accuracy.

> **Not yet run against the real model: prompt v4 and value shapes.** The last real-model result recorded in this document is for prompt **v3** (10 October 2026, below). Prompt v4 adds [value shapes](#value-shapes) to the model's input and one paragraph to its instructions. Both were developed where no Ollama model was available, so they are covered by unit tests and by the controlled HTTP double only. Whether `qwen2.5:1.5b` reads shapes correctly, whether the extra text changes its answers on other columns, and how much time it adds per column are unknown until the [checks below](#check-prompt-v4-on-a-machine-with-ollama) are run.

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

The smoke helper sends a fabricated email-column description, aggregate counts and, since prompt v4, two fabricated value shapes, with no actual email address or source records. Success prints an `ok` summary, model name, prompt version, category, and the required-approval flag. It must classify the fixture as `EMAIL_ADDRESS` and recommend an action other than `KEEP`; connection success alone does not pass this test.

On 10 October 2026, the actual local `qwen2.5:1.5b` model (digest prefix `65ec06548149`) passed this smoke test with prompt v3 in 46.71 seconds after a prompt/context change. Ollama reported 855 prompt tokens, 110 output tokens, 30.76 seconds of prompt evaluation, and 12.21 seconds of generation. This is one fabricated fixture on the local CPU setup, not an accuracy benchmark or a latency guarantee for a multi-column job. No later prompt version has a recorded real-model result.

To exercise authentication, the API, Redis delivery, a separate worker, persisted results, and the real model together:

```powershell
python scripts/register_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
python scripts/classify_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
```

Use an existing administrator and a locally protected password file; there is no committed default password. The script scans ten synthetic rows per table, selects the customer email finding, requests classification, and checks its accepted recommendation. To reuse a completed synthetic scan, append `--scan-id <scan-uuid>`. The script prints job identifiers, status, and timing, never the password or source samples.

### Check prompt v4 on a machine with Ollama

Rebuild first so the API and worker run the current code, then run the same smoke test and demo as above:

```powershell
docker compose up -d --build
docker compose --profile ai up -d ollama
docker compose --profile ai run --rm ollama-pull
docker compose exec -T api python -c "from app.services.classification.adapter import smoke_test; print(smoke_test())"
python scripts/register_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
python scripts/classify_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
```

`smoke_test()` now sends the same fabricated email column with two fabricated shapes and the full v4 instructions. It passes on the same condition as before: category `EMAIL_ADDRESS` and an action other than `KEEP`. `classify_demo.py` scans, selects the customer email finding explicitly, and so sends that column's stored shapes through the worker. Two further one-line checks separate the cases:

```powershell
docker compose exec -T api python -c "from app.services.classification.adapter import smoke_test; print(smoke_test(shapes=False))"
docker compose exec -T api python -c "from app.services.classification.adapter import shapes_smoke_test; print(shapes_smoke_test())"
```

The first sends, byte for byte, the request that passed under v3, so a failure there is not caused by shapes. The second describes a fabricated column the detectors missed (`contact_ref`, no matches) whose values all have a phone-like form. It prints `status: ok` when the model proposes protection and `status: review` when it answers `NONE` or `KEEP`, which means the shapes did not help on that fixture. Neither is an accuracy measurement.

If v4 behaves worse than v3, set `AI_SEND_SHAPES=false` in `.env` and run `docker compose up -d` again (no rebuild). The worker then sends exactly the v3 request for every column, and stored shapes are left unused. Jobs are still labelled `privacyshield-classify-v4`.

## Workflow and API

An administrator or analyst submits `POST /api/v1/scans/{scan_id}/classify`. The scan must be complete. The optional body is `{"result_ids": ["<result-uuid>"]}` with one to fifty unique result IDs belonging to that scan. An omitted selection chooses the first fifty **uncertain** whole-column results in schema/table/column order: the columns the detectors did not settle, including results with zero detector matches. Columns the detectors decided are no longer selected automatically; see [the rule](#columns-the-detectors-already-decided). Any result, decided or not, and any JSON path can still be selected explicitly. Auditors can review jobs and recommendations but cannot request classification.

When no selection is given and no whole column is uncertain, the request fails with `409` and the detail `NOTHING_UNCERTAIN`. No job is created. The page explains it as "the detectors already decided every scanned column, so nothing needs the model".

`GET /api/v1/scans/{scan_id}/classification-summary` reports the counts behind the default selection for a completed scan, to any signed-in user: `whole_columns`, `decided`, `uncertain`, `not_classifiable`, `selection_limit` (50) and `will_classify` (the smaller of `uncertain` and the limit). The page shows these where a classification is started, for example "8 columns were already decided by the detectors and will be skipped. 15 columns will be sent to the model." It answers `409` for a scan that has not completed and `404` for an unknown scan.

The API returns `202` with a durable job identifier. `GET /api/v1/classification-jobs`, `GET /api/v1/classification-jobs/{job_id}`, and `GET /api/v1/classifications` expose progress and accepted decisions. List endpoints use `page` and `page_size` with a maximum page size of 100. The UI shows original scan findings separately, so model outages do not hide detection evidence.

Classification states are `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`, and `FAILED`. Each accepted decision is independently validated and committed with its audit event. `PARTIAL` means some selected results have accepted recommendations and others still require manual review. `FAILED` means none were accepted. Neither state means the source data is safe. Responses that fail validation produce no fabricated replacement recommendation.

## Columns the detectors already decided

The model takes 30 to 45 seconds per column on CPU. Asking it about a column where nearly every sampled row matched a detector adds waiting and little information: the category is already known, and the response schema forbids `NONE` and `KEEP` when there are matches. One function, `detector_verdict` in `backend/app/services/classification/triage.py`, sorts each whole-column scan result into one of three groups.

| Group | Rule |
| --- | --- |
| Not classifiable | The column was not read: unsupported type, no row sampled, no non-null value reached the detector (`values_read` is 0), or no coverage was recorded. |
| Decided | All three hold: every sampled value was read in full (`values_skipped`, `values_truncated`, `json_truncated` and `path_limit_reached` are all 0); at least 80% of the sampled rows matched; and the detector confidence is at least 0.6. |
| Uncertain | Everything else that was scanned: no match, a partial match, a low score, or values not read in full. |

The 0.6 threshold excludes a column matched by a column-name hint alone (0.45), so `full_name` in the bundled demo is uncertain even though every row matched. The 80% is of sampled rows, not of non-null values, so a sparsely filled column stays uncertain. A scan stored before `values_read` existed is judged on its coverage and row counts.

"Decided" means the detectors' evidence is strong enough that the model adds little. It does not mean the detected category is right. The [accuracy benchmark](detection-accuracy.md) lists ten-digit tracking numbers that match the phone detector on every row; such a column is decided, and a reviewer still has to reject it. To get the model's view of a decided column, select it explicitly.

On the bundled demo database (four tables, 100 rows each, 23 whole columns) the detectors decide 8 columns and leave 15 uncertain, with none unreadable. Of those 15, one has detector matches (`customers.full_name`, matched by its name hint) and 14 have none.

What a decided column no longer gets by default is the model's risk level and recommended action. [Policy suggestions](masking.md) are unaffected: they already take the mask from detector evidence for every column with a match and use a classification only for a column with none. The dashboard's risk breakdown lets a classification raise a column's level, and reports how many sensitive columns had one; after a default job that number now covers only uncertain columns with matches. Select a decided column explicitly to have the model weigh it.

## Metadata-only adapter contract

`classify_columns(columns, base_url=..., model=...)` accepts at most eight column descriptions and returns typed decisions in input order. The worker currently calls it with one column per request to keep CPU latency and identity binding predictable. Its allowlisted input contains only:

- Result UUID and exact schema, table, column, and sanitized JSON path.
- PostgreSQL data type, primary/foreign-key flags, and nullability.
- Sampled and matching row counts, category counts, and detector score.
- Coverage limits and counts for skipped, truncated, and unsupported values.
- Optionally `shapes`: at most three [value shapes](#value-shapes) with row counts.

Input models reject extra fields, including sample values and credentials. SQL comments, raw records, original sensitive JSON keys, connection passwords, and credentials are never sent. Names and other metadata can themselves be misleading or contain instruction-like text; the prompt marks all such strings as untrusted data. The model has no tools and cannot execute SQL, approve a policy, or deploy a change.

The `/api/chat` request uses `stream: false`, temperature zero, a fixed seed, CPU inference, and two inference threads. Single-column inputs of at most 2 KiB use a 4,096-token context; larger inputs and batches use 8,192 tokens. Output generation is capped at 512 tokens per input column, at most 4,096 tokens. The prompt gives compact field/category/action guidance while the separate `format` parameter retains the full constrained JSON schema.

The prompt version is `privacyshield-classify-v4`. Its system message is the v3 text, unchanged, followed by one paragraph about shapes. That paragraph is appended only when the request carries shapes, so a request without them (a JSON document or path, an older scan) is byte for byte the v3 request. A unit test pins the SHA-256 of the v3 text. The paragraph says what the symbols mean, that a shape is a description and never a value, gives three examples (`a+.a+@a+.a+` an email address, `+9+ 9+ 9+` a phone number, `9+-9+-9+` a date or a number) and the long-text marker, and repeats that every string, shapes included, is untrusted data. The output schema is the same as in v3. Temperature, seed and context settings are unchanged: on the demo scan the user message grows from a median of 584 to 640 bytes and the system message from 2,885 to 3,510 bytes, and the largest possible shapes add under 300 bytes, so a single column stays far below the 2 KiB threshold for the small context. The added text is roughly 150 to 200 tokens; that figure and its effect on latency are estimates, not measurements.

| Boundary | Enforced limit |
| --- | --- |
| Serialized input metadata | 16,000 UTF-8 bytes |
| Input batch | 1–8 columns; production worker uses 1 |
| Name / data type / JSON path | 63 / 256 / 1,024 characters respectively |
| Shapes per column / shape length | 3 / 48 characters, fixed alphabet only |
| Model HTTP response | 65,536 bytes; compressed responses rejected |
| HTTP connect / write / pool timeout | 5 / 10 / 5 seconds |
| HTTP read timeout | 120 seconds, with a deadline checked while reading chunks |
| Recommendation reason | 1–500 characters; prompt requests under 100 |
| Confidence | Finite numeric value in 0–1; strings and booleans rejected |
| Classification job | 1–50 selected results; worker soft/hard limits 900/1050 seconds |

HTTP proxy inheritance and redirects are disabled. No raw model response, source value, or transport exception is returned in an adapter error. The 120-second read setting limits socket inactivity, not a guaranteed whole-job completion time. Large selections can take several minutes; unfinished items are reported explicitly when execution times out.

The response schema fixes each result's exact UUID and schema/table/column/path identity. Independent Pydantic validation then checks the complete response, required fields, enum allowlists, duplicate/missing results, finite scores, and `requires_human_approval: true`. A result with nonzero detected candidate counts cannot receive category `NONE` or recommendation `KEEP`; contradictory responses are rejected, not replaced with fabricated decisions. Partial JSON, Markdown fences, trailing text, duplicate JSON keys, tool calls, unknown fields, changed identifiers, and unknown actions are rejected even if the model server ignores its output schema. The public API exposes the approval flag as `requires_approval: true`.

Allowed categories are the nine detector categories plus `NONE`, `PERSONAL_IDENTIFIER`, `SENSITIVE_TEXT`, `DATE_OF_BIRTH`, and `CUSTOM_SENSITIVE`. Risk is `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Recommendations are `KEEP`, `REDACT`, `PARTIAL`, `PSEUDONYMIZE`, `NULLIFY`, or `RESTRICT`. These labels are suggestions for a future explicit policy decision, not executable SQL.

## Value shapes

Until v4 the model saw a column's name, type, key flags and detector counts. For a column the detectors missed, that is a name and a type. A **shape** gives it something to reason on without giving it any value: the form of a sampled value, with every letter and digit replaced by the symbol of its class.

| In the value | In the shape |
| --- | --- |
| A lowercase letter, or a letter of a script without case (Devanagari, Arabic, CJK and others) | `a` |
| An uppercase or titlecase letter | `A` |
| A digit or other numeric character, in any script | `9` |
| `@ . - _ + ( ) / : ,` and the plain space | kept as they are |
| Anything else: other punctuation, quotes, backslashes, symbols, emoji, control characters, tabs and line breaks | `?` |
| A combining mark directly after a letter | nothing; it belongs to that letter |

A `+` or `-` at the very start or end of a value is a sign rather than part of its form, and is written `?`. A run of two or more of the same symbol is then written as the symbol followed by `+`. So `priya.sharma42@example.com` becomes `a+.a+9+@a+.a+`, `+91 98765 43210` becomes `?9+ 9+ 9+`, `ABCPK1234F` becomes `A+9+A`, `2026-10-11` becomes `9+-9+-9+`, and `1 Example Street, Demo City` becomes `9 Aa+ Aa+, Aa+ Aa+`. Classification is by Unicode category, so `प्रिया शर्मा` becomes `a+ a+`. The whole alphabet is the fifteen characters `aA9+?@.-_()/:, ` including the space.

Bounds:

- A value longer than 256 characters is not analysed. It is recorded as the fixed marker `a+ a+ a+ ...`, meaning long text.
- A shape longer than 48 characters is cut to 45 and ends in `...`. Three dots cannot occur in a computed shape, because a run of dots is written `.+`, so the ending is unambiguous.
- At most the three most common shapes per column are stored, each with the number of sampled rows that had it, most frequent first, ties in a fixed order. A shape that fewer than five sampled values have is not stored.
- While sampling, a column's counter holds at most 64 distinct shapes. Those are counted exactly. A shape first seen after 64 others is not counted. Rows are read in random order, so a shape present in one value in ten is missed with a probability of about 0.1%. A free-text column, where almost every value has its own shape, usually yields none, because no single shape reaches five rows.

Shapes are computed during the scan from the values already being read, for character columns only (`text`, `varchar`, `char`, `citext`), and stored in `sanitized_evidence.shapes` as a list of `{"shape", "rows"}`. The key is optional everywhere. It is absent for numbers, dates, booleans and UUIDs (the type already says their form, and a shape would add only sign and magnitude), for JSON documents and JSON paths, for types that are not read, and for scans stored before shapes existed. A JSON document has no single form, and its text would spell out keys that can themselves be personal data, so no shape is computed for it. The list is empty when a column had no value with a form to keep.

### What a shape hides, and what it shows

No letter or digit of a value is in its shape. Every class except the kept punctuation has many members, so a symbol does not say which character stood there, and collapsing runs removes lengths beyond "one" and "more than one". Two values with the same sequence of classes have the same shape. A shape can therefore look like a value only when the value is itself spelled with the symbols, as in `aA9`, and it is then indistinguishable from the shape of `xQ4`.

A kept punctuation mark is a class of one, so it does appear in the shape as itself. That is deliberate: the marks are the signal that separates an email address from a date. Three rules keep that from turning a shape back into a value, and one consequence remains.

- A sign at either end of a value is written `?`. `O+` and `O-` share the shape `A?`, and `-12.50` and `+12.50` share `?9+.9+`, so a shape does not say which sign a value had.
- A shape is stored only when at least five sampled values have it, so a stored shape never describes one person's value. A column where every value has its own form stores none.
- A value made only of kept punctuation and spaces would have itself as its shape. Such content is usually a placeholder like `-`, but it can also carry meaning, for example text written in dots and dashes. **These values are dropped**: no shape is stored for them and they are not counted. The same applies to the empty string, and to a value whose shape holds punctuation only once it is cut to 48 characters.
- For every other value the layout of its kept punctuation is visible in the shape, with runs reduced to one or many. A value that is mostly punctuation with a few letters keeps that layout. This is accepted as part of what a shape is.

Shape counts are aggregate statistics, like category counts, and they are visible to every signed-in role in the scan results. In a column whose values differ only in form, the counts are that column's distribution: a `Yes`/`No` text column stores `Aa+` and `Aa` with their row counts, which says how many of each there were (though not which rows). If that distribution is itself sensitive, leave value shapes out of AI requests with `AI_SEND_SHAPES=false`; the counts are then stored but not sent to the model.

The property is tested, not only argued, in `backend/tests/test_shapes.py`. About 6,000 generated values mix lowercase, uppercase and caseless letters and digits from several scripts, emoji, control characters, quotes, backslashes, combining marks and very long strings, plus the empty string. For every one, each character of the shape is in the fixed alphabet, the shape is at most 48 characters, no letter or digit of the value appears in it, and no pair of adjacent input characters containing a letter or digit appears in it. Those values avoid the characters `a`, `A` and `9`, so that any letter or digit found in a shape is a leak. Values that do contain them are covered by a second test, which replaces every letter and digit by another of its class and requires the shape to stay the same. A third requires punctuation-only values to be dropped. A fourth runs the same check against five deliberately leaky versions of the function (keeping digits, caseless letters, quotes, Cyrillic capitals or control characters) and requires each leak to be caught. A sampling test and an integration test on a real scan assert that no stored shape contains a fragment of the synthetic values. Two further tests cover the sign rule (3,000 generated values, each tried with both signs at both ends, must give one shape) and the five-row minimum.

### Shapes at the adapter

`shapes` is validated like every other input field, before any request is made: at most three entries, no duplicates, each a `shape` of 1 to 48 characters that the shape function could have produced and a `rows` count of at least 1, with the counts summing to no more than the sampled rows. Shapes are accepted only for a whole column of a readable type, not for a JSON path. A string that is not a shape, such as an instruction or an email address, cannot pass: the alphabet has no letters other than `a` and `A`. The column is then rejected with `AI_INPUT_INVALID` and nothing is sent. The prompt still tells the model to treat shapes as untrusted data.

## Durable records and recovery

`classification_jobs` records the selected scan, requester, model/prompt provenance, status, bounded attempts, and result counts. `classification_job_items` records the selected results and each item's pending/completed/failed outcome. Composite foreign keys require job items to belong to the same scan as their job. `pii_classifications` retains accepted category/risk/recommendation/score/reason with a unique job/result pair, bounded reason, and a database constraint requiring approval.

The API commits a queued job before attempting broker publication. Periodic dispatch retries interrupted queued/running jobs. Advisory locks, lock-session checks, row locks, and attempt-number checks prevent an older worker attempt from overwriting a newer one. Accepted items survive interruption; a recovered worker resumes pending items. Three execution attempts exhaust automatic recovery. A changed prompt version prevents an old job from silently mixing prompt contracts: a job queued under v3 and picked up by a v4 worker fails with `PROMPT_VERSION_CHANGED`. The `prompt_version` columns hold 32 characters; `privacyshield-classify-v4` is 25, so no migration is needed.

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

Adapter fixtures inject malformed JSON, identity changes, unsupported actions, approval bypasses, metadata instructions, hostile or malformed shapes, oversized bodies, timeouts, and unavailable servers. `tests/test_shapes.py` and `tests/test_classification_triage.py` cover the shape function and the decided/uncertain rule. The integration runner uses real PostgreSQL, Redis, and a separate Linux worker with a controlled HTTP Ollama double for deterministic orchestration, partial-result, and failure checks; it also scans the synthetic target and checks the stored shapes, the counts endpoint, the default selection and the `NOTHING_UNCERTAIN` error. That double is not the real model and is never enabled in the application stack. The separate smoke helper and `classify_demo.py` must pass against actual local Ollama before the Phase 4 gate is complete, and they have not yet been run for prompt v4.

Primary references: [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs), [chat API](https://docs.ollama.com/api/chat), [generation parameters](https://docs.ollama.com/modelfile), and [HTTPX timeout semantics](https://www.python-httpx.org/advanced/timeouts/).

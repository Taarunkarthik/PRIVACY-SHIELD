# Bounded PII scanning

Phase 3 passed local acceptance using actual Presidio, PostgreSQL, Redis, a separate Linux worker, and the browser. See [verification evidence](verification-phase3.md) for results and GitHub delivery status.

## Workflow and API

An administrator or analyst first discovers an authorized connection, then submits its saved snapshot to `POST /api/v1/scans` with `connection_id`, `snapshot_id`, and `sample_limit`. The default is 1,000 rows per table; the API rejects limits outside 1–10,000. A `202` response contains a durable scan ID. An auditor can view history and results but cannot initiate scans.

`GET /api/v1/scans`, `GET /api/v1/scans/{id}`, and `GET /api/v1/scans/{id}/results` expose status, progress, sanitized error codes, and aggregate findings. List endpoints use `page` and `page_size` (maximum 100). PostgreSQL holds authoritative status; Redis messages carry job identifiers, never connection credentials or source values.

The reproducible demo uses the actual HTTP API and background worker:

```powershell
python scripts/register_demo.py --password-file .secrets/admin-password.txt
python scripts/scan_demo.py --password-file .secrets/admin-password.txt
```

Use an existing administrator's locally protected password file. The scripts do not create a default account or display its password. The scan demo uses 100 rows per table and checks scalar, JSONB, free-text, PAN-candidate, and Aadhaar-candidate findings without printing sample data.

## What findings mean

Presidio runs locally with a pinned spaCy `en_core_web_sm` model bundled into the backend image. No NLP model is downloaded while handling a scan. The supported categories are email address, phone number, person, location, credit card, IBAN, PAN candidate, Aadhaar candidate, and bank-account candidate. Candidate matches are indications for review, not verification of an identity or account.

Results are bounded samples. A zero match count does not prove that a column or database contains no PII. The small English model can miss Indian names, addresses, and non-English content; structured patterns can produce false positives. Bank-account candidates use column context. A twelve-digit number that passes the Aadhaar (Verhoeff) checksum is reported wherever it appears; one that fails the checksum is reported only with Aadhaar context. A PAN-shaped value is reported on its own when its fourth letter is a valid holder type, and otherwise only with PAN context. Neither check verifies an identity: about one random twelve-digit number in ten passes the checksum. Measured precision and recall, with every known false positive, are in [detection accuracy](detection-accuracy.md). Phone recognition is configured for India and the US; email validation uses a bundled suffix list without network access, which may omit newer domains.

Each category count is the number of sampled rows with that category. A row can match more than one category, so adding category counts may exceed the number of matching rows. Confidence is a detector score, not a calibrated probability: English NER uses a 0.65 heuristic and field hints use 0.45. Even a pattern score of 1.0 does not verify an identity. JSON path results and the whole JSON column may describe the same row; do not add them as independent affected rows.

## Data handling and coverage

The worker uses read-only PostgreSQL transactions, safely quoted identifiers, statement timeouts, explicit column projections, and streaming batches. Rows are sampled at random across the whole table: they are ordered by a hash of their physical location seeded from the scan ID, and the first `sample_limit` are read. The sample is uniform, holds `sample_limit` rows when that many are visible to the scanner, and does not depend on planner statistics. A retry of the same scan reads the same rows, and a new scan reads different ones. Rows are chosen in an inner query and only the chosen rows are converted to text, so large values in rows that are not sampled are never read. A table whose heap, including partitions, exceeds 32 MB first has a random share of its pages selected with `TABLESAMPLE SYSTEM`, so the cost stays bounded; that sample is spread across the table but clustered within the chosen pages. If those pages hold too few visible rows, as on a bloated table or one where row-level security hides most rows, every row is considered instead, up to a heap size of 256 MB; beyond that the shorter sample is kept so the scan stays inside its statement timeout. Each result also records how many non-null values the detector actually received. Earlier versions read the first rows in primary-key order, which never saw a column populated only in newer rows. Existing source row-level security applies to the scanner role.

Scalar input is limited to 4,096 characters (at most 16 KiB of UTF-8). JSONB cells larger than 16 KiB are skipped. Traversal is bounded to depth 6, 256 visited nodes, 64 leaves, and 32 stored whole-column/path entries per JSON column. Coverage fields disclose truncation, skipped values, unsupported types, and path limits. Treat affected columns as only partially assessed.

Only category labels, counts, confidence, coverage statistics, and value shapes are persisted. Source samples exist transiently during detection. A small allowlist preserves structural JSON keys such as `contact` and `email`; other keys become keyed opaque path tokens because JSON keys can themselves contain personal data. Array indices collapse to `[*]`. Unknown keys can still be checked for PII without retaining their original text.

For each character column (`text`, `varchar`, `char`, `citext`) the scan also stores, in `sanitized_evidence.shapes`, up to three of the most common **value shapes** with their row counts. A shape is the form of a value with every letter and digit replaced by its class (`a`, `A`, `9`), a few punctuation marks kept, everything else written `?`, and runs collapsed: `customer12@example.com` is stored as `a+9+@a+.a+`. It holds no letter or digit of the value; the kept punctuation marks appear as themselves, except a `+` or `-` at either end, which is written `?`. A shape is stored only when at least five sampled values have it. Shapes are computed from the rows already sampled, add no query, and are not computed for numbers, dates, JSON documents or unread types; values made only of punctuation are left out, and results from earlier scans simply lack the key. The definition, bounds, and the tests behind the privacy claim are in [value shapes](classification.md#value-shapes).

## Worker operation

Compose runs one Linux Celery worker with an embedded periodic scheduler. Production and integration-test workers use separate queues and separate control-plane databases. Test cleanup stops only the named temporary test worker.

The API commits a queued job before attempting Redis publication. The periodic dispatcher revisits eligible queued/interrupted jobs every 15 seconds, with a 30-second dispatch throttle. Execution uses a PostgreSQL advisory lock, a checked lock session, and an attempt number that prevents an older attempt from overwriting a newer attempt. Three interrupted execution attempts exhaust automatic recovery. Completion writes all aggregates and the completion audit event atomically; failed jobs expose no partial results. A scan is limited to 20,000 aggregate result entries.

The integration check is:

```powershell
python scripts/check.py --integration
```

Presidio fixtures are real detector tests. End-to-end scan acceptance requires an API-submitted job consumed by the separate worker; eager or mocked Celery execution is insufficient. The phase gate additionally checks schema/configuration drift, permissions, sample limits, redaction, duplicate delivery, and durable recovery behavior.

Implementation references: [spaCy model installation](https://spacy.io/usage/models), [English model capabilities](https://spacy.io/models/en), [Presidio spaCy integration](https://presidio.dataprivacystack.org/analyzer/nlp_engines/spacy_stanza/), and [Celery task delivery behavior](https://docs.celeryq.dev/en/stable/userguide/tasks.html).

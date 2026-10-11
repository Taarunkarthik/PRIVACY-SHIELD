# Masking policies, approval, and deployment

Phase 5 turns advisory recommendations into human-approved, deterministic
protection. A policy is an immutable, per-column decision set for one table. An
administrator approves a specific version, then separately deploys it. Deployment
creates a PostgreSQL security-barrier view owned by a restricted role; the
restricted reader sees only the approved projection, and source rows are never
modified.

## Protection actions

Every exposed column receives exactly one action. Columns without a rule become
typed `NULL` (no value is exposed) rather than being dropped, so consumers keep a
stable column list.

| Action | Compiled SQL | Notes |
| --- | --- | --- |
| `KEEP` | `"col" AS "col"` | Pass-through, original type preserved |
| `REDACT` | `CASE WHEN "col" IS NULL THEN NULL ELSE '[REDACTED]' END` | Text output; `NULL` preserved |
| `PARTIAL` | `CASE WHEN "col" IS NULL THEN NULL ELSE '***' \|\| right("col"::text, 4) END` | Text output; last four characters retained |
| `MASK_EMAIL` | `left(v,1) \|\| '***' \|\| '@' \|\| <host>` when `v` is exactly one address, else `'***'` | `c***@example.com`; the part after `@` must be a dotted host name |
| `MASK_PHONE` | every digit but the last four replaced by `*`, punctuation kept; else `'***'` | `+** ***** *0001`; needs 8+ digits and no letters |
| `MASK_ID` | every letter and digit but the last four replaced by `*`, separators kept; else `'***'` | `**** **** 0001`, `******001F`; for PAN, Aadhaar, card and account numbers |
| `PSEUDONYMIZE` | `encode(extensions.hmac(convert_to("col"::text,'UTF8'), key, 'sha256'),'hex')` | Deterministic, keyed, text output |
| `NULLIFY` | `NULL::<type>` | Typed `NULL`; type preserved |
| `RESTRICT` | `NULL::<type>` | No value exposed |

The three format-aware masks fail closed. A value that does not have the shape
the mask expects (free text in an email column, a phone field holding a name) is
replaced entirely with `***`, so a wrongly chosen mask hides data instead of
leaking part of it. `NULL` stays `NULL`.

For `MASK_EMAIL` the shape is strict: a local part of at most 64 characters, one
`@`, then a host name of dot-separated labels (letters, digits, hyphens) ending
in letters, such as `mail.example.org`. The host is shown in full, so without
that rule anything following the `@` would be shown too: `a@b.com;9876543210`, a
JSON string containing an address, or `x@2345-6789-0124`. Those are replaced
entirely. What each mask deliberately reveals is the first character
and the host of an email, and the last four characters of a phone or ID number.
`MASK_ID` applied to a sentence that contains a digit keeps the sentence's word
lengths and its last four characters, so use `REDACT` for free text.

`PSEUDONYMIZE` reads its key from `privacyshield_private.pseudonym_keys` by
domain. Equal values with the same domain produce equal pseudonyms; unrelated
domains do not. If the domain key is missing, the output is `NULL` (fail closed).
Pseudonym and partial outputs are **text**, as recorded in the design; they are
not cast back to the source type.

## Compiled plan

`compile_plan` is a pure function: it reads only the saved catalog and the
policy's own rules, never source rows. The output is one
`CREATE OR REPLACE VIEW ... WITH (security_barrier = true)` statement. The view
name is derived deterministically from the schema and table (`<table>_<digest>`,
bounded to 63 bytes), so a newer policy version replaces the same view.

The plan fingerprint is a SHA-256 over the source identity, view identity, and
ordered column decisions. It is stored at approval time and re-derived at
deployment time; a mismatch blocks the deployment as schema or content drift.

Identifier and data-type inputs are validated before interpolation. Pseudonym
domains must match `^[a-z0-9_]{1,60}$`; column and view names must be simple
identifiers. This prevents identifier or literal injection through policy input.

## Suggested rules

`GET /api/v1/policies/suggestions` proposes a rule per column for a table, from
the latest completed scan of its connection:

- A column with detector findings gets the mask for its most frequent category:
  `MASK_EMAIL`, `MASK_PHONE`, `MASK_ID`, or `REDACT` for names and addresses. A
  JSONB column gets `NULLIFY` and a free-text column gets `REDACT`, because a
  format mask cannot handle either.
- A column the detectors did not flag, but which has an advisory AI
  classification, gets the mask for that classification.
- A scanned column with no findings gets `KEEP`, the one suggestion that
  exposes data, and only when every sampled value was read in full. A column
  with any skipped, truncated or path-limited value, a type the scanner cannot
  read, or no scan at all gets no suggestion and stays `NULL` unless a person
  chooses otherwise.

Each suggestion carries its evidence: source, category, and matching rows out of
sampled rows. The policy editor shows that beside the column and applies the
suggestions only when asked, and only to columns that have no rule yet. A
suggestion creates nothing; a person still creates, submits, approves and
deploys the policy.

"Nothing found" describes the sampled rows. A column that was empty in every
sampled row also reports nothing found, so review a `KEEP` suggestion as a
suggestion.

## Preview with example values

`GET /api/v1/policies/{id}/preview/samples` shows what a policy does before it is
deployed. It fabricates three example values per column from the column's type,
name and action, then runs the policy's compiled expressions over them on the
target server:

```sql
SELECT "email"::text AS before_1, (<compiled expression>)::text AS after_1, ...
FROM (VALUES ($1::bigint, $2::text, ...)) AS src("id", "email", ...)
```

The only relation in the query is the `VALUES` list, so no source row is read,
and for every action but one the output is what the deployed view will produce
for those inputs, because it is the same expression.

The exception is `PSEUDONYMIZE`. A real pseudonym is an HMAC under a secret key
held in the target database. Returning real tokens for known example inputs
would let anyone with preview access match them against masked output, so the
preview shows an unkeyed SHA-256 digest of the same shape instead and the editor
says so. The preview therefore reads no key and needs no role beyond the
deployer's own login.

The response is marked `source: FABRICATED`. If the target is unreachable or no
deployer is configured, the status is `UNAVAILABLE` and the compiled preview
still works. If an example cannot be cast to a column's type (a value too wide
for `numeric(3,2)`), the preview falls back to examples for text columns only.

## Lifecycle

```text
DRAFT ──submit──▶ PENDING_APPROVAL ──approve──▶ APPROVED ──deploy──▶ DEPLOYED
                          │                                    ▲
                          └──reject──▶ REJECTED               │
                                              APPROVED ──fail──▶ FAILED ──retry──▶ (APPROVED)
```

- Submitted content is immutable. Any change to the rules or source schema
  creates a new version; a rejected policy is not edited in place.
- Approval writes the approval row and the plan fingerprint in the same
  control-plane transaction as the status change, under a row lock. Concurrent
  approvals cannot double-decide.
- A failed deployment may return to `APPROVED` only for unchanged content: the
  retry re-derives the plan and requires the same fingerprint.
- Only `ADMIN` may approve, reject, or deploy. `ANALYST` may create and submit.
  `AUDITOR` is read-only.

## Deployment

Deployment is asynchronous and durable. The API returns `202` with a durable
deployment identifier; a separate Linux Celery worker performs the target work.

1. The worker holds a per-deployment advisory lock (duplicate deliveries exit).
2. It re-derives the plan and verifies the fingerprint against the approval.
3. It opens a dedicated target transaction as the **deployer** role, then
   `SET LOCAL ROLE ps_view_owner` so created objects are owned by the restricted
   view owner.
4. Idempotency: if `privacyshield_private.deployment_receipts` already holds a
   receipt for this deployment with the same plan hash, the migration is skipped
   and the deployment is completed (this is the reconciliation path after a lost
   response). A differing hash is a conflict.
5. Otherwise the view statement is executed and a receipt row is inserted in the
   same transaction. View creation and receipt commit atomically. If a newer
   version changes a column's output type (a kept `numeric` column that is now
   redacted to text), `CREATE OR REPLACE VIEW` refuses; the view is then dropped
   and recreated inside the same transaction, so readers never see it missing.
6. Before committing, the worker verifies the result: the reader role must be
   able to read the masked view and must have no table or column privilege on
   the source table. If either check fails, the transaction rolls back and the
   deployment fails with `ACCESS_VERIFICATION_FAILED`. A successful receipt
   records `access_verified: true`.
7. On success the control-plane policy moves to `DEPLOYED`; on failure it moves
   to `FAILED` with a bounded error code and can be retried.

The "one active attempt per policy" partial unique index, plus the advisory lock
and receipt check, make duplicate and interrupted deployments safe.

## Protected output

`GET /api/v1/policies/{id}/protected-output` is the evidence that a deployed
policy works. For the version deployed last on its table, through any connection
to that database, it returns up to five rows read through the masked view, and
two facts read from the catalog:
whether the reader role can read the view, and whether it can read the source
table.

It returns only what the approved policy already exposes to the reader role, so a
`KEEP` column appears unmasked there exactly as the reader would see it. It is
limited to administrators, and each call writes a `PROTECTED_OUTPUT_VIEWED`
audit event. A superseded or undeployed version returns `409`.

## Security properties

- Views are `security_barrier` and owned by `ps_view_owner`; the reader role has
  `SELECT` only and cannot read base tables or the private schema.
- Deployer credential material is decrypted in-process only and never logged,
  returned, or placed in task payloads.
- Source data is read only during scanning; deployment performs DDL and never
  writes or migrates source rows.

## Limitations

- Deployment onto tables with row-level security enabled is deferred: view-owner
  privilege rules for RLS require separate handling.
- Pseudonymized values depend on target-side keys. If a domain key is absent the
  value becomes `NULL`; operators must provision keys before relying on
  pseudonyms.
- Whole-column protection for sensitive JSONB and free text currently uses
  nullification; path-level JSONB projection is future work.
- Recreating a view for a type change keeps only the reader role's grant. A
  privilege an operator granted on the old view by hand is not carried over, and
  the recreation is refused if another database object depends on the view.
- The policy editor pre-fills the pseudonym key domain with `demo`, the key the
  bundled target provisions. Another target needs its own domain entered.
- "The version deployed last on a table" is worked out from connection records
  with the same host, port and database name. Two records that name one server
  differently (a host name and its IP address) are treated as separate targets.
- Access verification covers the reader role's privileges on the view and its
  source table. It does not look for other routes to the data, such as a
  different view over the same table.

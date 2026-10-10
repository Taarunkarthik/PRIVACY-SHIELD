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
| `PSEUDONYMIZE` | `encode(extensions.hmac(convert_to("col"::text,'UTF8'), key, 'sha256'),'hex')` | Deterministic, keyed, text output |
| `NULLIFY` | `NULL::<type>` | Typed `NULL`; type preserved |
| `RESTRICT` | `NULL::<type>` | No value exposed |

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
   same transaction. View creation and receipt commit atomically.
6. On success the control-plane policy moves to `DEPLOYED`; on failure it moves
   to `FAILED` with a bounded error code and can be retried.

The "one active attempt per policy" partial unique index, plus the advisory lock
and receipt check, make duplicate and interrupted deployments safe.

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

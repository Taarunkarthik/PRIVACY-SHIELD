# Audit chain

The audit log (`audit_events`) is append-only for the runtime role `ps_app`: it can insert and read, and cannot update, delete or truncate. That is a permission boundary. The table owner or a superuser can still change history, and before the chain nothing would show it.

The audit chain makes such a change visible. Every audit event is *sealed* into a hash chain kept in a second table, and *verification* recomputes the chain from the stored events.

Read [Limits](#limits) before relying on it. The chain detects edits to sealed history. It does not, on its own, detect removal of the newest entries or a chain that a privileged role rebuilt after an edit. Those need the [head anchor](#the-head-anchor).

## What it detects

| Change made by a privileged role | Result |
| --- | --- |
| Any protected field of a sealed event is changed | `BROKEN`, `HASH_MISMATCH` at that event's position |
| A chain row's `row_hash` is changed | `BROKEN`, `HASH_MISMATCH` at that row |
| A chain row's `prev_hash` is changed | `BROKEN`, `LINK_MISMATCH` at that row |
| An event is changed and only its own `row_hash` is recomputed | `BROKEN`, `LINK_MISMATCH` at the next row |
| A chain row is removed from the middle | `BROKEN`, `INDEX_GAP` at the missing position |
| A sealed event is removed while its chain row remains | `BROKEN`, `MISSING_EVENT` at that row |

The protected fields are `id`, `actor_id`, `event_type`, `subject_type`, `subject_id`, `correlation_id`, `details` and `created_at`.

## Data model

Table `audit_chain` (migration `0006_audit_chain`, model `AuditChain`):

| Column | Meaning |
| --- | --- |
| `chain_index` | Position in the chain. Primary key, starts at 1, dense. Assigned by the sealer, not by a sequence. |
| `event_id` | The sealed event. Unique, foreign key to `audit_events.id`. |
| `prev_hash` | `row_hash` of the previous row; 64 zeros for position 1. |
| `row_hash` | 64 lowercase hex characters, defined below. |
| `sealed_at` | When the row was appended. Informational, not hashed. |

`ps_app` has `SELECT` and `INSERT` on `audit_chain`. `UPDATE`, `DELETE` and `TRUNCATE` are revoked, the same boundary as `audit_events`. The primary key and the unique `event_id` mean the database itself rejects two rows at one position or two rows for one event.

Because of the foreign key, PostgreSQL refuses to delete a sealed event while its chain row exists. `MISSING_EVENT` therefore appears only if that constraint was bypassed.

## The hash

```text
row_hash = hex( sha256( prev_hash || canonical_bytes(event) ) )
```

`prev_hash` is its 64 ASCII characters. `canonical_bytes` is one JSON object, encoded as UTF-8:

- keys sorted, `,` and `:` as the only separators, no other whitespace;
- non-ASCII characters written as UTF-8, not as `\u` escapes;
- UUIDs as lowercase hyphenated text, or `null`;
- `created_at` in UTC as `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always six fractional digits;
- `details` with its own keys sorted, and its numbers written exactly as PostgreSQL stores them, never through a floating-point conversion.

For ordinary values this equals Python's `json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

Example. This event:

```json
{"actor_id":null,"correlation_id":"99999999-8888-7777-6666-555555555555","created_at":"2026-10-01T09:00:00.000000Z","details":{},"event_type":"LOGIN_SUCCEEDED","id":"11111111-2222-3333-4444-555555555555","subject_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","subject_type":"session"}
```

sealed at position 1 (`prev_hash` is 64 zeros) has `row_hash`
`daf3364da4351b357b16060c5960ac7b63d67d3b342bb8ff2f335f8c7dd63351`. A unit test pins these bytes and this hash, because changing the format would invalidate every stored chain.

`created_at` and `details` are rendered by PostgreSQL (`to_char` in UTC, and `details::text`) and then normalised, so a value Python cannot represent, such as an infinite timestamp or JSON nested deeper than Python's reader allows, is still hashed and can never make sealing or verification fail. If `details` cannot be parsed it is hashed as PostgreSQL's own text under the key `details_raw`.

## Sealing

`seal_audit_chain()` in `backend/app/services/audit_chain.py`. It takes no arguments and can be called from any process.

The insert path of `audit_events` is untouched: no trigger, no lock. Request transactions write audit rows exactly as before. Sealing is a separate step:

1. Take a PostgreSQL advisory transaction lock with a fixed key. Only sealers take it, so a sealer only ever waits for another sealer, and only for one short batch.
2. Read the head of the chain (highest `chain_index` and its `row_hash`).
3. Select up to 500 committed events that have no chain row, ordered by `created_at`, then `id`.
4. Append one chain row per event, continuing the index and the hash from the head.
5. Commit, which releases the lock. Repeat until a batch comes back short, or 20,000 events were sealed in this call.

Why no event is skipped, sealed twice, or given a gap:

- **Density.** The next index is the committed head plus one, computed while the lock is held. If the transaction rolls back, nothing was consumed. A sequence would leave a gap.
- **No fork.** PostgreSQL makes a commit visible before it releases that transaction's locks, and under `READ COMMITTED` each statement takes a new snapshot. The head read runs after the lock is granted, so it always sees the previous sealer's rows. The sealer sets `READ COMMITTED` explicitly for this reason.
- **No skip.** Events are selected by "has no chain row", not by a timestamp watermark. An event whose transaction is still open is invisible and is not marked as handled in any way. Once it commits, the next pass finds it, even if events with later timestamps were sealed in between. It gets a later index: chain order is sealing order, not timestamp order.
- **No double seal.** An event with a chain row is never selected again, and `event_id` is unique.

Events that already existed when the chain was introduced are sealed by the first passes, in the same order. The chain attests to them as they were found then, not to anything that happened to them earlier.

### When it runs

- A Celery beat task, `privacyshield.seal_audit_chain`, every 15 seconds, next to the existing dispatch tasks.
- At the start of every verification.
- Any other job runner can call `seal_audit_chain()` directly.

## Verification

`verify_audit_chain()` first seals pending events, then reads the chain in `chain_index` order in batches inside one `REPEATABLE READ` transaction, so the counts, the head and every batch describe the same moment. For each row it checks, in this order:

| Reason | Check that failed |
| --- | --- |
| `INDEX_GAP` | The row's `chain_index` is not the next expected position. Reported at the first missing position. |
| `LINK_MISMATCH` | The row's `prev_hash` is not the previous row's `row_hash` (64 zeros for position 1). |
| `MISSING_EVENT` | The event the row refers to does not exist. |
| `HASH_MISMATCH` | `sha256(prev_hash || canonical_bytes(event))` is not the row's `row_hash`. |

It stops at the first failure. Rows before that position verified; rows from it onward were not checked and should not be relied on.

Result fields:

| Field | Meaning |
| --- | --- |
| `status` | `INTACT` or `BROKEN` |
| `sealed` | Number of chain rows |
| `pending` | Events with no chain row yet. Not covered by the check. |
| `head_index`, `head_hash` | The last chain row: the head anchor. `0` and `null` for an empty chain. |
| `broken_index`, `reason` | First failing position and its reason code; `null` when intact |
| `anchor_status` | Only when an anchor was supplied: `MATCH`, `MISMATCH` or `NOT_FOUND` |
| `verified_at` | When the check ran |

A `BROKEN` result is also written to the application log with the position and reason. If sealing fails at the start of a verification, the check still runs on what is stored and the unsealed events show as `pending`.

## API

`GET /api/v1/audit-events/verify`: `ADMIN` and `AUDITOR` only. Anonymous callers get `401`, analysts `403`.

```json
{
  "status": "INTACT",
  "sealed": 1222,
  "pending": 0,
  "head_index": 1222,
  "head_hash": "9df800e54ab7bd0e38072530cea98ef5a90e1d350b25724dc7b54c0f349fc043",
  "broken_index": null,
  "reason": null,
  "anchor_status": null,
  "verified_at": "2026-10-11T07:09:26.969309Z"
}
```

Optional query parameters `anchor_index` and `anchor_hash` (both or neither) check a saved anchor; see below.

Verification is deliberately **not** recorded as an audit event. Recording it would append to the log being measured: two checks of an idle log would report different heads, and a monitor that polls the endpoint would fill the log with its own checks. A broken result is logged by the application instead.

## Dashboard

The Audit Logs page has a **Log integrity** panel for administrators and auditors. **Verify log integrity** runs the check on request and shows intact or broken, the sealed and not-yet-sealed counts, and the head position with a shortened hash and a button that copies the full hash. A broken chain shows the position and a plain-language reason.

## The head anchor

`head_index` and `head_hash` summarise the whole chain up to that position. Copy both somewhere the database administrator cannot change: a ticket, a signed email, another system.

To check a saved anchor later:

```text
GET /api/v1/audit-events/verify?anchor_index=1222&anchor_hash=9df800e5...
```

- `MATCH`: position 1222 still holds that hash. Together with `INTACT`, every event up to the anchor is as it was when the anchor was taken.
- `MISMATCH`: that position now holds a different hash. The chain was rebuilt.
- `NOT_FOUND`: that position no longer exists. The end of the chain was removed.

The dashboard shows and copies the head but has no field for checking a saved one; use the API parameters above.

## Limits

1. **Removing the newest rows of both tables together is not detectable from inside the database.** What remains is a shorter chain that verifies. Only a saved anchor shows it (`NOT_FOUND`, or `MISMATCH` once new events are sealed at those positions).
2. **A privileged role can rebuild the chain.** SHA-256 is unkeyed. Whoever can update `audit_chain` can change an event and recompute its hash and every later one, and verification then reports `INTACT`. An integration test does exactly this and shows that only the saved anchor disagrees. Dropping and recreating the chain (for example a migration downgrade followed by an upgrade) has the same effect: every event is sealed again as it is now. Closing this inside the system would need a keyed hash whose key the database administrator does not hold, or anchors published automatically to an external store. Neither is implemented.
3. **Unsealed events are not protected.** Between an event's commit and the next sealing pass (normally at most about 15 seconds while the worker runs, longer if it is stopped) the event is covered by table permissions only. `pending` reports how many there are.
4. **The chain says nothing about who wrote an event.** `ps_app` can insert audit events and chain rows, so a compromised application can add entries. It cannot change or remove existing ones.
5. **Cost grows with the log.** Finding unsealed events and verifying both read the whole log. Measured on a development container with 200,000 events: a sealing pass with nothing to seal took about 0.13 s, verification about 9 s, and sealing a 200,000-event backlog for the first time about 90 to 130 s spread over several passes. Extrapolating linearly from those figures (not measured): each statement must finish within the runtime connection's 10 s statement timeout, which the scan for unsealed events would reach somewhere above ten million events; and verification is one HTTP request, so the bundled proxy's 65 s read timeout would be reached first, at a little over a million events. A log of that size needs a watermark for the scan and a background verification job; neither is implemented.

## Tests

- `backend/tests/test_audit_chain.py`: the canonical format (pinned), every reason code on in-memory chains, route order and role checks without a database.
- `backend/tests/integration/test_audit_chain.py`, on real PostgreSQL: sealing of events written through the application, tampering with events and with chain rows by the schema owner, the rebuilt-chain limit and the anchor, the runtime role's inability to update, delete or truncate, concurrent sealers, sealing during concurrent inserts, an event committed late, and the endpoint's role checks. Tests that break the chain restore it and confirm `INTACT` before returning.
- `frontend/tests/AuditLogs.test.tsx`: intact, broken (every reason), request failure, clipboard fallback, and no verification offered to analysts.

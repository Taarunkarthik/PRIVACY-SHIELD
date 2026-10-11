"""Tamper-evident hash chain over ``audit_events``.

Audit rows are written inside request transactions and are never locked or
serialised here. A separate step, *sealing*, appends one ``audit_chain`` row per
event: ``row_hash = sha256(prev_hash || canonical_bytes(event))``. Verification
recomputes every hash from the stored events.

What this detects: any change to a sealed event, any change to a chain row, and
a chain row or sealed event removed from the middle.

What it cannot detect from inside the database (see ``docs/audit-chain.md``):

* Removing the newest rows of both tables together. What is left is a shorter,
  internally consistent chain.
* A privileged role that changes an event and then recomputes every later
  ``row_hash``. SHA-256 is unkeyed, so anyone who can rewrite ``audit_chain``
  can rebuild it.
* Events that are not sealed yet. Until the next sealing pass they are covered
  by table permissions only.

The defence against the first two is the head anchor (``head_index`` and
``head_hash``) kept somewhere outside the database: after either change the
hash stored at that index is different or gone, which ``verify_audit_chain``
reports when it is given the saved anchor.
"""

import hashlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import Text, cast, exists, func, insert, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import get_engine
from app.models import AuditChain, AuditEvent

logger = logging.getLogger("privacyshield")

GENESIS_HASH = "0" * 64
SEAL_BATCH_SIZE = 500
# Upper bound for one call, so a periodic run or a request never loops unbounded.
SEAL_MAX_EVENTS = 20_000
VERIFY_BATCH_SIZE = 1000

# One fixed key: every sealer in every process takes the same transaction lock.
SEAL_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"privacyshield:audit-chain:seal").digest()[:8], "big", signed=True
)

INTACT = "INTACT"
BROKEN = "BROKEN"
HASH_MISMATCH = "HASH_MISMATCH"
LINK_MISMATCH = "LINK_MISMATCH"
INDEX_GAP = "INDEX_GAP"
MISSING_EVENT = "MISSING_EVENT"

ANCHOR_MATCH = "MATCH"
ANCHOR_MISMATCH = "MISMATCH"
ANCHOR_NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True)
class EventRecord:
    """The hashed fields of one audit event, as PostgreSQL returns them.

    ``details_json`` and ``created_at_utc`` are rendered by the database
    (``details::text`` and a fixed UTC ``to_char`` format), so hashing never
    depends on a driver's number or timestamp conversion and cannot fail on a
    value Python cannot represent.
    """

    id: UUID
    actor_id: UUID | None
    event_type: str
    subject_type: str
    subject_id: UUID | None
    correlation_id: UUID
    details_json: str | None
    created_at_utc: str | None


@dataclass(frozen=True)
class ChainLink:
    chain_index: int
    prev_hash: str
    row_hash: str
    event: EventRecord | None


@dataclass(frozen=True)
class ChainBreak:
    chain_index: int
    reason: str


@dataclass(frozen=True)
class ChainVerification:
    status: str
    sealed: int
    pending: int
    head_index: int
    head_hash: str | None
    broken_index: int | None
    reason: str | None
    anchor_status: str | None
    verified_at: datetime


# to_char yields NULL for the two infinite timestamps; their text form keeps them distinct.
_CREATED_AT_UTC = func.coalesce(
    func.to_char(func.timezone("UTC", AuditEvent.created_at), 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    cast(AuditEvent.created_at, Text),
)
EVENT_FIELDS = (
    AuditEvent.id,
    AuditEvent.actor_id,
    AuditEvent.event_type,
    AuditEvent.subject_type,
    AuditEvent.subject_id,
    AuditEvent.correlation_id,
    cast(AuditEvent.details, Text).label("details_json"),
    _CREATED_AT_UTC.label("created_at_utc"),
)
_UNSEALED = ~exists().where(AuditChain.event_id == AuditEvent.id)


def _canonical_json(value: Any) -> str:
    """Sorted keys, no insignificant whitespace, numbers written exactly as stored."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, Decimal):
        # Positional notation with the stored scale; never an exponent or a float.
        return format(value, "f")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + _canonical_json(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    raise TypeError("Unsupported value in canonical audit JSON")


def _optional(value: UUID | None) -> str | None:
    return None if value is None else str(value)


_COMPACT: dict[str, Any] = {"sort_keys": True, "separators": (",", ":"), "ensure_ascii": False}


def _canonical_details(details_json: str | None) -> tuple[str, str]:
    """Member name and canonical text for the event's details."""
    if details_json == "{}":
        # What record_event always writes; nothing to parse.
        return "details", "{}"
    try:
        value = (
            None
            if details_json is None
            else json.loads(details_json, parse_int=Decimal, parse_float=Decimal)
        )
        return "details", _canonical_json(value)
    except (ValueError, TypeError, RecursionError, ArithmeticError):
        # A value Python cannot parse (for example nesting deeper than its JSON
        # reader allows) is hashed as the database's own text under a different
        # name, so sealing and verification never fail on it.
        return "details_raw", json.dumps(details_json, ensure_ascii=False)


def canonical_bytes(event: EventRecord) -> bytes:
    """Stable UTF-8 serialisation of exactly the fields the chain protects.

    One JSON object with sorted keys, ``,`` and ``:`` as the only separators and
    non-ASCII characters written as UTF-8, equal to ``json.dumps(document,
    sort_keys=True, separators=(",", ":"), ensure_ascii=False)`` except that
    numbers inside ``details`` are written exactly as PostgreSQL stores them.
    """
    name, details = _canonical_details(event.details_json)
    before = json.dumps(
        {
            "actor_id": _optional(event.actor_id),
            "correlation_id": str(event.correlation_id),
            "created_at": event.created_at_utc,
        },
        **_COMPACT,
    )
    after = json.dumps(
        {
            "event_type": event.event_type,
            "id": str(event.id),
            "subject_id": _optional(event.subject_id),
            "subject_type": event.subject_type,
        },
        **_COMPACT,
    )
    # "details" sorts after "created_at" and before "event_type".
    return f'{before[:-1]},"{name}":{details},{after[1:]}'.encode("utf-8", "surrogatepass")


def compute_row_hash(prev_hash: str, event: EventRecord) -> str:
    return hashlib.sha256(prev_hash.encode("utf-8") + canonical_bytes(event)).hexdigest()


class ChainWalker:
    """Checks chain rows one at a time in ``chain_index`` order."""

    def __init__(self) -> None:
        self.expected_index = 1
        self.expected_prev_hash = GENESIS_HASH

    def check(self, link: ChainLink) -> ChainBreak | None:
        if link.chain_index != self.expected_index:
            # Reported at the first position that should exist and does not.
            return ChainBreak(self.expected_index, INDEX_GAP)
        if link.prev_hash != self.expected_prev_hash:
            return ChainBreak(link.chain_index, LINK_MISMATCH)
        if link.event is None:
            return ChainBreak(link.chain_index, MISSING_EVENT)
        if compute_row_hash(link.prev_hash, link.event) != link.row_hash:
            return ChainBreak(link.chain_index, HASH_MISMATCH)
        self.expected_index += 1
        self.expected_prev_hash = link.row_hash
        return None


def first_break(links: Iterable[ChainLink]) -> ChainBreak | None:
    walker = ChainWalker()
    for link in links:
        found = walker.check(link)
        if found is not None:
            return found
    return None


def _connect(isolation_level: str) -> Connection:
    return get_engine().connect().execution_options(isolation_level=isolation_level)


def _seal_batch(connection: Connection, limit: int) -> int:
    # Only sealers take this lock, so a sealer only ever waits for another sealer.
    # It is held until this transaction ends. PostgreSQL makes a commit visible
    # to new snapshots before it releases the committer's locks, and under READ
    # COMMITTED each statement below takes its snapshot after the lock was
    # granted. The head read therefore always sees the previous sealer's rows.
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SEAL_LOCK_KEY})
    head = connection.execute(
        select(AuditChain.chain_index, AuditChain.row_hash)
        .order_by(AuditChain.chain_index.desc())
        .limit(1)
    ).first()
    index, prev_hash = (head.chain_index, head.row_hash) if head else (0, GENESIS_HASH)
    # "Has no chain row" rather than a timestamp watermark: an event whose
    # transaction commits after later events were sealed is still found by the
    # next pass, and an event that already has a chain row is never taken again.
    events = connection.execute(
        select(*EVENT_FIELDS)
        .where(_UNSEALED)
        .order_by(AuditEvent.created_at, AuditEvent.id)
        .limit(limit)
    ).all()
    rows = []
    for event in events:
        # Dense by construction: the next index is derived from the committed
        # head while the lock is held. A rollback leaves no gap, unlike a sequence.
        index += 1
        row_hash = compute_row_hash(prev_hash, EventRecord(*event))
        rows.append(
            {
                "chain_index": index,
                "event_id": event.id,
                "prev_hash": prev_hash,
                "row_hash": row_hash,
            }
        )
        prev_hash = row_hash
    if rows:
        connection.execute(insert(AuditChain), rows)
    return len(rows)


def seal_audit_chain(
    *, batch_size: int = SEAL_BATCH_SIZE, max_events: int = SEAL_MAX_EVENTS
) -> int:
    """Append a chain row for every committed audit event that has none.

    Safe to call from any process at any time and with no arguments. Each batch
    is its own short transaction, so the lock is never held across batches.
    Returns the number of events sealed by this call. A database error
    (``SQLAlchemyError``) propagates after the current batch rolls back; batches
    already committed stay sealed and the rest is picked up by the next call.
    """
    if batch_size < 1 or max_events < 1:
        raise ValueError("batch_size and max_events must be positive")
    sealed = 0
    while sealed < max_events:
        limit = min(batch_size, max_events - sealed)
        # Explicit, because the snapshot-after-lock argument above needs it.
        with _connect("READ COMMITTED") as connection, connection.begin():
            count = _seal_batch(connection, limit)
        sealed += count
        if count < limit:
            break
    return sealed


def _verify(
    connection: Connection, batch_size: int, anchor: tuple[int, str] | None
) -> ChainVerification:
    sealed = connection.scalar(select(func.count()).select_from(AuditChain)) or 0
    pending = (
        connection.scalar(select(func.count()).select_from(AuditEvent).where(_UNSEALED)) or 0
    )
    head = connection.execute(
        select(AuditChain.chain_index, AuditChain.row_hash)
        .order_by(AuditChain.chain_index.desc())
        .limit(1)
    ).first()
    walker = ChainWalker()
    found: ChainBreak | None = None
    last_index: int | None = None
    while found is None:
        statement = (
            select(
                AuditChain.chain_index, AuditChain.prev_hash, AuditChain.row_hash, *EVENT_FIELDS
            )
            .select_from(AuditChain)
            .outerjoin(AuditEvent, AuditEvent.id == AuditChain.event_id)
            .order_by(AuditChain.chain_index)
            .limit(batch_size)
        )
        if last_index is not None:
            statement = statement.where(AuditChain.chain_index > last_index)
        rows = connection.execute(statement).all()
        if not rows:
            break
        for row in rows:
            event = None if row.id is None else EventRecord(*row[3:])
            found = walker.check(ChainLink(row.chain_index, row.prev_hash, row.row_hash, event))
            if found is not None:
                break
        last_index = rows[-1].chain_index
    anchor_status = None
    if anchor is not None:
        stored = connection.scalar(
            select(AuditChain.row_hash).where(AuditChain.chain_index == anchor[0])
        )
        anchor_status = (
            ANCHOR_NOT_FOUND
            if stored is None
            else ANCHOR_MATCH
            if stored == anchor[1].lower()
            else ANCHOR_MISMATCH
        )
    return ChainVerification(
        status=INTACT if found is None else BROKEN,
        sealed=sealed,
        pending=pending,
        head_index=head.chain_index if head else 0,
        head_hash=head.row_hash if head else None,
        broken_index=found.chain_index if found else None,
        reason=found.reason if found else None,
        anchor_status=anchor_status,
        verified_at=datetime.now(UTC),
    )


def verify_audit_chain(
    *,
    seal_first: bool = True,
    batch_size: int = VERIFY_BATCH_SIZE,
    anchor_index: int | None = None,
    anchor_hash: str | None = None,
) -> ChainVerification:
    """Recompute the whole chain and report the first position that does not hold.

    ``INTACT`` means every sealed event still matches its hash and every link
    holds. It does not cover ``pending`` events, and it cannot show that the
    newest rows were removed or that the chain was rebuilt after a change (see
    the module docstring). Supplying a head anchor saved earlier outside the
    database (``anchor_index`` with ``anchor_hash``) closes that gap for
    everything up to the anchor: ``anchor_status`` is ``MATCH`` only if that
    position still holds that hash.
    """
    if (anchor_index is None) != (anchor_hash is None):
        raise ValueError("anchor_index and anchor_hash must be given together")
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    if seal_first:
        try:
            seal_audit_chain()
        except SQLAlchemyError as exc:
            # Verification reads only; report on what is stored even if nothing
            # could be appended. Unsealed events then show up as ``pending``.
            logger.error("Audit chain sealing failed before verification (%s)", type(exc).__name__)
    anchor = None if anchor_index is None or anchor_hash is None else (anchor_index, anchor_hash)
    # One snapshot for the counts, the head and every batch of the walk.
    with _connect("REPEATABLE READ") as connection, connection.begin():
        result = _verify(connection, batch_size, anchor)
    if result.status == BROKEN:
        logger.error(
            "Audit chain verification failed at index %s (%s)", result.broken_index, result.reason
        )
    return result

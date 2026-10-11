"""Real PostgreSQL checks for the audit hash chain.

Covers sealing and verification of events written by the application, detection
of changes made by a privileged role, the runtime role's inability to rewrite
the chain, and the concurrency rules of sealing.

The suite shares one database with the other integration tests and with a
worker that seals every few seconds, and it is re-run on the same database.
Every test therefore identifies its own events by a fresh marker, tolerates
other events, and puts back anything it deliberately broke before returning.
"""

import os
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from app.api.auth import LoginThrottle
from app.core.audit import record_event
from app.core.database import get_engine, session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AuditChain, AuditEvent, User
from app.services.audit_chain import (
    EVENT_FIELDS,
    GENESIS_HASH,
    SEAL_LOCK_KEY,
    EventRecord,
    compute_row_hash,
    seal_audit_chain,
    verify_audit_chain,
)
from app.workers.celery_app import celery_app

pytestmark = pytest.mark.integration

VERIFY_PATH = "/api/v1/audit-events/verify"


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def owner():
    """The schema owner: a role that, unlike the runtime role, can rewrite history."""
    url = os.environ.get("MIGRATION_DATABASE_URL")
    assert url, "MIGRATION_DATABASE_URL is required to act as a privileged role"
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    with TestClient(app, base_url="http://localhost:8080") as client:
        yield client


def _account(role: str) -> tuple[User, str]:
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"chain-{role.lower()}-{uuid.uuid4().hex}@example.com",
        role=role,
        password_hash=hash_password(password),
    )
    with session_factory()() as db:
        db.add(user)
        db.commit()
    return user, password


def _login(client, role: str) -> User:
    user, password = _account(role)
    response = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return user


def _record(count: int, marker: uuid.UUID | None = None) -> uuid.UUID:
    """Commit ``count`` events through the application's audit function."""
    marker = marker or uuid.uuid4()
    with session_factory()() as db:
        for _ in range(count):
            record_event(
                db,
                actor_id=None,
                event_type="AUDIT_CHAIN_TEST",
                subject_type="audit_chain_test",
                subject_id=marker,
            )
        db.commit()
    return marker


def _event_ids(marker: uuid.UUID) -> list[uuid.UUID]:
    with session_factory()() as db:
        return list(db.scalars(select(AuditEvent.id).where(AuditEvent.subject_id == marker)))


def _sealed(marker: uuid.UUID):
    """Chain rows of this marker's events, in chain order."""
    with session_factory()() as db:
        return db.execute(
            select(AuditChain.chain_index, AuditChain.event_id, AuditChain.row_hash)
            .join(AuditEvent, AuditEvent.id == AuditChain.event_id)
            .where(AuditEvent.subject_id == marker)
            .order_by(AuditChain.chain_index)
        ).all()


def _assert_whole_chain_is_well_formed() -> int:
    with session_factory()() as db:
        rows = db.execute(
            select(
                AuditChain.chain_index,
                AuditChain.event_id,
                AuditChain.prev_hash,
                AuditChain.row_hash,
            ).order_by(AuditChain.chain_index)
        ).all()
    assert [row.chain_index for row in rows] == list(range(1, len(rows) + 1)), "indices not dense"
    assert len({row.event_id for row in rows}) == len(rows), "an event was sealed twice"
    previous = GENESIS_HASH
    for row in rows:
        assert row.prev_hash == previous, f"fork or broken link at {row.chain_index}"
        previous = row.row_hash
    return len(rows)


def _assert_sealed_exactly_once(marker: uuid.UUID, expected: int) -> None:
    ids = _event_ids(marker)
    assert len(ids) == expected
    sealed = [row.event_id for row in _sealed(marker)]
    assert sorted(sealed, key=str) == sorted(ids, key=str)


@contextmanager
def _sealing_paused(owner):
    """Hold the sealer lock on its own session so nothing is appended meanwhile."""
    with owner.connect().execution_options(isolation_level="AUTOCOMMIT") as holder:
        holder.execute(text("SELECT pg_advisory_lock(:key)"), {"key": SEAL_LOCK_KEY})
        try:
            yield
        finally:
            holder.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": SEAL_LOCK_KEY})


def _assert_intact() -> None:
    result = verify_audit_chain()
    assert (result.status, result.broken_index, result.reason) == ("INTACT", None, None)


def test_application_events_are_sealed_and_the_chain_verifies(client):
    user = _login(client, "ADMIN")
    assert client.post("/api/v1/auth/logout").status_code == 204
    with session_factory()() as db:
        event_ids = list(db.scalars(select(AuditEvent.id).where(AuditEvent.actor_id == user.id)))
    assert len(event_ids) == 2  # AUTH_LOGIN and AUTH_LOGOUT

    _login(client, "AUDITOR")
    response = client.get(VERIFY_PATH)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "INTACT"
    assert body["broken_index"] is None and body["reason"] is None
    assert body["anchor_status"] is None
    assert body["sealed"] == body["head_index"] >= 2
    assert body["pending"] >= 0

    with session_factory()() as db:
        sealed = db.execute(
            select(AuditChain.event_id).where(AuditChain.event_id.in_(event_ids))
        ).all()
        head_hash = db.scalar(
            select(AuditChain.row_hash).where(AuditChain.chain_index == body["head_index"])
        )
    assert len(sealed) == 2
    assert head_hash == body["head_hash"]
    # Indices are dense from 1 and every prev_hash is the previous row's row_hash.
    assert _assert_whole_chain_is_well_formed() >= body["sealed"]


def test_unsealed_events_are_reported_as_pending_until_sealed(owner):
    with _sealing_paused(owner):
        marker = _record(3)
        result = verify_audit_chain(seal_first=False)
        assert result.status == "INTACT"
        assert result.pending >= 3
        assert _sealed(marker) == []
    # No assertion on the count returned here: the worker's own sealer may have
    # been waiting for the lock and sealed these events first.
    seal_audit_chain()
    _assert_sealed_exactly_once(marker, 3)
    seal_audit_chain(batch_size=1)
    _assert_sealed_exactly_once(marker, 3)
    _assert_intact()


@pytest.mark.parametrize(
    "assignment,value",
    [
        pytest.param("event_type = :value", "TAMPERED_BY_OWNER", id="event_type"),
        pytest.param("details = CAST(:value AS jsonb)", '{"note": "tampered"}', id="details"),
        # Values a verifier could choke on must be reported, not crash the check.
        pytest.param(
            "details = CAST(:value AS jsonb)", "[" * 2000 + "]" * 2000, id="details-deeply-nested"
        ),
        pytest.param(
            "created_at = CAST(:value AS timestamptz)", "infinity", id="created_at-infinity"
        ),
    ],
)
def test_privileged_change_to_a_sealed_event_is_detected(client, owner, assignment, value):
    marker = _record(3)
    seal_audit_chain()
    target = _sealed(marker)[1]
    _assert_intact()
    with owner.connect() as connection:
        original = connection.execute(
            text(
                "SELECT event_type, details::text AS details, created_at::text AS created_at "
                "FROM audit_events WHERE id = :id"
            ),
            {"id": target.event_id},
        ).one()
    try:
        with owner.begin() as connection:
            changed = connection.execute(
                text(f"UPDATE audit_events SET {assignment} WHERE id = :id"),
                {"value": value, "id": target.event_id},
            )
            assert changed.rowcount == 1
        result = verify_audit_chain()
        assert (result.status, result.reason, result.broken_index) == (
            "BROKEN",
            "HASH_MISMATCH",
            target.chain_index,
        )
        assert result.head_index > target.chain_index

        _login(client, "AUDITOR")
        body = client.get(VERIFY_PATH).json()
        assert (body["status"], body["reason"], body["broken_index"]) == (
            "BROKEN",
            "HASH_MISMATCH",
            target.chain_index,
        )
    finally:
        with owner.begin() as connection:
            connection.execute(
                text(
                    "UPDATE audit_events SET event_type = :event_type, "
                    "details = CAST(:details AS jsonb), "
                    "created_at = CAST(:created_at AS timestamptz) WHERE id = :id"
                ),
                {**original._mapping, "id": target.event_id},
            )
        _assert_intact()


@pytest.mark.parametrize(
    "column,reason", [("row_hash", "HASH_MISMATCH"), ("prev_hash", "LINK_MISMATCH")]
)
def test_privileged_rewrite_of_a_chain_row_is_detected(owner, column, reason):
    marker = _record(3)
    seal_audit_chain()
    # Not the head: later rows already reference it, so sealing that continues
    # in the worker meanwhile never builds on the forged value.
    target = _sealed(marker)[0]
    _assert_intact()
    with owner.connect() as connection:
        original = connection.scalar(
            text(f"SELECT {column} FROM audit_chain WHERE chain_index = :index"),
            {"index": target.chain_index},
        )
    update = text(f"UPDATE audit_chain SET {column} = :value WHERE chain_index = :index")
    try:
        with owner.begin() as connection:
            connection.execute(update, {"value": "f" * 64, "index": target.chain_index})
        result = verify_audit_chain()
        assert (result.status, result.reason, result.broken_index) == (
            "BROKEN",
            reason,
            target.chain_index,
        )
    finally:
        with owner.begin() as connection:
            connection.execute(update, {"value": original, "index": target.chain_index})
        _assert_intact()


def test_event_and_its_own_hash_rewritten_together_break_the_next_link(owner):
    marker = _record(3)
    seal_audit_chain()
    target = _sealed(marker)[0]
    _assert_intact()
    with owner.connect() as connection:
        record = EventRecord(
            *connection.execute(select(*EVENT_FIELDS).where(AuditEvent.id == target.event_id)).one()
        )
        prev_hash = connection.scalar(
            select(AuditChain.prev_hash).where(AuditChain.chain_index == target.chain_index)
        )
    forged = compute_row_hash(prev_hash, replace(record, event_type="FORGED"))
    change = text(
        "WITH e AS (UPDATE audit_events SET event_type = :event_type WHERE id = :id) "
        "UPDATE audit_chain SET row_hash = :row_hash WHERE chain_index = :index"
    )
    try:
        with owner.begin() as connection:
            connection.execute(
                change,
                {
                    "event_type": "FORGED",
                    "id": target.event_id,
                    "row_hash": forged,
                    "index": target.chain_index,
                },
            )
        result = verify_audit_chain()
        assert (result.status, result.reason, result.broken_index) == (
            "BROKEN",
            "LINK_MISMATCH",
            target.chain_index + 1,
        )
    finally:
        with owner.begin() as connection:
            connection.execute(
                change,
                {
                    "event_type": record.event_type,
                    "id": target.event_id,
                    "row_hash": target.row_hash,
                    "index": target.chain_index,
                },
            )
        _assert_intact()


def test_removed_chain_row_is_reported_as_an_index_gap(owner):
    marker = _record(3)
    seal_audit_chain()
    target = _sealed(marker)[0]
    _assert_intact()
    # Paused, because a sealer would otherwise seal the orphaned event again at
    # the head and the removed row could no longer be put back.
    with _sealing_paused(owner):
        with owner.begin() as connection:
            saved = connection.execute(
                text(
                    "DELETE FROM audit_chain WHERE chain_index = :index "
                    "RETURNING chain_index, event_id, prev_hash, row_hash, sealed_at"
                ),
                {"index": target.chain_index},
            ).one()
        try:
            result = verify_audit_chain(seal_first=False)
            assert (result.status, result.reason, result.broken_index) == (
                "BROKEN",
                "INDEX_GAP",
                target.chain_index,
            )
            assert result.pending >= 1
        finally:
            with owner.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO audit_chain "
                        "(chain_index, event_id, prev_hash, row_hash, sealed_at) VALUES "
                        "(:chain_index, :event_id, :prev_hash, :row_hash, :sealed_at)"
                    ),
                    dict(saved._mapping),
                )
            assert verify_audit_chain(seal_first=False).status == "INTACT"
    _assert_intact()


def test_rebuilt_chain_passes_verification_but_not_a_saved_anchor(client, owner):
    """The documented limit, and what the head anchor is for.

    A role that can rewrite ``audit_chain`` can change an event and recompute
    every later hash. Nothing inside the database then disagrees; only an anchor
    kept elsewhere does.
    """
    marker = _record(3)
    seal_audit_chain()
    target = _sealed(marker)[0]
    _login(client, "AUDITOR")
    with _sealing_paused(owner):
        before = verify_audit_chain(seal_first=False)
        assert before.status == "INTACT"
        anchor = {"anchor_index": before.head_index, "anchor_hash": before.head_hash}
        assert verify_audit_chain(seal_first=False, **anchor).anchor_status == "MATCH"
        with owner.connect() as connection:
            suffix = connection.execute(
                select(AuditChain.chain_index, AuditChain.prev_hash, AuditChain.row_hash)
                .where(AuditChain.chain_index >= target.chain_index)
                .order_by(AuditChain.chain_index)
            ).all()
        rewrite = text(
            "UPDATE audit_chain SET prev_hash = :prev_hash, row_hash = :row_hash "
            "WHERE chain_index = :chain_index"
        )
        retype = text("UPDATE audit_events SET event_type = :value WHERE id = :id")
        try:
            with owner.begin() as connection:
                connection.execute(retype, {"value": "FORGED", "id": target.event_id})
                prev_hash = suffix[0].prev_hash
                rows = connection.execute(
                    select(AuditChain.chain_index, *EVENT_FIELDS)
                    .join(AuditEvent, AuditEvent.id == AuditChain.event_id)
                    .where(AuditChain.chain_index >= target.chain_index)
                    .order_by(AuditChain.chain_index)
                ).all()
                for row in rows:
                    row_hash = compute_row_hash(prev_hash, EventRecord(*row[1:]))
                    connection.execute(
                        rewrite,
                        {"prev_hash": prev_hash, "row_hash": row_hash, "chain_index": row[0]},
                    )
                    prev_hash = row_hash
            forged = verify_audit_chain(seal_first=False, **anchor)
            assert forged.status == "INTACT"
            assert forged.head_index == before.head_index
            assert forged.head_hash != before.head_hash
            assert forged.anchor_status == "MISMATCH"
        finally:
            with owner.begin() as connection:
                connection.execute(retype, {"value": "AUDIT_CHAIN_TEST", "id": target.event_id})
                connection.execute(rewrite, [dict(row._mapping) for row in suffix])
            restored = verify_audit_chain(seal_first=False, **anchor)
            assert (restored.status, restored.anchor_status) == ("INTACT", "MATCH")
    # The same anchor through the API, and one that points past the end of the chain.
    assert client.get(VERIFY_PATH, params=anchor).json()["anchor_status"] == "MATCH"
    beyond = {"anchor_index": before.head_index + 10_000_000, "anchor_hash": "a" * 64}
    assert client.get(VERIFY_PATH, params=beyond).json()["anchor_status"] == "NOT_FOUND"
    _assert_intact()


def test_runtime_role_can_append_to_but_not_rewrite_the_chain(db):
    _record(1)
    seal_audit_chain()
    assert db.scalar(text("SELECT current_user")) == "ps_app"
    for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
        assert not db.scalar(
            text("SELECT has_table_privilege(current_user, 'audit_chain', :privilege)"),
            {"privilege": privilege},
        ), f"audit_chain must deny runtime {privilege}"
    for privilege in ("SELECT", "INSERT"):
        assert db.scalar(
            text("SELECT has_table_privilege(current_user, 'audit_chain', :privilege)"),
            {"privilege": privilege},
        )
    first_row = text("SELECT prev_hash, row_hash FROM audit_chain WHERE chain_index = 1")
    before = db.execute(first_row).one()
    db.rollback()
    for statement in (
        "UPDATE audit_chain SET row_hash = repeat('0', 64) WHERE chain_index = 1",
        "UPDATE audit_chain SET prev_hash = repeat('0', 64) WHERE false",
        "DELETE FROM audit_chain WHERE chain_index = 1",
        "DELETE FROM audit_chain WHERE false",
        "TRUNCATE audit_chain",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(statement))
        db.rollback()
    after = db.execute(first_row).one()
    assert tuple(after) == tuple(before)


def test_a_sealer_waits_for_the_sealer_that_holds_the_lock(db):
    marker = _record(2)
    with get_engine().connect() as holder:
        transaction = holder.begin()
        holder.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SEAL_LOCK_KEY})
        pid = holder.scalar(text("SELECT pg_backend_pid()"))
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(seal_audit_chain)
            deadline = time.monotonic() + 5
            blocked = 0
            while not blocked and time.monotonic() < deadline:
                blocked = db.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE :pid = ANY(pg_blocking_pids(pid))"
                    ),
                    {"pid": pid},
                )
                db.rollback()
                time.sleep(0.02)
            assert blocked >= 1
            assert not future.done()
            assert _sealed(marker) == []
            transaction.commit()
            assert future.result(timeout=10) >= 0
    seal_audit_chain()
    _assert_sealed_exactly_once(marker, 2)
    _assert_whole_chain_is_well_formed()


def test_concurrent_sealers_never_fork_the_chain_or_leave_a_gap():
    before = _assert_whole_chain_is_well_formed()
    marker = _record(240)
    sealers = 4
    barrier = threading.Barrier(sealers)

    def sealer() -> int:
        barrier.wait(timeout=10)
        # A small batch is one short transaction, so the sealers interleave.
        return seal_audit_chain(batch_size=5)

    with ThreadPoolExecutor(max_workers=sealers) as pool:
        futures = [pool.submit(sealer) for _ in range(sealers)]
        counts = [future.result(timeout=60) for future in futures]
    seal_audit_chain()
    _assert_sealed_exactly_once(marker, 240)
    # Dense, linked, no event twice; and no sealer counted a row it did not add.
    added = _assert_whole_chain_is_well_formed() - before
    assert added >= 240
    assert sum(counts) <= added
    _assert_intact()


def test_sealing_while_transactions_insert_never_loses_or_duplicates_an_event():
    marker = uuid.uuid4()
    writers, transactions = 4, 30
    done = threading.Event()

    def writer(seed: int) -> int:
        written = 0
        for number in range(transactions):
            events = 1 + (seed + number) % 2
            with session_factory()() as db:
                for _ in range(events):
                    record_event(
                        db,
                        actor_id=None,
                        event_type="AUDIT_CHAIN_TEST",
                        subject_type="audit_chain_test",
                        subject_id=marker,
                    )
                # Stay open across a sealing pass so the events commit after
                # events with a later timestamp have already been sealed.
                db.flush()
                time.sleep(0.004 * ((seed + number) % 4))
                db.commit()
            written += events
        return written

    def sealer() -> None:
        while not done.is_set():
            seal_audit_chain(batch_size=3)

    with ThreadPoolExecutor(max_workers=writers + 2) as pool:
        sealing = [pool.submit(sealer) for _ in range(2)]
        try:
            written = sum(
                future.result(timeout=60)
                for future in [pool.submit(writer, seed) for seed in range(writers)]
            )
        finally:
            done.set()
        for future in sealing:
            future.result(timeout=60)
    seal_audit_chain()
    _assert_sealed_exactly_once(marker, written)
    _assert_whole_chain_is_well_formed()
    _assert_intact()


def test_event_committed_late_is_sealed_later_and_never_skipped():
    early_marker = uuid.uuid4()
    with session_factory()() as early:
        record_event(
            early,
            actor_id=None,
            event_type="AUDIT_CHAIN_TEST",
            subject_type="audit_chain_test",
            subject_id=early_marker,
        )
        early.flush()  # Written, but its transaction is still open.
        time.sleep(0.01)
        later_marker = _record(2)
        seal_audit_chain()
        # Invisible to the sealer, so neither sealed nor counted as handled.
        assert _sealed(early_marker) == []
        later = _sealed(later_marker)
        assert len(later) == 2
        early.commit()
    seal_audit_chain()
    seal_audit_chain()
    _assert_sealed_exactly_once(early_marker, 1)
    _assert_sealed_exactly_once(later_marker, 2)
    with session_factory()() as db:
        early_created = db.scalar(
            select(AuditEvent.created_at).where(AuditEvent.subject_id == early_marker)
        )
        later_created = db.scalar(
            select(AuditEvent.created_at)
            .where(AuditEvent.subject_id == later_marker)
            .order_by(AuditEvent.created_at)
            .limit(1)
        )
    # Older by timestamp, later in the chain: chain order is sealing order.
    assert early_created < later_created
    assert _sealed(early_marker)[0].chain_index > later[-1].chain_index
    _assert_whole_chain_is_well_formed()
    _assert_intact()


def test_the_worker_seals_pending_events():
    marker = _record(2)
    # The real worker runs the task (its beat schedule would also reach these
    # events within seconds); this process never seals them itself.
    celery_app.send_task("privacyshield.seal_audit_chain")
    deadline = time.monotonic() + 60
    while len(_sealed(marker)) < 2 and time.monotonic() < deadline:
        time.sleep(0.25)
    _assert_sealed_exactly_once(marker, 2)


def test_verify_endpoint_role_checks(client):
    assert client.get(VERIFY_PATH).status_code == 401
    for role, expected in (("ADMIN", 200), ("AUDITOR", 200), ("ANALYST", 403)):
        client.cookies.clear()
        _login(client, role)
        response = client.get(VERIFY_PATH)
        assert response.status_code == expected, role
        if expected == 200:
            assert response.json()["status"] == "INTACT"
    client.cookies.clear()
    assert client.get(VERIFY_PATH).status_code == 401


def test_verifying_does_not_add_to_the_log_it_measures(client):
    user = _login(client, "AUDITOR")
    first = client.get(VERIFY_PATH).json()
    second = client.get(VERIFY_PATH).json()
    assert first["status"] == second["status"] == "INTACT"
    with session_factory()() as db:
        types = list(
            db.scalars(select(AuditEvent.event_type).where(AuditEvent.actor_id == user.id))
        )
    assert types == ["AUTH_LOGIN"]

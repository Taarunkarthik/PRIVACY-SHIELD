"""Hashing, chain-walking and routing rules of the audit chain; no database needed."""

import inspect
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Match

from app.api.dependencies import current_user
from app.api.policies import router as policy_router
from app.main import app
from app.models import User
from app.services.audit_chain import (
    GENESIS_HASH,
    ChainBreak,
    ChainLink,
    ChainVerification,
    EventRecord,
    canonical_bytes,
    compute_row_hash,
    first_break,
    seal_audit_chain,
    verify_audit_chain,
)
from app.workers.celery_app import celery_app

EVENT = EventRecord(
    id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
    actor_id=None,
    event_type="LOGIN_SUCCEEDED",
    subject_type="session",
    subject_id=uuid.UUID("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
    correlation_id=uuid.UUID("99999999-8888-7777-6666-555555555555"),
    details_json="{}",
    created_at_utc="2026-10-01T09:00:00.000000Z",
)


def test_canonical_bytes_is_a_pinned_format():
    # Changing this output invalidates every chain already stored, so it is pinned.
    assert canonical_bytes(EVENT) == (
        b'{"actor_id":null,"correlation_id":"99999999-8888-7777-6666-555555555555",'
        b'"created_at":"2026-10-01T09:00:00.000000Z","details":{},'
        b'"event_type":"LOGIN_SUCCEEDED","id":"11111111-2222-3333-4444-555555555555",'
        b'"subject_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","subject_type":"session"}'
    )
    # sha256 of 64 ASCII zeros followed by the bytes above, computed independently.
    assert compute_row_hash(GENESIS_HASH, EVENT) == (
        "daf3364da4351b357b16060c5960ac7b63d67d3b342bb8ff2f335f8c7dd63351"
    )


def test_canonical_bytes_is_sorted_compact_utf8_json():
    details = {"zeta": [1, "two", None, True, False], "alpha": {"b": "é ✓ \" \\ \n", "a": 3}}
    event = replace(EVENT, details_json=json.dumps(details))
    expected = {
        "id": str(EVENT.id),
        "actor_id": None,
        "event_type": EVENT.event_type,
        "subject_type": EVENT.subject_type,
        "subject_id": str(EVENT.subject_id),
        "correlation_id": str(EVENT.correlation_id),
        "created_at": EVENT.created_at_utc,
        "details": details,
    }
    assert canonical_bytes(event) == json.dumps(
        expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_details_key_order_and_whitespace_do_not_change_the_hash():
    one = replace(EVENT, details_json='{"a": 1, "b": {"c": [1, 2], "d": "x"}}')
    two = replace(EVENT, details_json='{"b":{"d":"x","c":[1,2]},"a":1}')
    assert canonical_bytes(one) == canonical_bytes(two)


@pytest.mark.parametrize(
    "left,right",
    [
        ('{"n": 0.1}', '{"n": 0.10000000000000000001}'),
        ('{"n": 9007199254740992}', '{"n": 9007199254740993}'),
        ('{"n": 1.5}', '{"n": "1.5"}'),
        ('{"n": 1}', '{"n": true}'),
        ('{"n": null}', "{}"),
        ('{"n": [1, 2]}', '{"n": [2, 1]}'),
    ],
)
def test_values_a_float_would_merge_still_hash_differently(left, right):
    assert canonical_bytes(replace(EVENT, details_json=left)) != canonical_bytes(
        replace(EVENT, details_json=right)
    )


@pytest.mark.parametrize(
    "change",
    [
        {"id": uuid.uuid4()},
        {"actor_id": uuid.uuid4()},
        {"event_type": "LOGIN_FAILED"},
        {"subject_type": "user"},
        {"subject_id": None},
        {"correlation_id": uuid.uuid4()},
        {"details_json": '{"note": "edited"}'},
        {"created_at_utc": "2026-10-01T09:00:00.000001Z"},
    ],
)
def test_every_protected_field_changes_the_row_hash(change):
    assert compute_row_hash(GENESIS_HASH, replace(EVENT, **change)) != compute_row_hash(
        GENESIS_HASH, EVENT
    )
    assert compute_row_hash("1" * 64, EVENT) != compute_row_hash(GENESIS_HASH, EVENT)


def test_details_python_cannot_parse_are_still_hashed_deterministically():
    deep = "[" * 100_000 + "]" * 100_000
    huge = '{"n": ' + "9" * 10_000 + "}"
    for raw in (deep, huge, None):
        event = replace(EVENT, details_json=raw)
        assert canonical_bytes(event) == canonical_bytes(event)
        assert len(compute_row_hash(GENESIS_HASH, event)) == 64
    assert canonical_bytes(replace(EVENT, details_json=deep)) != canonical_bytes(
        replace(EVENT, details_json=deep[1:-1])
    )


def _chain(length: int = 4) -> list[ChainLink]:
    links, prev_hash = [], GENESIS_HASH
    for index in range(1, length + 1):
        event = replace(EVENT, id=uuid.UUID(int=index), event_type=f"EVENT_{index}")
        row_hash = compute_row_hash(prev_hash, event)
        links.append(ChainLink(index, prev_hash, row_hash, event))
        prev_hash = row_hash
    return links


def test_an_untouched_chain_has_no_break():
    assert first_break(_chain()) is None
    assert first_break([]) is None


def test_changed_event_content_is_a_hash_mismatch_at_that_index():
    links = _chain()
    links[1] = replace(links[1], event=replace(links[1].event, details_json='{"edited": true}'))
    assert first_break(links) == ChainBreak(2, "HASH_MISMATCH")


def test_rewritten_row_hash_is_reported_on_the_rewritten_row():
    links = _chain()
    links[1] = replace(links[1], row_hash="f" * 64)
    assert first_break(links) == ChainBreak(2, "HASH_MISMATCH")


def test_recomputing_one_row_after_an_edit_breaks_the_next_link():
    links = _chain()
    edited = replace(links[1].event, event_type="EDITED")
    links[1] = replace(
        links[1], event=edited, row_hash=compute_row_hash(links[1].prev_hash, edited)
    )
    assert first_break(links) == ChainBreak(3, "LINK_MISMATCH")


def test_rewritten_prev_hash_is_a_link_mismatch():
    links = _chain()
    links[2] = replace(links[2], prev_hash="e" * 64)
    assert first_break(links) == ChainBreak(3, "LINK_MISMATCH")
    first = _chain()
    first[0] = replace(first[0], prev_hash="e" * 64)
    assert first_break(first) == ChainBreak(1, "LINK_MISMATCH")


def test_removed_chain_row_is_an_index_gap_at_the_missing_position():
    links = _chain()
    del links[1]
    assert first_break(links) == ChainBreak(2, "INDEX_GAP")
    assert first_break(_chain()[1:]) == ChainBreak(1, "INDEX_GAP")


def test_chain_row_without_its_event_is_a_missing_event():
    links = _chain()
    links[2] = replace(links[2], event=None)
    assert first_break(links) == ChainBreak(3, "MISSING_EVENT")


def test_sealer_is_callable_without_arguments_and_scheduled():
    required = [
        parameter
        for parameter in inspect.signature(seal_audit_chain).parameters.values()
        if parameter.default is inspect.Parameter.empty
    ]
    assert required == []
    entry = celery_app.conf.beat_schedule["seal-audit-chain"]
    assert entry["task"] == "privacyshield.seal_audit_chain"
    assert 15 <= entry["schedule"] <= 30
    assert "privacyshield.seal_audit_chain" in celery_app.tasks


def test_anchor_arguments_must_come_together():
    with pytest.raises(ValueError):
        verify_audit_chain(anchor_index=3)
    with pytest.raises(ValueError):
        verify_audit_chain(anchor_hash="a" * 64)


VERIFY_PATH = "/api/v1/audit-events/verify"


def test_verify_route_is_matched_before_any_other_audit_route():
    # Routes are tried in declaration order, so the literal path must come first.
    scope = {"type": "http", "method": "GET", "path": "/audit-events/verify", "root_path": ""}
    matched = next(
        route for route in policy_router.routes if route.matches(scope)[0] is Match.FULL
    )
    assert matched.endpoint.__name__ == "verify_audit_events"
    audit_paths = [
        route.path for route in policy_router.routes if route.path.startswith("/audit-events")
    ]
    assert audit_paths[0] == "/audit-events/verify"


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def _as(role: str) -> None:
    app.dependency_overrides[current_user] = lambda: User(
        id=uuid.uuid4(), email="test@example.com", password_hash="unused", role=role
    )


def test_verify_requires_a_session(client):
    assert client.get(VERIFY_PATH).status_code == 401


def test_verify_rejects_analysts_before_touching_the_chain(client, monkeypatch):
    def unexpected(**_):
        raise AssertionError("verification must not run for a forbidden role")

    monkeypatch.setattr("app.api.policies.verify_audit_chain", unexpected)
    _as("ANALYST")
    assert client.get(VERIFY_PATH).status_code == 403


@pytest.mark.parametrize("role", ["ADMIN", "AUDITOR"])
def test_verify_returns_the_result_for_permitted_roles(client, monkeypatch, role):
    calls = []
    result = ChainVerification(
        status="BROKEN",
        sealed=12,
        pending=1,
        head_index=12,
        head_hash="a" * 64,
        broken_index=7,
        reason="HASH_MISMATCH",
        anchor_status=None,
        verified_at=datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
    )

    def fake(**kwargs):
        calls.append(kwargs)
        return result

    monkeypatch.setattr("app.api.policies.verify_audit_chain", fake)
    _as(role)
    response = client.get(VERIFY_PATH)
    assert response.status_code == 200
    assert response.json() == {
        "status": "BROKEN",
        "sealed": 12,
        "pending": 1,
        "head_index": 12,
        "head_hash": "a" * 64,
        "broken_index": 7,
        "reason": "HASH_MISMATCH",
        "anchor_status": None,
        "verified_at": "2026-10-01T09:00:00Z",
    }
    assert calls == [{"anchor_index": None, "anchor_hash": None}]


def test_verify_validates_the_optional_anchor(client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.api.policies.verify_audit_chain",
        lambda **kwargs: calls.append(kwargs) or (_ for _ in ()).throw(RuntimeError("stop")),
    )
    _as("AUDITOR")
    for query in (
        "?anchor_index=3",
        "?anchor_hash=" + "a" * 64,
        "?anchor_index=0&anchor_hash=" + "a" * 64,
        "?anchor_index=3&anchor_hash=not-a-hash",
    ):
        assert client.get(VERIFY_PATH + query).status_code == 422, query
    assert calls == []


def test_verify_rejects_an_anchor_index_no_bigint_can_hold(client, monkeypatch):
    def unexpected(**_):
        raise AssertionError("an out-of-range anchor must be refused before the chain is read")

    monkeypatch.setattr("app.api.policies.verify_audit_chain", unexpected)
    _as("AUDITOR")
    query = f"?anchor_index={2**63}&anchor_hash=" + "a" * 64
    assert client.get(VERIFY_PATH + query).status_code == 422


def test_only_one_verification_runs_at_a_time(client, monkeypatch):
    """A check reads the whole log; a second request must not queue up behind it."""
    import threading

    started, release = threading.Event(), threading.Event()
    result = ChainVerification(
        status="INTACT",
        sealed=1,
        pending=0,
        head_index=1,
        head_hash="b" * 64,
        broken_index=None,
        reason=None,
        anchor_status=None,
        verified_at=datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
    )

    def slow(**_):
        started.set()
        assert release.wait(10)
        return result

    monkeypatch.setattr("app.api.policies.verify_audit_chain", slow)
    _as("ADMIN")
    first = {}
    worker = threading.Thread(target=lambda: first.update(response=client.get(VERIFY_PATH)))
    worker.start()
    try:
        assert started.wait(10)
        second = client.get(VERIFY_PATH)
        assert second.status_code == 429
        assert second.headers["retry-after"] == "5"
    finally:
        release.set()
        worker.join(10)
    assert first["response"].status_code == 200
    # The first check has finished, so the next one runs. A failed check frees the slot too.
    assert client.get(VERIFY_PATH).status_code == 200

    def failing(**_):
        raise RuntimeError("database went away")

    monkeypatch.setattr("app.api.policies.verify_audit_chain", failing)
    with pytest.raises(RuntimeError):
        client.get(VERIFY_PATH)
    monkeypatch.setattr("app.api.policies.verify_audit_chain", lambda **_: result)
    assert client.get(VERIFY_PATH).status_code == 200


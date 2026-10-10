"""Real PostgreSQL checks that runtime cannot mutate append-only audit history.

The control database revokes UPDATE/DELETE/TRUNCATE on ``audit_events`` from the
runtime role; this suite asserts that control directly instead of trusting it.
"""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.database import session_factory
from app.models import AuditEvent

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


IMMUTABLE_TABLES = ("audit_events", "schema_snapshots")


@pytest.mark.parametrize("table", IMMUTABLE_TABLES)
def test_runtime_role_is_least_privileged_and_cannot_mutate(db, table):
    assert db.scalar(text("SELECT current_user")) == "ps_app"
    assert not db.scalar(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"))
    for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
        assert not db.scalar(
            text("SELECT has_table_privilege(current_user, :table, :privilege)"),
            {"table": table, "privilege": privilege},
        ), f"{table} must deny runtime {privilege}"
    # Appending audit history remains possible for the runtime role.
    assert db.scalar(
        text("SELECT has_table_privilege(current_user, :table, 'INSERT')"), {"table": table}
    )


def test_database_rejects_audit_update_delete_and_truncate(db):
    for statement in (
        "UPDATE audit_events SET event_type = 'tampered' WHERE false",
        "DELETE FROM audit_events WHERE false",
        "TRUNCATE audit_events",
    ):
        with pytest.raises(DBAPIError):
            db.execute(text(statement))
        db.rollback()


def test_appended_audit_row_is_durable_and_still_immutable(db):
    event = AuditEvent(event_type="SECURITY_TEST", subject_type="audit_security")
    db.add(event)
    db.commit()
    event_id = event.id
    db.expire_all()
    stored = db.get(AuditEvent, event_id)
    assert stored is not None
    assert stored.event_type == "SECURITY_TEST"
    assert db.scalar(
        text("SELECT count(*) FROM audit_events WHERE id = :id"), {"id": event_id}
    ) == 1
    with pytest.raises(DBAPIError):
        db.execute(
            text("UPDATE audit_events SET event_type = 'tampered' WHERE id = :id"),
            {"id": event_id},
        )
    db.rollback()
    with pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": event_id})
    db.rollback()
    # The immutable row is unchanged after rejected mutations.
    db.expire_all()
    assert db.get(AuditEvent, event_id).event_type == "SECURITY_TEST"


def test_runtime_cannot_edit_migration_state(db):
    # A runtime role must never be able to rewrite its own migration history.
    assert not db.scalar(
        text("SELECT has_table_privilege(current_user, 'alembic_version', 'UPDATE')")
    )
    with pytest.raises(DBAPIError):
        db.execute(text("UPDATE alembic_version SET version_num = :value"), {"value": "0" * 32})
    db.rollback()
    assert not db.scalar(
        text("SELECT has_table_privilege(current_user, 'audit_events', 'UPDATE')")
    )


def test_unknown_audit_ids_are_not_present_or_mutable(db):
    # Guard against a false pass if grants were checked on a different table name.
    assert db.scalar(text("SELECT to_regclass('public.audit_events')")) is not None
    with pytest.raises(DBAPIError):
        db.execute(
            text("UPDATE public.audit_events SET event_type = 'x' WHERE id = :id"),
            {"id": uuid.uuid4()},
        )
    db.rollback()

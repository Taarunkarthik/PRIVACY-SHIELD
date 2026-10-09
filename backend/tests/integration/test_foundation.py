"""Real PostgreSQL/Redis checks. Use a dedicated migrated test database.

Fixtures have unique identifiers and are retained. Tests never drop, truncate,
or delete pre-existing records (audit history is append-only).
"""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.api.auth import LoginThrottle
from app.api.dependencies import require_roles
from app.cli import create_admin
from app.core.database import get_engine, session_factory
from app.core.security import SESSION_COOKIE, hash_password, token_hash
from app.main import app, create_app
from app.models import (
    AuditEvent,
    Base,
    DatabaseConnection,
    ScanJob,
    SchemaSnapshot,
    User,
    UserSession,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def account(db):
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"foundation-{uuid.uuid4().hex}@example.com",
        role="ADMIN",
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    return user, password


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    with TestClient(app, base_url="http://localhost:8080") as client:
        yield client


def login(client, account):
    user, password = account
    response = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert response.status_code == 200, response.text
    return response


def test_migrations_create_all_tables_and_runtime_role(db):
    assert set(Base.metadata.tables) <= set(inspect(get_engine()).get_table_names())
    assert db.scalar(text("SELECT current_user")) == "ps_app"
    assert not db.scalar(text("SELECT rolsuper FROM pg_roles WHERE rolname=current_user"))
    assert not db.scalar(
        text("SELECT has_table_privilege(current_user,'alembic_version','UPDATE')")
    )


def test_ready_checks_real_database_and_redis(client):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200, response.text
    assert response.json()["checks"] == {"database": "ok", "redis": "ok"}


def test_login_csrf_logout_and_audit(client, account, db):
    response = login(client, account)
    payload = response.json()
    assert payload["role"] == "ADMIN"
    assert set(payload) == {"id", "email", "role", "csrf_token"}
    assert account[1] not in response.text
    cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        "ps_session=" in value and "HttpOnly" in value and "SameSite=lax" in value
        for value in cookie_headers
    )
    token = client.cookies.get(SESSION_COOKIE)
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    assert session is not None
    assert session.token_hash != token
    assert client.get("/api/v1/auth/me").json() == payload
    summary = client.get("/api/v1/dashboard/summary")
    assert summary.status_code == 200, summary.text
    assert set(summary.json()) == {
        "databases",
        "tables",
        "sensitive_columns",
        "pending_approvals",
        "deployed_policies",
        "scan_jobs",
    }
    assert all(isinstance(value, int) and value >= 0 for value in summary.json().values())
    assert client.post("/api/v1/auth/logout").status_code == 403
    assert (
        client.post(
            "/api/v1/auth/logout",
            headers={
                "X-CSRF-Token": payload["csrf_token"],
                "Origin": "https://attacker.example",
            },
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/auth/logout",
            headers={
                "X-CSRF-Token": payload["csrf_token"],
                "Origin": "http://localhost:8080",
            },
        ).status_code
        == 204
    )
    assert client.get("/api/v1/auth/me").status_code == 401
    events = db.scalars(select(AuditEvent.event_type).where(AuditEvent.actor_id == account[0].id))
    assert {"AUTH_LOGIN", "AUTH_LOGOUT"} <= set(events)


def test_login_failure_does_not_disclose_account(client, account):
    wrong_password = secrets.token_urlsafe(24)
    existing = client.post(
        "/api/v1/auth/login",
        json={
            "email": account[0].email,
            "password": wrong_password,
        },
    )
    unknown = client.post(
        "/api/v1/auth/login",
        json={
            "email": f"missing-{uuid.uuid4().hex}@example.com",
            "password": wrong_password,
        },
    )
    assert existing.status_code == unknown.status_code == 401
    assert existing.json() == unknown.json()
    assert wrong_password not in existing.text


def test_login_rotates_old_session(client, account):
    first = login(client, account)
    old_token = client.cookies.get(SESSION_COOKIE)
    second = login(client, account)
    assert first.json()["csrf_token"] != second.json()["csrf_token"]
    assert old_token != client.cookies.get(SESSION_COOKIE)
    with TestClient(app) as old_client:
        old_client.cookies.set(SESSION_COOKIE, old_token)
        assert old_client.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize(
    "role,expected_status", [("ADMIN", 200), ("ANALYST", 403), ("AUDITOR", 403)]
)
def test_rbac_enforces_roles_from_real_sessions(db, account, monkeypatch, role, expected_status):
    account[0].role = role
    db.commit()
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    guarded_app = create_app()

    @guarded_app.post("/test/admin-only")
    def administrative_operation(user: User = Depends(require_roles("ADMIN"))):
        return {"role": user.role}

    with TestClient(guarded_app, base_url="http://localhost:8080") as guarded_client:
        response = login(guarded_client, account)
        csrf = response.json()["csrf_token"]
        assert guarded_client.post("/test/admin-only").status_code == 403
        response = guarded_client.post("/test/admin-only", headers={"X-CSRF-Token": csrf})
        assert response.status_code == expected_status
        if role == "ADMIN":
            assert response.json() == {"role": "ADMIN"}


@pytest.mark.parametrize("invalidate", ["expired", "revoked", "inactive"])
def test_invalid_session_cannot_authenticate(client, account, db, invalidate):
    login(client, account)
    session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == token_hash(client.cookies.get(SESSION_COOKIE))
        )
    )
    if invalidate == "expired":
        session.created_at = datetime.now(UTC) - timedelta(hours=2)
        session.expires_at = datetime.now(UTC) - timedelta(hours=1)
    elif invalidate == "revoked":
        session.revoked_at = datetime.now(UTC)
    else:
        account[0].is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_runtime_audit_and_snapshots_are_append_only(db):
    for table in ("audit_events", "schema_snapshots"):
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            assert not db.scalar(
                text("SELECT has_table_privilege(current_user, :table, :privilege)"),
                {"table": table, "privilege": privilege},
            )
    with pytest.raises(DBAPIError):
        db.execute(text("UPDATE audit_events SET event_type = 'tampered' WHERE false"))
    db.rollback()
    with pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM audit_events WHERE false"))
    db.rollback()


@pytest.mark.parametrize(
    "role,email", [("OWNER", "valid@example.com"), ("ADMIN", "UPPER@example.com")]
)
def test_database_rejects_invalid_user_values(db, role, email):
    with pytest.raises(IntegrityError):
        db.add(User(email=email, role=role, password_hash="test-invalid-hash"))
        db.flush()
    db.rollback()


def test_foreign_keys_and_sampling_bounds_are_enforced(db, account):
    connection = DatabaseConnection(
        name=f"test-{uuid.uuid4().hex}",
        host="synthetic.invalid",
        database_name="demo",
        scanner_username="scanner",
        scanner_password_ciphertext="test-only-not-a-secret",
        created_by=account[0].id,
    )
    db.add(connection)
    db.flush()
    snapshot = SchemaSnapshot(
        connection_id=connection.id, fingerprint="a" * 64, catalog={"tables": []}
    )
    db.add(snapshot)
    db.flush()
    for sample_limit in [0, 10001]:
        with pytest.raises(IntegrityError), db.begin_nested():
            db.add(
                ScanJob(
                    connection_id=connection.id,
                    snapshot_id=snapshot.id,
                    requested_by=account[0].id,
                    sample_limit=sample_limit,
                )
            )
            db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(
            ScanJob(
                connection_id=uuid.uuid4(),
                snapshot_id=snapshot.id,
                requested_by=account[0].id,
            )
        )
        db.flush()
    db.rollback()  # Unique fixture graph remains entirely uncommitted.


def test_bootstrap_admin_is_atomic_and_does_not_overwrite(db):
    email = f"bootstrap-{uuid.uuid4().hex}@example.com"
    password = secrets.token_urlsafe(24)
    create_admin(email.upper(), password)
    user = db.scalar(select(User).where(User.email == email))
    assert user is not None and user.role == "ADMIN"
    assert (
        db.scalar(
            select(AuditEvent.id).where(
                AuditEvent.actor_id == user.id,
                AuditEvent.event_type == "ADMIN_BOOTSTRAPPED",
            )
        )
        is not None
    )
    with pytest.raises(ValueError, match="already exists"):
        create_admin(email, secrets.token_urlsafe(24))


def test_scan_snapshot_must_belong_to_the_same_connection(db, account):
    connections = [
        DatabaseConnection(
            name=f"test-{uuid.uuid4().hex}",
            host="synthetic.invalid",
            database_name="demo",
            scanner_username="scanner",
            scanner_password_ciphertext="test-only-not-a-secret",
            created_by=account[0].id,
        )
        for _ in range(2)
    ]
    db.add_all(connections)
    db.flush()
    snapshot = SchemaSnapshot(
        connection_id=connections[0].id,
        fingerprint="b" * 64,
        catalog={"tables": []},
    )
    db.add(snapshot)
    db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(
            ScanJob(
                connection_id=connections[1].id,
                snapshot_id=snapshot.id,
                requested_by=account[0].id,
            )
        )
        db.flush()
    db.add(
        ScanJob(
            connection_id=connections[0].id,
            snapshot_id=snapshot.id,
            requested_by=account[0].id,
        )
    )
    db.flush()  # The same snapshot is valid for its actual connection.
    db.rollback()


def test_worker_roundtrip():
    from app.workers.celery_app import celery_app

    marker = f"foundation-{uuid.uuid4().hex}"
    result = celery_app.send_task("privacyshield.smoke", args=[marker])
    try:
        assert result.get(timeout=30) == {"status": "ok", "message": marker}
    finally:
        result.forget()

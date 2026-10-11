"""Account management against real PostgreSQL: who may do it, and what it changes.

Every test creates its own accounts. Rows created by other tests are left alone.
"""

import json
import secrets
import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AuditEvent, User, UserSession

pytestmark = pytest.mark.integration

BASE_URL = "http://localhost:8080"


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def clients(monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    opened = []

    def sign_in(email: str, password: str, *, expect: int = 200):
        client = TestClient(app, base_url=BASE_URL)
        opened.append(client)
        response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert response.status_code == expect, response.text
        if expect == 200:
            client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        return client

    yield sign_in
    for client in opened:
        client.close()


@pytest.fixture
def admin(db, clients):
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"users-admin-{uuid.uuid4().hex}@example.com",
        role="ADMIN",
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    client = clients(user.email, password)
    client.account = {"id": str(user.id), "email": user.email, "password": password}
    return client


def _new(role="ANALYST"):
    return {
        "email": f"Users-{uuid.uuid4().hex}@Example.com",
        "role": role,
        "password": secrets.token_urlsafe(18),
    }


def _events(db, subject_id):
    db.expire_all()
    rows = db.execute(
        select(AuditEvent.event_type, AuditEvent.actor_id)
        .where(AuditEvent.subject_type == "user", AuditEvent.subject_id == uuid.UUID(subject_id))
        .order_by(AuditEvent.created_at, AuditEvent.id)
    ).all()
    return [(row.event_type, str(row.actor_id)) for row in rows]


def test_an_administrator_creates_an_account_that_can_sign_in_with_its_role(admin, clients, db):
    payload = _new("ANALYST")
    response = admin.post("/api/v1/users", json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body) == {"id", "email", "role", "is_active", "created_at"}
    assert body["email"] == payload["email"].lower() and body["role"] == "ANALYST"
    assert body["is_active"] is True
    assert payload["password"] not in response.text and "hash" not in response.text.lower()
    assert _events(db, body["id"]) == [("USER_CREATED_AS_ANALYST", admin.account["id"])]

    analyst = clients(payload["email"].lower(), payload["password"])
    assert analyst.get("/api/v1/auth/me").json()["role"] == "ANALYST"
    # The stored value is a hash, never the password.
    stored = db.scalar(select(User.password_hash).where(User.id == uuid.UUID(body["id"])))
    assert stored.startswith("$argon2") and payload["password"] not in stored

    listed = admin.get("/api/v1/users?page_size=100")
    assert listed.status_code == 200
    assert "password" not in listed.text.lower()
    page = listed.json()
    assert page["total"] >= 2 and {"items", "total", "page", "page_size"} == set(page)


@pytest.mark.parametrize("role", ["ANALYST", "AUDITOR"])
def test_only_administrators_may_see_or_change_accounts(admin, clients, role):
    payload = _new(role)
    created = admin.post("/api/v1/users", json=payload).json()
    member = clients(payload["email"].lower(), payload["password"])
    assert member.get("/api/v1/users").status_code == 403
    assert member.post("/api/v1/users", json=_new()).status_code == 403
    # Not even their own account: a role cannot be raised from inside it.
    own = member.patch(f"/api/v1/users/{created['id']}", json={"role": "ADMIN"})
    assert own.status_code == 403
    with TestClient(app, base_url=BASE_URL) as anonymous:
        assert anonymous.get("/api/v1/users").status_code == 401
        assert anonymous.post("/api/v1/users", json=_new()).status_code == 401


def test_requests_are_validated_and_never_echo_the_password(admin, db):
    taken = _new()
    assert admin.post("/api/v1/users", json=taken).status_code == 201
    again = admin.post("/api/v1/users", json=taken | {"email": taken["email"].upper()})
    assert again.status_code == 409 and again.json() == {"detail": "EMAIL_IN_USE"}

    weak = "short-pw"
    for bad in (
        _new() | {"password": weak},
        _new() | {"password": "x" * 129},
        _new() | {"role": "OWNER"},
        _new() | {"email": "not-an-address"},
        _new() | {"is_admin": True},
    ):
        response = admin.post("/api/v1/users", json=bad)
        assert response.status_code == 422, bad
        assert bad["password"] not in response.text
    created = admin.post("/api/v1/users", json=_new()).json()
    assert admin.patch(f"/api/v1/users/{created['id']}", json={}).status_code == 422
    assert admin.patch(f"/api/v1/users/{created['id']}", json={"password": weak}).status_code == 422
    assert admin.patch(f"/api/v1/users/{uuid.uuid4()}", json={"role": "AUDITOR"}).status_code == 404

    # A state-changing request without the CSRF token is refused.
    token = admin.headers.pop("X-CSRF-Token")
    try:
        assert admin.post("/api/v1/users", json=_new()).status_code == 403
    finally:
        admin.headers["X-CSRF-Token"] = token


def test_a_role_change_takes_effect_on_the_next_request(admin, clients, db):
    payload = _new("ANALYST")
    created = admin.post("/api/v1/users", json=payload).json()
    member = clients(payload["email"].lower(), payload["password"])
    scans = "/api/v1/scans?page=1&page_size=1"
    assert member.get(scans).status_code == 200

    changed = admin.patch(f"/api/v1/users/{created['id']}", json={"role": "AUDITOR"})
    assert changed.status_code == 200 and changed.json()["role"] == "AUDITOR"
    assert member.get("/api/v1/auth/me").json()["role"] == "AUDITOR"
    # Saying the same thing again changes nothing and records nothing.
    assert (
        admin.patch(f"/api/v1/users/{created['id']}", json={"role": "AUDITOR"}).status_code == 200
    )
    assert _events(db, created["id"]) == [
        ("USER_CREATED_AS_ANALYST", admin.account["id"]),
        # The log has no details, so the event type itself says which role was given.
        ("USER_ROLE_SET_AUDITOR", admin.account["id"]),
    ]


def test_deactivating_signs_the_person_out_and_reactivating_lets_them_back(admin, clients, db):
    payload = _new("AUDITOR")
    email = payload["email"].lower()
    created = admin.post("/api/v1/users", json=payload).json()
    member = clients(email, payload["password"])
    assert member.get("/api/v1/auth/me").status_code == 200

    off = admin.patch(f"/api/v1/users/{created['id']}", json={"is_active": False})
    assert off.status_code == 200 and off.json()["is_active"] is False
    assert member.get("/api/v1/auth/me").status_code == 401
    clients(email, payload["password"], expect=401)
    db.expire_all()
    open_sessions = db.scalars(
        select(UserSession.id).where(
            UserSession.user_id == uuid.UUID(created["id"]), UserSession.revoked_at.is_(None)
        )
    ).all()
    assert open_sessions == []

    on = admin.patch(f"/api/v1/users/{created['id']}", json={"is_active": True})
    assert on.status_code == 200 and on.json()["is_active"] is True
    # The old session stays revoked; signing in again works.
    assert member.get("/api/v1/auth/me").status_code == 401
    assert clients(email, payload["password"]).get("/api/v1/auth/me").status_code == 200
    assert [event for event, _ in _events(db, created["id"])] == [
        "USER_CREATED_AS_AUDITOR",
        "USER_DEACTIVATED",
        "USER_REACTIVATED",
    ]


def test_a_password_reset_replaces_the_password_and_ends_existing_sessions(admin, clients, db):
    payload = _new("ANALYST")
    email = payload["email"].lower()
    created = admin.post("/api/v1/users", json=payload).json()
    member = clients(email, payload["password"])
    replacement = secrets.token_urlsafe(18)

    reset = admin.patch(f"/api/v1/users/{created['id']}", json={"password": replacement})
    assert reset.status_code == 200 and replacement not in reset.text
    assert member.get("/api/v1/auth/me").status_code == 401
    clients(email, payload["password"], expect=401)
    assert clients(email, replacement).get("/api/v1/auth/me").status_code == 200
    assert _events(db, created["id"])[-1] == ("USER_PASSWORD_RESET", admin.account["id"])
    # Nothing about the password reaches the audit log.
    db.expire_all()
    details = db.scalars(
        select(AuditEvent.details).where(AuditEvent.subject_id == uuid.UUID(created["id"]))
    ).all()
    assert details and all(item == {} for item in details)


def test_an_administrator_changing_their_own_password_keeps_only_this_session(admin, clients):
    elsewhere = clients(admin.account["email"], admin.account["password"])
    replacement = secrets.token_urlsafe(18)
    own = admin.patch(f"/api/v1/users/{admin.account['id']}", json={"password": replacement})
    assert own.status_code == 200
    assert admin.get("/api/v1/auth/me").status_code == 200
    assert elsewhere.get("/api/v1/auth/me").status_code == 401
    clients(admin.account["email"], admin.account["password"], expect=401)
    clients(admin.account["email"], replacement)


def test_an_administrator_cannot_remove_their_own_access(admin, db):
    for change in (
        {"is_active": False},
        {"role": "ANALYST"},
        {"role": "AUDITOR", "is_active": True},
    ):
        response = admin.patch(f"/api/v1/users/{admin.account['id']}", json=change)
        assert response.status_code == 409 and response.json() == {"detail": "OWN_ACCESS"}
    db.expire_all()
    own = db.get(User, uuid.UUID(admin.account["id"]))
    assert own.role == "ADMIN" and own.is_active is True
    assert _events(db, admin.account["id"]) == []
    assert admin.get("/api/v1/auth/me").status_code == 200


def test_the_last_administrator_cannot_be_demoted_or_deactivated(admin, db, monkeypatch):
    """Unreachable by one request, since the actor stays an administrator. Forced here."""
    other = _new("ADMIN")
    created = admin.post("/api/v1/users", json=other).json()
    monkeypatch.setattr("app.services.users._other_active_admins", lambda db, user_id: 0)
    for change in ({"role": "ANALYST"}, {"is_active": False}):
        response = admin.patch(f"/api/v1/users/{created['id']}", json=change)
        assert response.status_code == 409 and response.json() == {"detail": "LAST_ADMIN"}
    # A change that leaves them an administrator is still allowed.
    assert (
        admin.patch(
            f"/api/v1/users/{created['id']}", json={"password": secrets.token_urlsafe(18)}
        ).status_code
        == 200
    )
    db.expire_all()
    kept = db.get(User, uuid.UUID(created["id"]))
    assert kept.role == "ADMIN" and kept.is_active is True


def test_two_administrators_demoting_each_other_cannot_both_succeed(admin, clients, db):
    other = _new("ADMIN")
    created = admin.post("/api/v1/users", json=other).json()
    second = clients(other["email"].lower(), other["password"])

    def demote(results, start, name, client, target):
        start.wait(10)
        results[name] = client.patch(f"/api/v1/users/{target}", json={"role": "ANALYST"})

    for _ in range(5):
        results = {}
        start = threading.Barrier(2)
        threads = [
            threading.Thread(target=demote, args=(results, start, "first", admin, created["id"])),
            threading.Thread(
                target=demote, args=(results, start, "second", second, admin.account["id"])
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        codes = sorted(response.status_code for response in results.values())
        # Whoever went second found they were no longer an administrator.
        assert codes == [200, 403], {name: r.text for name, r in results.items()}
        db.expire_all()
        pair = db.scalars(
            select(User).where(
                User.id.in_([uuid.UUID(created["id"]), uuid.UUID(admin.account["id"])])
            )
        ).all()
        assert sum(user.role == "ADMIN" and user.is_active for user in pair) == 1
        # Put both back for the next round, directly: neither can promote the other now.
        for user in pair:
            user.role = "ADMIN"
        db.commit()


def test_creating_an_administrator_is_recorded_as_exactly_that(admin, db):
    created = admin.post("/api/v1/users", json=_new("ADMIN")).json()
    promoted = admin.post("/api/v1/users", json=_new("AUDITOR")).json()
    assert admin.patch(f"/api/v1/users/{promoted['id']}", json={"role": "ADMIN"}).status_code == 200
    assert _events(db, created["id"]) == [("USER_CREATED_AS_ADMIN", admin.account["id"])]
    assert [event for event, _ in _events(db, promoted["id"])] == [
        "USER_CREATED_AS_AUDITOR",
        "USER_ROLE_SET_ADMIN",
    ]


def test_an_administrator_removed_while_their_request_is_running_creates_nothing(
    admin, clients, db, monkeypatch
):
    """Hashing the new password takes time. Access taken away meanwhile must count."""
    other = _new("ADMIN")
    assert admin.post("/api/v1/users", json=other).status_code == 201
    second = clients(other["email"].lower(), other["password"])
    from app.services import users as service

    real_hash = service.hash_password
    for change in ({"is_active": False}, {"is_active": True, "role": "AUDITOR"}):
        attempted = _new("ADMIN")

        def slow_hash(password, change=change):
            encoded = real_hash(password)
            # While the first administrator's request is still hashing, the second
            # one takes their access away.
            done = second.patch(f"/api/v1/users/{admin.account['id']}", json=change)
            assert done.status_code == 200, done.text
            return encoded

        monkeypatch.setattr(service, "hash_password", slow_hash)
        response = admin.post("/api/v1/users", json=attempted)
        monkeypatch.setattr(service, "hash_password", real_hash)
        assert response.status_code in (401, 403), response.text
        db.expire_all()
        assert db.scalar(select(User.id).where(User.email == attempted["email"].lower())) is None
        # Restore the first administrator for the next round and for the fixture.
        restore = db.get(User, uuid.UUID(admin.account["id"]))
        restore.role, restore.is_active = "ADMIN", True
        db.commit()


@pytest.mark.parametrize("change", ["reset", "deactivate"])
def test_a_sign_in_that_overlaps_a_reset_or_deactivation_gets_no_session(
    admin, clients, db, monkeypatch, change
):
    """The password check is slow; what an administrator did during it must win."""
    payload = _new("ANALYST")
    email = payload["email"].lower()
    created = admin.post("/api/v1/users", json=payload).json()
    from app.api import auth

    real_verify = auth.verify_password
    replacement = secrets.token_urlsafe(18)
    body = {"password": replacement} if change == "reset" else {"is_active": False}

    def slow_verify(password, encoded):
        matched = real_verify(password, encoded)
        done = admin.patch(f"/api/v1/users/{created['id']}", json=body)
        assert done.status_code == 200, done.text
        return matched

    monkeypatch.setattr(auth, "verify_password", slow_verify)
    overlapping = clients(email, payload["password"], expect=401)
    monkeypatch.setattr(auth, "verify_password", real_verify)
    assert overlapping.get("/api/v1/auth/me").status_code == 401
    db.expire_all()
    live = db.scalars(
        select(UserSession.id).where(
            UserSession.user_id == uuid.UUID(created["id"]), UserSession.revoked_at.is_(None)
        )
    ).all()
    assert live == []
    if change == "reset":
        # The reset stands: it was not overwritten by the overlapping sign-in.
        assert clients(email, replacement).get("/api/v1/auth/me").status_code == 200
    else:
        assert (
            admin.patch(f"/api/v1/users/{created['id']}", json={"is_active": True}).status_code
            == 200
        )
        assert overlapping.get("/api/v1/auth/me").status_code == 401


def test_a_password_that_cannot_be_hashed_is_refused_not_an_error(admin):
    unpaired = "\ud800" + "a" * 16  # A lone surrogate: valid JSON, not valid text.
    created = admin.post("/api/v1/users", json=_new()).json()

    def send(method, path, body):
        # Sent as escaped JSON, the way a hostile client would: the test client
        # itself cannot encode this string.
        return admin.request(
            method, path, content=json.dumps(body), headers={"Content-Type": "application/json"}
        )

    assert send("POST", "/api/v1/users", _new() | {"password": unpaired}).status_code == 422
    patched = send("PATCH", f"/api/v1/users/{created['id']}", {"password": unpaired})
    assert patched.status_code == 422
    # Signing in with such a value is a wrong password, not a server error.
    with TestClient(app, base_url=BASE_URL) as anonymous:
        attempt = anonymous.post(
            "/api/v1/auth/login",
            content=json.dumps({"email": created["email"], "password": unpaired}),
            headers={"Content-Type": "application/json"},
        )
        assert attempt.status_code == 401


def test_startup_leaves_a_deactivated_configured_administrator_alone_and_says_so(admin, db, caplog):
    from app.render_seed import ensure_admin

    configured = _new("ADMIN")
    created = admin.post("/api/v1/users", json=configured).json()
    assert ensure_admin(configured["email"], "another-password-123") is False
    assert "no longer an active administrator" not in caplog.text
    assert (
        admin.patch(f"/api/v1/users/{created['id']}", json={"is_active": False}).status_code == 200
    )
    caplog.clear()
    with caplog.at_level("WARNING", logger="privacyshield"):
        assert ensure_admin(configured["email"], "another-password-123") is False
    assert "no longer an active administrator" in caplog.text
    db.expire_all()
    assert db.get(User, uuid.UUID(created["id"])).is_active is False

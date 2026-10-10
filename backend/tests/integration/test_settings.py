"""Real PostgreSQL integration for operator settings and custom detection patterns.

The settings row is a process-wide singleton; tests configure their own state via
bounded PATCH rather than assuming defaults, and never delete audit history.
"""

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AppSettings, AuditEvent, CustomPattern, User
from app.services.settings.service import enabled_custom_patterns

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def login(db, monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    clients = []

    def create(role="ADMIN"):
        password = secrets.token_urlsafe(24)
        user = User(
            email=f"settings-{uuid.uuid4().hex}@example.com",
            role=role,
            password_hash=hash_password(password),
        )
        db.add(user)
        db.commit()
        client = TestClient(app, base_url="http://localhost:8080")
        clients.append(client)
        response = client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": password}
        )
        assert response.status_code == 200, response.text
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        return client, user

    yield create
    for client in clients:
        client.close()


def _pattern(name, category="PII", regex=r"\bE[0-9]{6}\b", enabled=True):
    return {"name": name, "category": category, "regex": regex, "enabled": enabled}


def test_get_creates_singleton_and_returns_only_bounded_fields(login, db):
    client, _ = login("ANALYST")
    response = client.get("/api/v1/settings")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"workspace_name", "retention_days", "custom_patterns"}
    assert isinstance(body["workspace_name"], str) and body["workspace_name"]
    assert isinstance(body["retention_days"], int)
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(AppSettings)) == 1
    # Reading twice is idempotent and never exposes credentials or actor ids.
    assert client.get("/api/v1/settings").json() == body
    assert "password" not in response.text.lower()


def test_admin_patch_updates_every_field_and_records_audit(login, db):
    client, admin = login("ADMIN")
    name = f"Workspace {uuid.uuid4().hex[:8]}"
    patterns = [
        _pattern(f"emp-{uuid.uuid4().hex[:8]}", "PII"),
        _pattern(f"acct-{uuid.uuid4().hex[:8]}", "FINANCIAL", r"ACCT-[0-9]{6}", enabled=False),
    ]
    response = client.patch(
        "/api/v1/settings",
        json={"workspace_name": name, "retention_days": 90, "custom_patterns": patterns},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["workspace_name"] == name
    assert body["retention_days"] == 90
    assert {pattern["category"] for pattern in body["custom_patterns"]} == {"PII", "FINANCIAL"}
    expected_keys = {"id", "name", "category", "regex", "enabled"}
    assert all(set(pattern) == expected_keys for pattern in body["custom_patterns"])

    db.expire_all()
    stored = db.scalars(
        select(CustomPattern).where(CustomPattern.name.in_([p["name"] for p in patterns]))
    ).all()
    assert {row.name for row in stored} == {p["name"] for p in patterns}
    assert db.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.actor_id == admin.id, AuditEvent.event_type == "SETTINGS_UPDATED")
    ) >= 1
    # The GET path reflects the committed mutation.
    assert client.get("/api/v1/settings").json()["workspace_name"] == name


def test_patch_replaces_the_pattern_collection(login):
    client, _ = login("ADMIN")
    first = f"first-{uuid.uuid4().hex[:8]}"
    second = f"second-{uuid.uuid4().hex[:8]}"
    assert client.patch(
        "/api/v1/settings", json={"custom_patterns": [_pattern(first)]}
    ).status_code == 200
    replaced = client.patch("/api/v1/settings", json={"custom_patterns": [_pattern(second)]})
    assert replaced.status_code == 200, replaced.text
    names = {pattern["name"] for pattern in replaced.json()["custom_patterns"]}
    assert names == {second}


def test_pattern_can_be_updated_in_place_by_id(login):
    client, _ = login("ADMIN")
    name = f"edit-{uuid.uuid4().hex[:8]}"
    created = client.patch(
        "/api/v1/settings", json={"custom_patterns": [_pattern(name)]}
    ).json()["custom_patterns"][0]
    updated = client.patch(
        "/api/v1/settings",
        json={
            "custom_patterns": [
                {
                    "id": created["id"],
                    "name": name,
                    "category": "HEALTH",
                    "regex": r"\bH[0-9]{4}\b",
                    "enabled": False,
                }
            ]
        },
    )
    assert updated.status_code == 200, updated.text
    body = updated.json()["custom_patterns"][0]
    assert body["id"] == created["id"]
    assert body["category"] == "HEALTH" and body["enabled"] is False


def test_enabled_patterns_helper_excludes_disabled_rows(login, db):
    client, _ = login("ADMIN")
    live = f"live-{uuid.uuid4().hex[:8]}"
    off = f"off-{uuid.uuid4().hex[:8]}"
    client.patch(
        "/api/v1/settings",
        json={"custom_patterns": [_pattern(live), _pattern(off, enabled=False)]},
    )
    db.expire_all()
    rows = enabled_custom_patterns(db)
    assert live in {name for name, _, _ in rows}
    assert off not in {name for name, _, _ in rows}
    assert len(rows) <= 20


@pytest.mark.parametrize("role", ["ANALYST", "AUDITOR"])
def test_non_admin_cannot_patch_but_can_read(login, role):
    client, _ = login(role)
    assert client.get("/api/v1/settings").status_code == 200
    assert client.patch("/api/v1/settings", json={"retention_days": 30}).status_code == 403


def test_patch_requires_csrf(login):
    client, _ = login("ADMIN")
    response = client.patch(
        "/api/v1/settings", json={"retention_days": 30}, headers={"X-CSRF-Token": "invalid"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"retention_days": 0},
        {"retention_days": 3651},
        {"workspace_name": ""},
        {"workspace_name": None},
        {"retention_days": None},
        {"custom_patterns": [{"name": "bad", "category": "PII", "regex": "(unclosed"}]},
        {"custom_patterns": [{"name": "bad", "category": "SECRET", "regex": "x[0-9]"}]},
        {"custom_patterns": [{"name": "x" * 61, "category": "PII", "regex": "x[0-9]"}]},
        {
            "custom_patterns": [
                {"name": f"p{index}", "category": "PII", "regex": f"[{index}]{4}"}
                for index in range(21)
            ]
        },
    ],
)
def test_invalid_patch_returns_422_without_echoing_input(login, payload):
    client, _ = login("ADMIN")
    response = client.patch("/api/v1/settings", json=payload)
    assert response.status_code == 422, response.text
    assert "unclosed" not in response.text


def test_duplicate_pattern_names_conflict(login):
    client, _ = login("ADMIN")
    name = f"dup-{uuid.uuid4().hex[:8]}"
    response = client.patch(
        "/api/v1/settings", json={"custom_patterns": [_pattern(name), _pattern(name)]}
    )
    assert response.status_code == 409, response.text


def test_unknown_pattern_id_is_rejected(login):
    client, _ = login("ADMIN")
    response = client.patch(
        "/api/v1/settings",
        json={
            "custom_patterns": [
                {"id": str(uuid.uuid4()), "name": "ghost", "category": "PII", "regex": "x[0-9]"}
            ]
        },
    )
    assert response.status_code == 422, response.text

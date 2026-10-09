import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.auth import LoginThrottle
from app.api.dependencies import require_roles
from app.core.config import get_settings
from app.main import app
from app.models import User


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def test_liveness_is_independent_of_database(client):
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["Cache-Control"] == "no-store"


def test_protected_routes_deny_anonymous(client):
    for path in ["/api/v1/auth/me", "/api/v1/dashboard/summary"]:
        assert client.get(path).status_code == 401


def test_validation_response_does_not_echo_credentials(client):
    secret = "secret-value-" * 30
    response = client.post("/api/v1/auth/login", json={"email": "bad", "password": secret})
    assert response.status_code == 422
    assert secret not in response.text
    assert "input" not in response.text


def test_cross_origin_login_is_rejected_before_database(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "test password"},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("role,allowed", [("ADMIN", True), ("ANALYST", False), ("AUDITOR", False)])
def test_admin_guard_rejects_other_roles(role, allowed):
    user = User(id=uuid.uuid4(), email="test@example.com", password_hash="unused", role=role)
    guard = require_roles("ADMIN")
    if allowed:
        assert guard(user) is user
    else:
        with pytest.raises(HTTPException) as exc:
            guard(user)
        assert exc.value.status_code == 403


def test_login_throttle_has_bounded_attempts():
    throttle = LoginThrottle()
    for _ in range(get_settings().login_attempt_limit):
        throttle.check("unit-test")
    with pytest.raises(HTTPException) as exc:
        throttle.check("unit-test")
    assert exc.value.status_code == 429

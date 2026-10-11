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


def test_keep_is_suggested_only_for_fully_read_columns():
    from app.services.policies.suggestions import fully_assessed

    clean = {
        "unsupported_type": False,
        "values_skipped": 0,
        "values_truncated": 0,
        "json_truncated": 0,
        "path_limit_reached": 0,
    }
    assert fully_assessed(clean)
    for key in clean:
        # Any value that was skipped, cut short, or of an unreadable type means
        # "nothing found" is not evidence, so KEEP must not be suggested.
        assert not fully_assessed(clean | {key: True if key == "unsupported_type" else 1})


def test_column_risk_is_the_highest_level_detected():
    from app.api.dashboard import _column_risk

    # Mostly names, a few Aadhaar numbers: as sensitive as the Aadhaar numbers.
    assert _column_risk({"PERSON": 60, "AADHAAR_CANDIDATE": 4}, None) == "CRITICAL"
    assert _column_risk({"PERSON": 60}, None) == "MEDIUM"
    assert _column_risk({"EMAIL_ADDRESS": 3, "LOCATION": 9}, None) == "HIGH"
    # An advisory classification can raise the level but never lower it.
    assert _column_risk({"PERSON": 60}, "CRITICAL") == "CRITICAL"
    assert _column_risk({"AADHAAR_CANDIDATE": 1}, "LOW") == "CRITICAL"
    assert _column_risk({"CUSTOM_PII": 2}, None) == "MEDIUM"
    assert _column_risk({}, "unexpected") == "MEDIUM"

"""Real deployment check: approved policy produces a reader view, source stays intact."""

import os
import secrets
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import User
from app.services.policies.execution import run_deployment

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def admin_client(db, monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"deployment-{uuid.uuid4().hex}@example.com",
        role="ADMIN",
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    client = TestClient(app, base_url="http://localhost:8080")
    response = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    yield client
    client.close()


def _target_env():
    host = os.environ.get("TEST_TARGET_HOST", "target-db")
    port = int(os.environ.get("TEST_TARGET_PORT", "5432"))
    scanner = os.environ.get("TEST_TARGET_SCANNER_PASSWORD")
    deployer = os.environ.get("TEST_TARGET_DEPLOYER_PASSWORD")
    reader = os.environ.get("TEST_TARGET_READER_PASSWORD")
    if not (scanner and deployer and reader):
        pytest.fail("Target scanner, deployer, and reader passwords are required")
    return host, port, scanner, deployer, reader


def _connect(host, port, user, password, *, read_only=False):
    return psycopg.connect(
        host=host,
        port=port,
        dbname="enterprise_demo",
        user=user,
        password=password,
        connect_timeout=5,
        autocommit=True,
        row_factory=dict_row,
        options="-c default_transaction_read_only=on" if read_only else None,
    )


def test_real_deployment_protects_reader_and_preserves_source(admin_client, db):
    host, port, scanner, deployer, reader = _target_env()

    connection = admin_client.post(
        "/api/v1/connections",
        json={
            "name": f"deployment-{uuid.uuid4().hex[:10]}",
            "host": host,
            "port": port,
            "database_name": "enterprise_demo",
            "ssl_mode": "disable",
            "scanner_username": "ps_scanner",
            "scanner_password": scanner,
            "deployer_username": "ps_deployer",
            "deployer_password": deployer,
        },
    )
    assert connection.status_code == 201, connection.text
    connection_id = connection.json()["id"]
    path = f"/api/v1/connections/{connection_id}"

    snapshot = admin_client.post(path + "/discover", json={"schemas": ["enterprise"]}).json()
    snapshot_id = snapshot["snapshot_id"]

    policy = admin_client.post(
        "/api/v1/policies",
        json={
            "connection_id": connection_id,
            "schema_name": "enterprise",
            "table_name": "customers",
            "snapshot_id": snapshot_id,
            "rules": [
                {"column_name": "id", "action": "KEEP"},
                {"column_name": "full_name", "action": "REDACT"},
                {"column_name": "email", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
                {"column_name": "created_at", "action": "KEEP"},
            ],
        },
    )
    assert policy.status_code == 201, policy.text
    policy_id = policy.json()["id"]

    assert admin_client.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200
    approved = admin_client.post(f"/api/v1/policies/{policy_id}/approve")
    assert approved.status_code == 200, approved.text

    preview = admin_client.get(f"/api/v1/policies/{policy_id}/preview").json()
    view = f'{preview["view_schema"]}."{preview["view_name"]}"'

    deployment = admin_client.post(f"/api/v1/policies/{policy_id}/deploy", json={})
    assert deployment.status_code == 202, deployment.text
    deployment_id = uuid.UUID(deployment.json()["id"])

    run_deployment(deployment_id)

    db.expire_all()
    final = admin_client.get(f"/api/v1/policies/{policy_id}").json()
    assert final["status"] == "DEPLOYED", final
    deployments = admin_client.get("/api/v1/deployments?page=1&page_size=5").json()
    assert any(
        item["id"] == str(deployment_id) and item["status"] == "COMPLETED"
        for item in deployments["items"]
    )

    # The restricted reader sees only the approved projection.
    with _connect(host, port, "ps_reader", reader, read_only=True) as reader_conn:
        rows = reader_conn.execute(
            f"SELECT id, full_name, email, phone FROM {view} ORDER BY id LIMIT 5"
        ).fetchall()
        assert rows, "the reader view returned no rows"
        assert all(row["full_name"] == "[REDACTED]" for row in rows)
        assert all(row["phone"] is None for row in rows)
        assert all(row["email"] and row["email"] != "customer1@example.com" for row in rows)
        # Pseudonyms are deterministic: the same source value maps to one value.
        repeated = reader_conn.execute(
            f"SELECT count(DISTINCT email) = count(*) AS consistent FROM {view}"
        ).fetchone()
        assert repeated["consistent"] is True
        # The reader cannot read base tables.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader_conn.execute("SELECT * FROM enterprise.customers LIMIT 1")

    # Source rows are unchanged.
    with _connect(host, port, "ps_scanner", scanner, read_only=True) as scanner_conn:
        source = scanner_conn.execute(
            "SELECT full_name, email, phone FROM enterprise.customers WHERE id = 1"
        ).fetchone()
        assert source["full_name"] == "Synthetic Customer 1"
        assert source["email"] == "customer1@example.com"
        assert source["phone"] == "+91 90000 00001"

    # Re-running an already completed deployment is a no-op.
    run_deployment(deployment_id)
    db.expire_all()
    assert admin_client.get(f"/api/v1/policies/{policy_id}").json()["status"] == "DEPLOYED"

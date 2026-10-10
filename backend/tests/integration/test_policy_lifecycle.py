"""Real PostgreSQL/Redis integration tests for policy approval and deployment.

These exercise the control-plane lifecycle through the API. Actual target DDL is
covered separately by the deployment acceptance checks; here we verify durable
state, RBAC, immutable decisions, and idempotency.
"""

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import encrypt_credential, hash_password
from app.main import app
from app.models import (
    DatabaseConnection,
    PolicyApproval,
    PolicyDeployment,
    SchemaSnapshot,
    User,
)
from app.services.discovery.catalog import catalog_fingerprint

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


def _account(db, role):
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"policy-{role.lower()}-{uuid.uuid4().hex}@example.com",
        role=role,
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    return user, password


@pytest.fixture
def admin_user(db):
    return _account(db, "ADMIN")


@pytest.fixture
def analyst_user(db):
    return _account(db, "ANALYST")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    with TestClient(app, base_url="http://localhost:8080") as client:
        yield client


def login(client, email, password):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return response


def _fixture(db, admin, *, table, columns):
    connection = DatabaseConnection(
        name=f"policy-{uuid.uuid4().hex[:10]}",
        host="target-db",
        port=5432,
        database_name="enterprise_demo",
        ssl_mode="disable",
        scanner_username="ps_scanner",
        scanner_password_ciphertext=encrypt_credential("scanner-secret"),
        deployer_username="ps_deployer",
        deployer_password_ciphertext=encrypt_credential("deployer-secret"),
        created_by=admin.id,
    )
    db.add(connection)
    db.flush()
    catalog = {
        "schemas": ["enterprise"],
        "tables": [
            {
                "schema": "enterprise",
                "name": table,
                "oid": 1,
                "row_estimate": 100,
                "rls_enabled": False,
                "columns": columns,
                "primary_key": ["id"],
                "foreign_keys": [],
            }
        ],
    }
    snapshot = SchemaSnapshot(
        connection_id=connection.id,
        catalog=catalog,
        fingerprint=catalog_fingerprint(catalog),
    )
    db.add(snapshot)
    db.commit()
    return connection, snapshot


def _col(name, data_type, ordinal, *, pk=False, nullable=True):
    return {
        "name": name,
        "data_type": data_type,
        "udt_name": data_type.split("(")[0],
        "nullable": nullable,
        "ordinal": ordinal,
        "is_primary_key": pk,
        "is_jsonb": False,
    }


CUSTOMERS = [
    _col("id", "bigint", 1, pk=True, nullable=False),
    _col("email", "text", 2, nullable=False),
    _col("phone", "text", 3),
]
ACCOUNTS = [
    _col("id", "bigint", 1, pk=True, nullable=False),
    _col("balance", "numeric(14,2)", 2, nullable=False),
]
SUPPORT = [
    _col("id", "bigint", 1, pk=True, nullable=False),
    _col("body", "text", 2, nullable=False),
]


def _create(client, connection, snapshot, table, rules):
    response = client.post(
        "/api/v1/policies",
        json={
            "connection_id": str(connection.id),
            "schema_name": "enterprise",
            "table_name": table,
            "snapshot_id": str(snapshot.id),
            "rules": rules,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_policy_lifecycle_transitions(db, client, admin_user, analyst_user):
    admin, admin_pw = admin_user
    analyst, analyst_pw = analyst_user
    connection, snapshot = _fixture(db, admin, table="customers", columns=CUSTOMERS)

    login(client, analyst.email, analyst_pw)
    policy = _create(
        client,
        connection,
        snapshot,
        "customers",
        [
            {"column_name": "id", "action": "KEEP"},
            {"column_name": "email", "action": "PSEUDONYMIZE", "pseudonym_domain": "contact"},
            {"column_name": "phone", "action": "PARTIAL"},
        ],
    )
    assert policy["status"] == "DRAFT"
    assert policy["version"] == 1
    policy_id = policy["id"]

    submitted = client.post(f"/api/v1/policies/{policy_id}/submit")
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["status"] == "PENDING_APPROVAL"

    # An analyst cannot approve.
    assert client.post(f"/api/v1/policies/{policy_id}/approve").status_code == 403

    login(client, admin.email, admin_pw)
    approved = client.post(f"/api/v1/policies/{policy_id}/approve")
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["compiled_plan_fingerprint"]

    approval = db.scalar(
        select(PolicyApproval).where(PolicyApproval.policy_id == uuid.UUID(policy_id))
    )
    assert approval is not None and approval.decision == "APPROVED"

    deployment = client.post(f"/api/v1/policies/{policy_id}/deploy", json={})
    assert deployment.status_code == 202, deployment.text
    assert deployment.json()["status"] == "QUEUED"


def test_policy_rejection_workflow(db, client, admin_user, analyst_user):
    admin, admin_pw = admin_user
    analyst, analyst_pw = analyst_user
    connection, snapshot = _fixture(db, admin, table="accounts", columns=ACCOUNTS)

    login(client, analyst.email, analyst_pw)
    policy = _create(
        client, connection, snapshot, "accounts", [{"column_name": "id", "action": "KEEP"}]
    )
    policy_id = policy["id"]
    assert client.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200

    login(client, admin.email, admin_pw)
    rejected = client.post(f"/api/v1/policies/{policy_id}/reject")
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "REJECTED"
    approval = db.scalar(
        select(PolicyApproval).where(PolicyApproval.policy_id == uuid.UUID(policy_id))
    )
    assert approval is not None and approval.decision == "REJECTED"


def test_invalid_transitions_return_409(db, client, admin_user, analyst_user):
    admin, admin_pw = admin_user
    analyst, analyst_pw = analyst_user
    connection, snapshot = _fixture(db, admin, table="customers", columns=CUSTOMERS)

    login(client, analyst.email, analyst_pw)
    policy = _create(
        client, connection, snapshot, "customers", [{"column_name": "id", "action": "KEEP"}]
    )
    policy_id = policy["id"]

    login(client, admin.email, admin_pw)
    # Cannot approve or deploy a DRAFT policy.
    assert client.post(f"/api/v1/policies/{policy_id}/approve").status_code == 409
    assert client.post(f"/api/v1/policies/{policy_id}/deploy", json={}).status_code == 409


def test_unknown_column_is_rejected(db, client, admin_user):
    admin, admin_pw = admin_user
    connection, snapshot = _fixture(db, admin, table="customers", columns=CUSTOMERS)
    login(client, admin.email, admin_pw)
    response = client.post(
        "/api/v1/policies",
        json={
            "connection_id": str(connection.id),
            "schema_name": "enterprise",
            "table_name": "customers",
            "snapshot_id": str(snapshot.id),
            "rules": [{"column_name": "not_a_column", "action": "KEEP"}],
        },
    )
    assert response.status_code == 422


def test_idempotent_deployment(db, client, admin_user, analyst_user):
    admin, admin_pw = admin_user
    analyst, analyst_pw = analyst_user
    connection, snapshot = _fixture(db, admin, table="support_records", columns=SUPPORT)

    login(client, analyst.email, analyst_pw)
    policy = _create(
        client,
        connection,
        snapshot,
        "support_records",
        [{"column_name": "id", "action": "KEEP"}, {"column_name": "body", "action": "REDACT"}],
    )
    policy_id = policy["id"]
    client.post(f"/api/v1/policies/{policy_id}/submit")

    login(client, admin.email, admin_pw)
    client.post(f"/api/v1/policies/{policy_id}/approve")

    key = str(uuid.uuid4())
    first = client.post(f"/api/v1/policies/{policy_id}/deploy", json={"idempotency_key": key})
    assert first.status_code == 202, first.text
    second = client.post(f"/api/v1/policies/{policy_id}/deploy", json={"idempotency_key": key})
    assert second.status_code == 202, second.text
    assert first.json()["id"] == second.json()["id"]
    assert db.get(PolicyDeployment, uuid.UUID(first.json()["id"])) is not None


def test_preview_returns_compiled_view(db, client, admin_user):
    admin, admin_pw = admin_user
    connection, snapshot = _fixture(db, admin, table="customers", columns=CUSTOMERS)
    login(client, admin.email, admin_pw)
    policy = _create(
        client,
        connection,
        snapshot,
        "customers",
        [
            {"column_name": "id", "action": "KEEP"},
            {"column_name": "email", "action": "REDACT"},
            {"column_name": "phone", "action": "NULLIFY"},
        ],
    )
    response = client.get(f"/api/v1/policies/{policy['id']}/preview")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["view_schema"] == "privacyshield_masked"
    assert "security_barrier = true" in body["sql"]
    assert {column["action"] for column in body["columns"]} == {"KEEP", "REDACT", "NULLIFY"}


def test_audit_events_listed(db, client, admin_user):
    admin, admin_pw = admin_user
    login(client, admin.email, admin_pw)
    response = client.get("/api/v1/audit-events?page=1&page_size=10")
    assert response.status_code == 200, response.text
    assert "items" in response.json()

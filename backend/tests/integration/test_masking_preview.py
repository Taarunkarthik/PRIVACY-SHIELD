"""Real checks for format-aware masks, the sample preview, and deployed-output evidence."""

import os
import secrets
import time
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row
from sqlalchemy import select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AuditEvent, PolicyDeployment, User
from app.services.policies.execution import run_deployment

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


def _client(db, monkeypatch, role):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"masking-{role.lower()}-{uuid.uuid4().hex}@example.com",
        role=role,
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    client = TestClient(app, base_url="http://localhost:8080")
    response = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return client


@pytest.fixture
def admin_client(db, monkeypatch):
    client = _client(db, monkeypatch, "ADMIN")
    yield client
    client.close()


def _target_env():
    host = os.environ.get("TEST_TARGET_HOST", "target-db")
    port = int(os.environ.get("TEST_TARGET_PORT", "5432"))
    passwords = {
        name: os.environ.get(f"TEST_TARGET_{name.upper()}_PASSWORD")
        for name in ("scanner", "deployer", "reader", "superuser")
    }
    if not all(passwords.values()):
        pytest.fail("Target scanner, deployer, reader, and superuser passwords are required")
    return host, port, passwords


def _connect(host, port, user, password):
    return psycopg.connect(
        host=host,
        port=port,
        dbname="enterprise_demo",
        user=user,
        password=password,
        connect_timeout=5,
        autocommit=True,
        row_factory=dict_row,
    )


def _register(client, host, port, passwords):
    connection = client.post(
        "/api/v1/connections",
        json={
            "name": f"masking-{uuid.uuid4().hex[:10]}",
            "host": host,
            "port": port,
            "database_name": "enterprise_demo",
            "ssl_mode": "disable",
            "scanner_username": "ps_scanner",
            "scanner_password": passwords["scanner"],
            "deployer_username": "ps_deployer",
            "deployer_password": passwords["deployer"],
        },
    )
    assert connection.status_code == 201, connection.text
    connection_id = connection.json()["id"]
    snapshot = client.post(
        f"/api/v1/connections/{connection_id}/discover", json={"schemas": ["enterprise"]}
    )
    assert snapshot.status_code in (200, 201), snapshot.text
    return connection_id, snapshot.json()["snapshot_id"]


def _create_policy(client, connection_id, snapshot_id, table, rules):
    policy = client.post(
        "/api/v1/policies",
        json={
            "connection_id": connection_id,
            "schema_name": "enterprise",
            "table_name": table,
            "snapshot_id": snapshot_id,
            "rules": rules,
        },
    )
    assert policy.status_code == 201, policy.text
    return policy.json()["id"]


def _approve(client, policy_id):
    assert client.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200
    assert client.post(f"/api/v1/policies/{policy_id}/approve").status_code == 200


def _deploy(client, db, policy_id):
    deployment = client.post(f"/api/v1/policies/{policy_id}/deploy", json={})
    assert deployment.status_code == 202, deployment.text
    deployment_id = uuid.UUID(deployment.json()["id"])
    # Either this process or the isolated worker may hold the deployment lock.
    run_deployment(deployment_id)
    deadline = time.monotonic() + 30
    status = None
    while time.monotonic() < deadline:
        db.expire_all()
        status = client.get(f"/api/v1/policies/{policy_id}").json()["status"]
        if status in ("DEPLOYED", "FAILED"):
            break
        time.sleep(0.5)
    return deployment_id, status


CUSTOMER_RULES = [
    {"column_name": "id", "action": "KEEP"},
    {"column_name": "full_name", "action": "REDACT"},
    {"column_name": "email", "action": "MASK_EMAIL"},
    {"column_name": "phone", "action": "MASK_PHONE"},
    {"column_name": "pan", "action": "MASK_ID"},
    {"column_name": "aadhaar", "action": "MASK_ID"},
]


def test_format_masks_samples_and_protected_output(admin_client, db, monkeypatch):
    host, port, passwords = _target_env()
    connection_id, snapshot_id = _register(admin_client, host, port, passwords)
    policy_id = _create_policy(
        admin_client, connection_id, snapshot_id, "customers", CUSTOMER_RULES
    )

    # The sample preview works on a draft and reads no source rows: its inputs
    # are fabricated, and the outputs come from the real compiled expressions.
    samples = admin_client.get(f"/api/v1/policies/{policy_id}/preview/samples")
    assert samples.status_code == 200, samples.text
    body = samples.json()
    assert body["status"] == "OK" and body["source"] == "FABRICATED"
    names = [column["name"] for column in body["columns"]]
    assert len(body["before"]) == len(body["after"]) == 3
    first_before = dict(zip(names, body["before"][0], strict=True))
    first_after = dict(zip(names, body["after"][0], strict=True))
    assert first_before["email"] == "priya.sharma@example.com"
    assert first_after["email"] == "p***@example.com"
    assert first_after["phone"] == "+** ***** *3210"
    assert first_after["pan"] == "******234F"
    assert first_after["aadhaar"] == "**** **** 0124"
    assert first_after["full_name"] == "[REDACTED]"
    assert first_after["id"] == first_before["id"]
    # Columns without a rule are NULL after masking, whatever the input was.
    assert first_before["address"] and first_after["address"] is None
    assert "customer1@example.com" not in samples.text

    # Protected output exists only for a deployed policy.
    assert admin_client.get(f"/api/v1/policies/{policy_id}/protected-output").status_code == 409

    _approve(admin_client, policy_id)
    deployment_id, status = _deploy(admin_client, db, policy_id)
    assert status == "DEPLOYED"
    db.expire_all()
    receipt = db.get(PolicyDeployment, deployment_id).target_receipt
    assert receipt["access_verified"] is True

    preview = admin_client.get(f"/api/v1/policies/{policy_id}/preview").json()
    view = f'{preview["view_schema"]}."{preview["view_name"]}"'
    with _connect(host, port, "ps_reader", passwords["reader"]) as reader:
        row = reader.execute(
            f"SELECT full_name, email, phone, pan, aadhaar, address FROM {view} WHERE id = 7"
        ).fetchone()
        assert row == {
            "full_name": "[REDACTED]",
            "email": "c***@example.com",
            "phone": "+** ***** *0007",
            "pan": "******007F",
            "aadhaar": "**** **** 0007",
            "address": None,
        }
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("SELECT email FROM enterprise.customers LIMIT 1")

    output = admin_client.get(f"/api/v1/policies/{policy_id}/protected-output")
    assert output.status_code == 200, output.text
    evidence = output.json()
    assert evidence["access"] == {
        "reader_role": "ps_reader",
        "reader_can_read_view": True,
        "reader_can_read_source": False,
    }
    assert 1 <= len(evidence["rows"]) <= evidence["row_limit"] == 5
    columns = [column["name"] for column in evidence["columns"]]
    for values in evidence["rows"]:
        record = dict(zip(columns, values, strict=True))
        assert record["email"].endswith("***@example.com")
        assert record["full_name"] == "[REDACTED]"
        assert record["address"] is None
    # Unmasked addresses and full email local parts never reach the response.
    assert "Example Street" not in output.text
    assert "customer1@" not in output.text
    viewed = db.scalar(
        select(AuditEvent).where(
            AuditEvent.event_type == "PROTECTED_OUTPUT_VIEWED",
            AuditEvent.subject_id == uuid.UUID(policy_id),
        )
    )
    assert viewed is not None and viewed.details == {}

    # Only administrators may read rows through the deployed view.
    for role in ("ANALYST", "AUDITOR"):
        other = _client(db, monkeypatch, role)
        try:
            assert other.get(f"/api/v1/policies/{policy_id}/protected-output").status_code == 403
            assert other.get(f"/api/v1/policies/{policy_id}/preview/samples").status_code == 200
        finally:
            other.close()


def test_new_version_can_change_a_columns_output_type(admin_client, db):
    host, port, passwords = _target_env()
    connection_id, snapshot_id = _register(admin_client, host, port, passwords)
    first = _create_policy(
        admin_client,
        connection_id,
        snapshot_id,
        "accounts",
        [{"column_name": "id", "action": "KEEP"}, {"column_name": "balance", "action": "KEEP"}],
    )
    _approve(admin_client, first)
    assert _deploy(admin_client, db, first)[1] == "DEPLOYED"

    # balance was numeric through KEEP and becomes text through REDACT, which
    # CREATE OR REPLACE VIEW alone refuses.
    second = _create_policy(
        admin_client,
        connection_id,
        snapshot_id,
        "accounts",
        [
            {"column_name": "id", "action": "KEEP"},
            {"column_name": "balance", "action": "REDACT"},
            {"column_name": "account_number", "action": "MASK_ID"},
        ],
    )
    _approve(admin_client, second)
    assert _deploy(admin_client, db, second)[1] == "DEPLOYED"

    preview = admin_client.get(f"/api/v1/policies/{second}/preview").json()
    view = f'{preview["view_schema"]}."{preview["view_name"]}"'
    with _connect(host, port, "ps_reader", passwords["reader"]) as reader:
        row = reader.execute(f"SELECT balance, account_number FROM {view} WHERE id = 3").fetchone()
        assert row == {"balance": "[REDACTED]", "account_number": "************0003"}

    # The superseded version no longer describes the deployed view.
    assert admin_client.get(f"/api/v1/policies/{first}/protected-output").status_code == 409
    assert admin_client.get(f"/api/v1/policies/{second}/protected-output").status_code == 200


def test_deployment_fails_when_reader_can_reach_the_source_table(admin_client, db):
    host, port, passwords = _target_env()
    connection_id, snapshot_id = _register(admin_client, host, port, passwords)
    policy_id = _create_policy(
        admin_client,
        connection_id,
        snapshot_id,
        "support_records",
        [{"column_name": "id", "action": "KEEP"}, {"column_name": "body", "action": "REDACT"}],
    )
    _approve(admin_client, policy_id)

    with _connect(host, port, "postgres", passwords["superuser"]) as superuser:
        superuser.execute("GRANT USAGE ON SCHEMA enterprise TO ps_reader")
        superuser.execute("GRANT SELECT (body) ON enterprise.support_records TO ps_reader")
        try:
            deployment_id, status = _deploy(admin_client, db, policy_id)
            assert status == "FAILED"
            db.expire_all()
            failed = db.get(PolicyDeployment, deployment_id)
            assert failed.error_code == "ACCESS_VERIFICATION_FAILED"
            # The view and its receipt commit together, so a missing receipt
            # shows the failed attempt rolled back completely.
            receipt = superuser.execute(
                "SELECT count(*) AS n FROM privacyshield_private.deployment_receipts "
                "WHERE deployment_id = %s",
                (deployment_id,),
            ).fetchone()
            assert receipt["n"] == 0
        finally:
            superuser.execute("REVOKE SELECT (body) ON enterprise.support_records FROM ps_reader")
            superuser.execute("REVOKE USAGE ON SCHEMA enterprise FROM ps_reader")

    # With the exposure removed, the unchanged approved version deploys on retry.
    assert _deploy(admin_client, db, policy_id)[1] == "DEPLOYED"


def test_suggestions_follow_scan_findings(admin_client, db):
    host, port, passwords = _target_env()
    connection_id, snapshot_id = _register(admin_client, host, port, passwords)
    query = (
        f"/api/v1/policies/suggestions?connection_id={connection_id}"
        f"&snapshot_id={snapshot_id}&schema_name=enterprise&table_name="
    )

    # Before any scan there is no evidence, so no action is suggested.
    unscanned = admin_client.get(query + "customers")
    assert unscanned.status_code == 200, unscanned.text
    assert unscanned.json()["scan_id"] is None
    assert {c["source"] for c in unscanned.json()["columns"]} == {"NOT_SCANNED"}
    assert all(c["action"] is None for c in unscanned.json()["columns"])

    scan = admin_client.post(
        "/api/v1/scans",
        json={"connection_id": connection_id, "snapshot_id": snapshot_id, "sample_limit": 50},
    )
    assert scan.status_code == 202, scan.text
    scan_id = scan.json()["id"]
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status = admin_client.get(f"/api/v1/scans/{scan_id}").json()["status"]
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        time.sleep(0.5)
    assert status == "COMPLETED"

    body = admin_client.get(query + "customers").json()
    assert body["scan_id"] == scan_id
    by_name = {column["column_name"]: column for column in body["columns"]}
    assert by_name["email"]["action"] == "MASK_EMAIL"
    assert by_name["email"]["source"] == "DETECTOR"
    assert by_name["email"]["category"] == "EMAIL_ADDRESS"
    assert by_name["email"]["matching_rows"] == by_name["email"]["sampled_rows"] == 50
    assert by_name["phone"]["action"] == "MASK_PHONE"
    assert by_name["pan"]["action"] == "MASK_ID"
    assert by_name["aadhaar"]["action"] == "MASK_ID"
    assert by_name["full_name"]["action"] == "REDACT"
    assert by_name["address"]["action"] == "REDACT"
    # A JSON document holding an email is hidden whole, not format-masked.
    assert by_name["profile"]["action"] == "NULLIFY"
    assert by_name["id"]["action"] == "KEEP" and by_name["id"]["source"] == "NO_FINDINGS"

    # An email inside prose is redacted whole rather than format-masked.
    support = admin_client.get(query + "support_records").json()
    body_column = next(c for c in support["columns"] if c["column_name"] == "body")
    assert body_column["category"] == "EMAIL_ADDRESS" and body_column["action"] == "REDACT"

    # Suggested rules are valid policy input as they stand.
    rules = [
        {"column_name": c["column_name"], "action": c["action"]}
        for c in body["columns"]
        if c["action"]
    ]
    policy_id = _create_policy(admin_client, connection_id, snapshot_id, "customers", rules)
    assert admin_client.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200

    assert admin_client.get(query + "missing_table").status_code == 422

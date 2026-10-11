"""Real checks for format-aware masks, the sample preview, and deployed-output evidence."""

import os
import secrets
import time
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AuditEvent, PolicyDeployment, ScanJob, ScanResult, User
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


def test_dashboard_insights_match_the_overview_and_track_coverage(admin_client, db):
    host, port, passwords = _target_env()
    connection_id, snapshot_id = _register(admin_client, host, port, passwords)
    scan = admin_client.post(
        "/api/v1/scans",
        json={"connection_id": connection_id, "snapshot_id": snapshot_id, "sample_limit": 25},
    )
    assert scan.status_code == 202, scan.text
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status = admin_client.get(f"/api/v1/scans/{scan.json()['id']}").json()["status"]
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        time.sleep(0.5)
    assert status == "COMPLETED"

    before = admin_client.get("/api/v1/dashboard/insights")
    assert before.status_code == 200, before.text
    body = before.json()
    summary = admin_client.get("/api/v1/dashboard/summary").json()
    sensitive = body["coverage"]["sensitive_columns"]
    # Every breakdown describes the same set of columns as the overview total.
    assert sensitive == summary["sensitive_columns"] > 0
    assert sum(item["columns"] for item in body["categories"]) == sensitive
    assert sum(item["columns"] for item in body["risks"]) == sensitive
    assert [item["risk"] for item in body["risks"]] == ["CRITICAL", "HIGH", "MEDIUM"]
    assert 0 <= body["risks_from_ai"] <= sensitive
    assert 0 <= body["coverage"]["protected_columns"] <= sensitive
    counts = [item["columns"] for item in body["categories"]]
    assert counts == sorted(counts, reverse=True)
    assert {"EMAIL_ADDRESS", "PHONE_NUMBER"} <= {item["category"] for item in body["categories"]}
    assert [item["status"] for item in body["policy_status"]] == [
        "DRAFT",
        "PENDING_APPROVAL",
        "APPROVED",
        "DEPLOYED",
        "REJECTED",
        "FAILED",
    ]
    assert sum(item["policies"] for item in body["policy_status"]) >= 0
    assert 1 <= len(body["recent_activity"]) <= 6
    times = [event["created_at"] for event in body["recent_activity"]]
    assert times == sorted(times, reverse=True)
    # Counts and event names only: no source value appears in the breakdowns.
    assert "@example" not in before.text

    suggestions = admin_client.get(
        f"/api/v1/policies/suggestions?connection_id={connection_id}"
        f"&snapshot_id={snapshot_id}&schema_name=enterprise&table_name=customers"
    ).json()
    flagged = [c["column_name"] for c in suggestions["columns"] if c["source"] == "DETECTOR"]
    assert "email" in flagged and len(flagged) >= 5

    # A view belongs to the table, so coverage follows the version deployed last
    # for enterprise.customers whichever connection record deployed it. First a
    # version with no rule for email (NULL in the view), then one that keeps it.
    def deploy_customers(rules):
        policy_id = _create_policy(admin_client, connection_id, snapshot_id, "customers", rules)
        _approve(admin_client, policy_id)
        assert _deploy(admin_client, db, policy_id)[1] == "DEPLOYED"
        return admin_client.get("/api/v1/dashboard/insights").json()["coverage"]

    hidden = deploy_customers([{"column_name": "id", "action": "KEEP"}])
    exposed = deploy_customers(
        [{"column_name": "id", "action": "KEEP"}, {"column_name": "email", "action": "KEEP"}]
    )
    assert hidden["sensitive_columns"] == exposed["sensitive_columns"] == sensitive

    # Keeping email uncovers exactly the email findings of this table: one per
    # connection whose latest completed scan flagged it.
    latest_scans = (
        select(ScanJob.id)
        .where(ScanJob.status == "COMPLETED")
        .distinct(ScanJob.connection_id)
        .order_by(ScanJob.connection_id, ScanJob.created_at.desc())
    )
    email_findings = db.scalar(
        select(func.count())
        .select_from(ScanResult)
        .where(
            ScanResult.scan_job_id.in_(latest_scans),
            ScanResult.schema_name == "enterprise",
            ScanResult.table_name == "customers",
            ScanResult.column_name == "email",
            ScanResult.json_path == "",
            ScanResult.matching_rows > 0,
        )
    )
    assert email_findings >= 1
    assert hidden["protected_columns"] - exposed["protected_columns"] == email_findings


# (value, MASK_EMAIL, MASK_PHONE, MASK_ID) evaluated by PostgreSQL itself.
ADVERSARIAL_VALUES = [
    (None, None, None, None),
    ("", "***", "***", "***"),
    ("customer1@example.com", "c***@example.com", "***", "***"),
    ("first.last+tag@mail.example.org", "f***@mail.example.org", "***", "***"),
    # Anything after the address must not ride along behind the "@".
    ("priya@example.com;9876543210;ABCPK1234F", "***", "***", "***"),
    ('{"email":"a@b.com","ssn":"123-45-6789"}', "***", "***", "***"),
    ("https://alice:s3cret@example.com/reset?token=abc123", "***", "***", "***"),
    ("a@b.com\nsecret line", "***", "***", "***"),
    ("a@b.com ", "***", "***", "***"),
    ("two@signs@example.com", "***", "***", "***"),
    # What follows the "@" must be a dotted host name ending in letters.
    ("x@2345-6789-0124", "***", "***", "***"),
    ("p@ssw0rd123", "***", "***", "***"),
    ("a@b.com:5432", "***", "***", "***"),
    ("a@b.com.", "***", "***", "***"),
    ("a@-b.com", "***", "***", "***"),
    ("x" * 65 + "@example.com", "***", "***", "***"),
    ("名前@example.com", "名***@example.com", "***", "***"),
    ("+91 90000 00001", "***", "+** ***** *0001", "***"),
    ("(022) 2345-6789", "***", "(***) ****-6789", "***"),
    ("12345", "***", "***", "***"),
    ("call John 9000000001", "***", "***", "**** **** ******0001"),
    ("2345 6789 0001", "***", "**** **** 0001", "**** **** 0001"),
    ("ABCDE1234F", "***", "***", "******234F"),
    ("4111-1111-1111-1111", "***", "****-****-****-1111", "****-****-****-1111"),
    ("x'; DROP TABLE enterprise.customers; --", "***", "***", "***"),
    ("9" * 80, "***", "***", "***"),
]


def test_format_masks_fail_closed_on_adversarial_values():
    from app.services.policies.compiler import ColumnDecision, compile_sample_query

    host, port, passwords = _target_env()
    columns = [
        ColumnDecision(name=name, data_type="text", action=action, source_column=name)
        for name, action in (("e", "MASK_EMAIL"), ("p", "MASK_PHONE"), ("i", "MASK_ID"))
    ]
    with _connect(host, port, "ps_deployer", passwords["deployer"]) as deployer:
        for start in range(0, len(ADVERSARIAL_VALUES), 7):
            chunk = ADVERSARIAL_VALUES[start : start + 7]
            params = [case[0] for case in chunk for _ in columns]
            rows = deployer.execute(compile_sample_query(columns, len(chunk)), params).fetchall()
            for case, row in zip(chunk, rows, strict=True):
                assert (row["after_0"], row["after_1"], row["after_2"]) == case[1:], case[0]


def test_sample_preview_shows_no_real_pseudonym(admin_client, db):
    import hashlib

    host, port, passwords = _target_env()
    connection_id, snapshot_id = _register(admin_client, host, port, passwords)
    policy_id = _create_policy(
        admin_client,
        connection_id,
        snapshot_id,
        "accounts",
        [
            {"column_name": "customer_id", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
            {"column_name": "account_number", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
        ],
    )
    body = admin_client.get(f"/api/v1/policies/{policy_id}/preview/samples").json()
    assert body["status"] == "OK"
    names = [column["name"] for column in body["columns"]]
    for before_row, after_row in zip(body["before"], body["after"], strict=True):
        before = dict(zip(names, before_row, strict=True))
        after = dict(zip(names, after_row, strict=True))
        for name in ("customer_id", "account_number"):
            # An unkeyed digest of the invented input: nothing from the target's
            # secret key, so it cannot be matched against real masked output.
            assert after[name] == hashlib.sha256(before[name].encode()).hexdigest()

    # The deployed view does use the key, and so produces a different token.
    _approve(admin_client, policy_id)
    assert _deploy(admin_client, db, policy_id)[1] == "DEPLOYED"
    preview = admin_client.get(f"/api/v1/policies/{policy_id}/preview").json()
    view = f'{preview["view_schema"]}."{preview["view_name"]}"'
    with _connect(host, port, "ps_reader", passwords["reader"]) as reader:
        tokens = [r["customer_id"] for r in reader.execute(f"SELECT customer_id FROM {view}")]
    assert len(tokens) == 100 and all(len(token) == 64 for token in tokens)
    assert hashlib.sha256(b"1").hexdigest() not in tokens


@pytest.fixture
def awkward_table():
    """A narrow numeric column and JSON too large for the scanner to read."""
    host, port, passwords = _target_env()
    schema = "ps_mask_" + uuid.uuid4().hex[:16]
    with _connect(host, port, "postgres", passwords["superuser"]) as admin:
        try:
            admin.execute(f"CREATE SCHEMA {schema}")
            admin.execute(f"CREATE TYPE {schema}.grade AS ENUM ('low', 'high')")
            admin.execute(
                f"CREATE TABLE {schema}.readings (id int PRIMARY KEY, ratio numeric(3,2), "
                f"label text, payload jsonb, never_filled text, grade {schema}.grade)"
            )
            admin.execute(
                f"INSERT INTO {schema}.readings SELECT n, 0.5, 'reading ' || n, "
                "jsonb_build_object('blob', repeat('x', 20000)), NULL, 'low' "
                "FROM generate_series(1, 5) AS n"
            )
            admin.execute(f"GRANT USAGE ON SCHEMA {schema} TO ps_scanner, ps_view_owner")
            admin.execute(f"GRANT SELECT ON {schema}.readings TO ps_scanner")
            yield schema
        finally:
            admin.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")


def test_partly_read_columns_get_no_keep_and_preview_survives_narrow_types(
    admin_client, awkward_table
):
    host, port, passwords = _target_env()
    connection = admin_client.post(
        "/api/v1/connections",
        json={
            "name": f"awkward-{uuid.uuid4().hex[:10]}",
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
    snapshot_id = admin_client.post(
        f"/api/v1/connections/{connection_id}/discover", json={"schemas": [awkward_table]}
    ).json()["snapshot_id"]
    scan = admin_client.post(
        "/api/v1/scans",
        json={"connection_id": connection_id, "snapshot_id": snapshot_id, "sample_limit": 5},
    ).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status = admin_client.get(f"/api/v1/scans/{scan['id']}").json()["status"]
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        time.sleep(0.5)
    assert status == "COMPLETED"

    suggestions = admin_client.get(
        f"/api/v1/policies/suggestions?connection_id={connection_id}"
        f"&snapshot_id={snapshot_id}&schema_name={awkward_table}&table_name=readings"
    ).json()
    by_name = {column["column_name"]: column for column in suggestions["columns"]}
    assert by_name["id"]["source"] == "NO_FINDINGS" and by_name["id"]["action"] == "KEEP"
    # Every payload value was too large to read, so "nothing found" is not
    # evidence and the column must not be offered as safe to keep.
    assert by_name["payload"]["source"] == "NO_FINDINGS"
    assert by_name["payload"]["action"] is None
    # A column that was NULL in every sampled row was never inspected either.
    assert by_name["never_filled"]["source"] == "NO_FINDINGS"
    assert by_name["never_filled"]["action"] is None
    assert by_name["label"]["action"] == "KEEP"

    policy = admin_client.post(
        "/api/v1/policies",
        json={
            "connection_id": connection_id,
            "schema_name": awkward_table,
            "table_name": "readings",
            "snapshot_id": snapshot_id,
            "rules": [
                {"column_name": "ratio", "action": "KEEP"},
                {"column_name": "label", "action": "REDACT"},
            ],
        },
    )
    assert policy.status_code == 201, policy.text
    samples = admin_client.get(f"/api/v1/policies/{policy.json()['id']}/preview/samples").json()
    # 2500.75 does not fit numeric(3,2). The preview drops to text-only examples
    # instead of becoming unavailable for the whole table.
    assert samples["status"] == "OK"
    names = [column["name"] for column in samples["columns"]]
    first_before = dict(zip(names, samples["before"][0], strict=True))
    first_after = dict(zip(names, samples["after"][0], strict=True))
    assert first_before["ratio"] is None and first_after["ratio"] is None
    assert first_before["label"] == "Sample text 1" and first_after["label"] == "[REDACTED]"
    # The enum type lives in the source schema; the preview still resolves it.
    assert "grade" in names and first_after["grade"] is None

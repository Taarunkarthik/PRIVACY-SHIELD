"""Real checks for per-audience masking: one table, a differently masked view per role.

Every test leaves the shared target as other tests expect it: audience views
created here are dropped again, and roles that were renamed are renamed back.
"""

import hashlib
import json
import os
import re
import secrets
import time
import uuid
from contextlib import contextmanager

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.api.dashboard import _deployed_rules
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AuditEvent, PolicyDeployment, User
from app.services.policies.compiler import view_name_for
from app.services.policies.execution import run_deployment

pytestmark = pytest.mark.integration

ROLES = {"reader": "ps_reader", "support": "ps_support", "analyst": "ps_analyst"}
TABLES = ("customers", "transactions")
PARKED = "_parked_by_test"
HEX_TOKEN = re.compile(r"[0-9a-f]{64}")


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


def _client(db, monkeypatch, role):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"audience-{role.lower()}-{uuid.uuid4().hex}@example.com",
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


def _view(table, audience="reader"):
    return f'privacyshield_masked."{view_name_for("enterprise", table, audience)}"'


def _unpark_roles(superuser):
    """Give back any audience role a test renamed away, even after a crashed run."""
    for role in ("ps_support", "ps_analyst"):
        names = {
            row["rolname"]
            for row in superuser.execute(
                "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", ([role, role + PARKED],)
            )
        }
        if role + PARKED in names and role not in names:
            superuser.execute(f"ALTER ROLE {role}{PARKED} RENAME TO {role}")


@pytest.fixture
def superuser():
    """A target superuser session that restores shared state when the test ends."""
    host, port, passwords = _target_env()
    with _connect(host, port, "postgres", passwords["superuser"]) as connection:
        _unpark_roles(connection)
        present = connection.execute(
            "SELECT count(*) AS n FROM pg_roles WHERE rolname = ANY(%s)", (list(ROLES.values()),)
        ).fetchone()["n"]
        if present != len(ROLES):
            pytest.fail(
                "The target database has no ps_support/ps_analyst roles: it was initialised "
                "before masking audiences. Run the role setup SQL in docs/masking-audiences.md "
                "once, or initialise the target again."
            )
        try:
            yield connection
        finally:
            connection.execute("RESET ROLE")
            _unpark_roles(connection)
            # Other tests deploy reader-only policies; leave no audience view behind.
            for table in TABLES:
                for audience in ("support", "analyst"):
                    connection.execute(f"DROP VIEW IF EXISTS {_view(table, audience)}")


@contextmanager
def _as(superuser, role):
    superuser.execute(f"SET ROLE {role}")
    try:
        yield superuser
    finally:
        superuser.execute("RESET ROLE")


def _exists(superuser, table, audience):
    return superuser.execute(
        "SELECT to_regclass(%s) IS NOT NULL AS present", (_view(table, audience),)
    ).fetchone()["present"]


def _register(client):
    host, port, passwords = _target_env()
    connection = client.post(
        "/api/v1/connections",
        json={
            "name": f"audience-{uuid.uuid4().hex[:10]}",
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


def _rules(**audiences):
    """Rules as request bodies. The reader's rules omit the field, as old clients do."""
    rules = []
    for audience, columns in audiences.items():
        for column, action in columns.items():
            rule = {"column_name": column, "action": action}
            if action == "PSEUDONYMIZE":
                rule["pseudonym_domain"] = "demo"
            if audience != "reader":
                rule["audience"] = audience
            rules.append(rule)
    return rules


def _post_policy(client, target, table, rules):
    connection_id, snapshot_id = target
    return client.post(
        "/api/v1/policies",
        json={
            "connection_id": connection_id,
            "schema_name": "enterprise",
            "table_name": table,
            "snapshot_id": snapshot_id,
            "rules": rules,
        },
    )


def _create_policy(client, target, table, **audiences):
    policy = _post_policy(client, target, table, _rules(**audiences))
    assert policy.status_code == 201, policy.text
    return policy.json()["id"]


def _approve(client, policy_id):
    assert client.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200
    approved = client.post(f"/api/v1/policies/{policy_id}/approve")
    assert approved.status_code == 200, approved.text
    return approved.json()["compiled_plan_fingerprint"]


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
    db.expire_all()
    return db.get(PolicyDeployment, deployment_id), status


def _receipts(superuser, deployment):
    return superuser.execute(
        "SELECT count(*) AS n FROM privacyshield_private.deployment_receipts "
        "WHERE deployment_id = %s",
        (deployment.id,),
    ).fetchone()["n"]


def _assert_nothing_deployed(superuser, deployment, status, code):
    assert status == "FAILED"
    assert deployment.status == "FAILED" and deployment.error_code == code
    # The views and their receipt commit together, so a missing receipt shows
    # the failed attempt rolled back completely.
    assert _receipts(superuser, deployment) == 0
    assert "audiences" not in (deployment.target_receipt or {})


def _preview(client, policy_id, audience=None):
    query = f"?audience={audience}" if audience else ""
    return client.get(f"/api/v1/policies/{policy_id}/preview{query}")


def test_each_audience_reads_only_its_own_view(admin_client, db, monkeypatch, superuser):
    host, port, _ = _target_env()
    target = _register(admin_client)
    created = _post_policy(
        admin_client,
        target,
        "customers",
        _rules(
            reader={"id": "KEEP", "email": "MASK_EMAIL", "phone": "NULLIFY"},
            support={
                "id": "KEEP",
                "full_name": "KEEP",
                "email": "MASK_EMAIL",
                "phone": "MASK_PHONE",
            },
            analyst={"id": "KEEP", "email": "PSEUDONYMIZE"},
        ),
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    by_audience = {}
    for rule in created.json()["rules"]:
        by_audience.setdefault(rule["audience"], {})[rule["column_name"]] = rule["action"]
    assert by_audience == {
        "reader": {"id": "KEEP", "email": "MASK_EMAIL", "phone": "NULLIFY"},
        "support": {
            "id": "KEEP",
            "full_name": "KEEP",
            "email": "MASK_EMAIL",
            "phone": "MASK_PHONE",
        },
        "analyst": {"id": "KEEP", "email": "PSEUDONYMIZE"},
    }

    # Compiled preview: one view per audience, each with its own name and SQL.
    previews = {}
    for audience, role in ROLES.items():
        response = _preview(admin_client, policy_id, audience)
        assert response.status_code == 200, response.text
        body = previews[audience] = response.json()
        assert body["audience"] == audience and body["role"] == role
        assert body["audiences"] == ["reader", "support", "analyst"]
        assert body["view_schema"] == "privacyshield_masked"
        assert body["view_name"] == view_name_for("enterprise", "customers", audience)
        assert len(body["view_name"]) <= 63
        assert f'"privacyshield_masked"."{body["view_name"]}"' in body["sql"]
        assert "security_barrier = true" in body["sql"]
        actions = {column["name"]: column["action"] for column in body["columns"]}
        # A column without a rule for this audience is NULL in its view.
        assert actions == {name: by_audience[audience].get(name, "NULLIFY") for name in actions}
    assert len({body["view_name"] for body in previews.values()}) == 3
    # Without the parameter the answer is the reader's, as before audiences.
    default = _preview(admin_client, policy_id).json()
    assert default == previews["reader"]
    assert default["view_name"] == view_name_for("enterprise", "customers")

    # Sample preview per audience: fabricated inputs, that audience's expressions.
    samples = {}
    for audience in ROLES:
        response = admin_client.get(
            f"/api/v1/policies/{policy_id}/preview/samples?audience={audience}"
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["audience"] == audience
        assert body["status"] == "OK" and body["source"] == "FABRICATED"
        names = [column["name"] for column in body["columns"]]
        samples[audience] = (
            dict(zip(names, body["before"][0], strict=True)),
            dict(zip(names, body["after"][0], strict=True)),
        )
        assert "customer1@example.com" not in response.text
    before, after = samples["reader"]
    assert before["email"] == "priya.sharma@example.com"
    assert (after["email"], after["phone"], after["full_name"]) == ("p***@example.com", None, None)
    before, after = samples["support"]
    assert (after["email"], after["phone"]) == ("p***@example.com", "+** ***** *3210")
    assert after["full_name"] == before["full_name"] == "Priya Sharma"
    before, after = samples["analyst"]
    # A sample pseudonym is an unkeyed digest, never a token made with the real key.
    assert after["email"] == hashlib.sha256(before["email"].encode()).hexdigest()
    assert (after["phone"], after["full_name"]) == (None, None)
    default = admin_client.get(f"/api/v1/policies/{policy_id}/preview/samples").json()
    assert default["audience"] == "reader" and default["after"][0][2] == "p***@example.com"

    # Protected output exists only for a deployed policy, for every audience.
    for audience in ROLES:
        undeployed = admin_client.get(
            f"/api/v1/policies/{policy_id}/protected-output?audience={audience}"
        )
        assert undeployed.status_code == 409
        assert undeployed.json()["detail"] == "POLICY_NOT_DEPLOYED"

    _approve(admin_client, policy_id)
    deployment, status = _deploy(admin_client, db, policy_id)
    assert status == "DEPLOYED", deployment.error_code
    receipt = deployment.target_receipt
    assert receipt["access_verified"] is True
    assert receipt["audiences"] == ["reader", "support", "analyst"]
    assert receipt["audience_views"] == {
        audience: previews[audience]["view_name"] for audience in ROLES
    }
    assert receipt["view_name"] == previews["reader"]["view_name"]

    # Each role reads its own view, with its own masking of the same row.
    expected_token = superuser.execute(
        "SELECT encode(extensions.hmac(convert_to('customer7@example.com', 'UTF8'), "
        "(SELECT key FROM privacyshield_private.pseudonym_keys "
        "WHERE domain = 'demo' AND key_version = 1), 'sha256'), 'hex') AS token"
    ).fetchone()["token"]
    expected = {
        "reader": {"full_name": None, "email": "c***@example.com", "phone": None},
        "support": {
            "full_name": "Synthetic Customer 7",
            "email": "c***@example.com",
            "phone": "+** ***** *0007",
        },
        "analyst": {"full_name": None, "email": expected_token, "phone": None},
    }
    query = "SELECT full_name, email, phone FROM {view} WHERE id = 7"
    for audience, role in ROLES.items():
        with _as(superuser, role) as session:
            row = session.execute(query.format(view=_view("customers", audience))).fetchone()
            assert row == expected[audience], audience
            # ...and is denied every other audience's view and the base table.
            for other in ROLES:
                if other != audience:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        session.execute(query.format(view=_view("customers", other)))
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                session.execute("SELECT email FROM enterprise.customers LIMIT 1")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                session.execute("SELECT key FROM privacyshield_private.pseudonym_keys")

    # Pseudonyms are stable: the same token on every read, one per source value.
    with _as(superuser, "ps_analyst") as session:
        view = _view("customers", "analyst")
        again = session.execute(f"SELECT email FROM {view} WHERE id = 7").fetchone()["email"]
        assert again == expected_token and HEX_TOKEN.fullmatch(again)
        counts = session.execute(
            f"SELECT count(*) AS total, count(DISTINCT email) AS tokens FROM {view}"
        ).fetchone()
        assert counts == {"total": 100, "tokens": 100}

    # Evidence through the API: that audience's view, rows and role.
    for audience, role in ROLES.items():
        output = admin_client.get(
            f"/api/v1/policies/{policy_id}/protected-output?audience={audience}"
        )
        assert output.status_code == 200, output.text
        evidence = output.json()
        assert evidence["audience"] == audience
        assert evidence["view_name"] == previews[audience]["view_name"]
        assert evidence["access"] == {
            "reader_role": role,
            "reader_can_read_view": True,
            "reader_can_read_source": False,
        }
        assert 1 <= len(evidence["rows"]) <= evidence["row_limit"] == 5
        columns = [column["name"] for column in evidence["columns"]]
        for values in evidence["rows"]:
            record = dict(zip(columns, values, strict=True))
            assert record["address"] is None and record["pan"] is None
            if audience == "analyst":
                assert HEX_TOKEN.fullmatch(record["email"]) and record["phone"] is None
            else:
                assert record["email"] == "c***@example.com"
            if audience == "support":
                assert re.fullmatch(r"\+\*\* \*{5} \*\d{4}", record["phone"])
                assert record["full_name"].startswith("Synthetic Customer ")
            else:
                assert record["full_name"] is None
            if audience == "reader":
                assert record["phone"] is None
        # No unmasked email or phone number reaches any response.
        assert "customer1@" not in output.text and "+91 90000" not in output.text
    default = admin_client.get(f"/api/v1/policies/{policy_id}/protected-output").json()
    assert default["audience"] == "reader" and default["access"]["reader_role"] == "ps_reader"
    viewed = db.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(
            AuditEvent.event_type == "PROTECTED_OUTPUT_VIEWED",
            AuditEvent.subject_id == uuid.UUID(policy_id),
        )
    )
    assert viewed == 4

    # Only administrators may read rows through a deployed view, whichever audience.
    for app_role in ("ANALYST", "AUDITOR"):
        other = _client(db, monkeypatch, app_role)
        try:
            for audience in ROLES:
                suffix = f"?audience={audience}"
                path = f"/api/v1/policies/{policy_id}"
                assert other.get(f"{path}/protected-output{suffix}").status_code == 403
                assert other.get(f"{path}/preview{suffix}").status_code == 200
                assert other.get(f"{path}/preview/samples{suffix}").status_code == 200
            assert other.get(f"/api/v1/policies/{policy_id}/protected-output").status_code == 403
        finally:
            other.close()

    # Dashboard coverage means "protected from the general reader": a column
    # kept only for support staff must not count as exposed.
    deployed = _deployed_rules(db)[(host, port, "enterprise_demo", "enterprise", "customers")]
    assert deployed == {"id": "KEEP", "email": "MASK_EMAIL", "phone": "NULLIFY"}

    # A newer version without support rules: the support view must not outlive
    # the version that created it.
    second = _create_policy(
        admin_client,
        target,
        "customers",
        reader={"id": "KEEP", "email": "PSEUDONYMIZE"},
        analyst={"id": "KEEP", "email": "PSEUDONYMIZE", "phone": "MASK_PHONE"},
    )
    assert _preview(admin_client, second).json()["audiences"] == ["reader", "analyst"]
    missing = _preview(admin_client, second, "support")
    assert missing.status_code == 404 and missing.json()["detail"] == "AUDIENCE_NOT_IN_POLICY"
    _approve(admin_client, second)
    assert _exists(superuser, "customers", "support")
    deployment, status = _deploy(admin_client, db, second)
    assert status == "DEPLOYED", deployment.error_code
    assert deployment.target_receipt["audiences"] == ["reader", "analyst"]
    assert set(deployment.target_receipt["audience_views"]) == {"reader", "analyst"}

    assert not _exists(superuser, "customers", "support")
    with _as(superuser, "ps_support") as session:
        with pytest.raises(psycopg.errors.UndefinedTable):
            session.execute(query.format(view=_view("customers", "support")))
        for other in ("reader", "analyst"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                session.execute(query.format(view=_view("customers", other)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            session.execute("SELECT email FROM enterprise.customers LIMIT 1")
    # The same domain gives every audience the same token for the same value.
    tokens = {}
    for audience in ("reader", "analyst"):
        with _as(superuser, ROLES[audience]) as session:
            row = session.execute(
                f"SELECT email, phone FROM {_view('customers', audience)} WHERE id = 7"
            ).fetchone()
            tokens[audience] = row["email"]
            assert row["phone"] == ("+** ***** *0007" if audience == "analyst" else None)
    assert tokens == {"reader": expected_token, "analyst": expected_token}

    path = f"/api/v1/policies/{second}/protected-output"
    assert admin_client.get(path + "?audience=analyst").status_code == 200
    gone = admin_client.get(path + "?audience=support")
    assert gone.status_code == 404 and gone.json()["detail"] == "AUDIENCE_NOT_IN_POLICY"
    # The superseded version no longer describes any deployed view.
    for audience in ROLES:
        superseded = admin_client.get(
            f"/api/v1/policies/{policy_id}/protected-output?audience={audience}"
        )
        assert superseded.status_code == 409


def test_missing_audience_role_fails_the_deployment_and_deploys_nothing(
    admin_client, db, superuser
):
    target = _register(admin_client)
    reader_only = _create_policy(
        admin_client, target, "transactions", reader={"account_id": "KEEP"}
    )
    with_analyst = _create_policy(
        admin_client,
        target,
        "transactions",
        reader={"account_id": "KEEP", "amount": "KEEP"},
        analyst={"account_id": "PSEUDONYMIZE", "amount": "KEEP"},
    )
    _approve(admin_client, reader_only)
    fingerprint = _approve(admin_client, with_analyst)
    reader_view = _view("transactions")
    amount = f"SELECT amount FROM {reader_view} WHERE account_id = 3"

    # A database initialised before audiences existed has neither role.
    for role in ("ps_support", "ps_analyst"):
        superuser.execute(f"ALTER ROLE {role} RENAME TO {role}{PARKED}")
    try:
        # A reader-only policy needs only the reader role, so it still deploys.
        deployment, status = _deploy(admin_client, db, reader_only)
        assert status == "DEPLOYED", deployment.error_code
        assert deployment.target_receipt["audiences"] == ["reader"]
        with _as(superuser, "ps_reader") as session:
            assert session.execute(amount).fetchone() == {"amount": None}

        # A policy with an analyst view cannot deploy any part of itself.
        failed, status = _deploy(admin_client, db, with_analyst)
        _assert_nothing_deployed(superuser, failed, status, "AUDIENCE_ROLE_MISSING")
        assert not _exists(superuser, "transactions", "analyst")
        with _as(superuser, "ps_reader") as session:
            # Still the earlier version's reader view: amount is not exposed.
            assert session.execute(amount).fetchone() == {"amount": None}
    finally:
        _unpark_roles(superuser)

    # With the role back, the same approved version deploys unchanged.
    deployment, status = _deploy(admin_client, db, with_analyst)
    assert status == "DEPLOYED", deployment.error_code
    assert deployment.id != failed.id
    policy = admin_client.get(f"/api/v1/policies/{with_analyst}").json()
    assert policy["compiled_plan_fingerprint"] == fingerprint
    assert _receipts(superuser, deployment) == 1
    with _as(superuser, "ps_reader") as session:
        assert str(session.execute(amount).fetchone()["amount"]) == "25.00"
    with _as(superuser, "ps_analyst") as session:
        row = session.execute(
            f"SELECT account_id, amount FROM {_view('transactions', 'analyst')} LIMIT 1"
        ).fetchone()
        assert HEX_TOKEN.fullmatch(row["account_id"]) and str(row["amount"]) == "25.00"


def test_stale_audience_view_in_use_blocks_the_deployment(admin_client, db, superuser):
    target = _register(admin_client)
    first = _create_policy(
        admin_client,
        target,
        "transactions",
        reader={"account_id": "KEEP"},
        support={"account_id": "KEEP", "note": "REDACT"},
    )
    _approve(admin_client, first)
    assert _deploy(admin_client, db, first)[1] == "DEPLOYED"
    second = _create_policy(
        admin_client, target, "transactions", reader={"account_id": "KEEP", "amount": "KEEP"}
    )
    _approve(admin_client, second)
    support_view = _view("transactions", "support")
    amount = f"SELECT amount FROM {_view('transactions')} WHERE account_id = 3"

    # Something an operator built on the support view. Dropping the view would
    # take it along, which a deployment must not decide by itself.
    schema = "ps_audience_" + uuid.uuid4().hex[:16]
    superuser.execute(f"CREATE SCHEMA {schema}")
    try:
        superuser.execute(f"CREATE VIEW {schema}.dependent AS SELECT * FROM {support_view}")
        failed, status = _deploy(admin_client, db, second)
        _assert_nothing_deployed(superuser, failed, status, "AUDIENCE_VIEW_IN_USE")
        # The earlier version is intact: support still reads its view, and the
        # reader view has not taken the new version's rules.
        with _as(superuser, "ps_support") as session:
            row = session.execute(f"SELECT note FROM {support_view} LIMIT 1").fetchone()
            assert row == {"note": "[REDACTED]"}
        with _as(superuser, "ps_reader") as session:
            assert session.execute(amount).fetchone() == {"amount": None}
    finally:
        superuser.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")

    deployment, status = _deploy(admin_client, db, second)
    assert status == "DEPLOYED", deployment.error_code
    assert not _exists(superuser, "transactions", "support")
    with _as(superuser, "ps_reader") as session:
        assert str(session.execute(amount).fetchone()["amount"]) == "25.00"


def test_redeploying_takes_an_audience_view_back_from_other_audience_roles(
    admin_client, db, superuser
):
    target = _register(admin_client)
    audiences = {"reader": {"account_id": "KEEP"}, "support": {"account_id": "KEEP"}}
    first = _create_policy(admin_client, target, "transactions", **audiences)
    _approve(admin_client, first)
    assert _deploy(admin_client, db, first)[1] == "DEPLOYED"
    support_view = _view("transactions", "support")
    read = f"SELECT account_id FROM {support_view} LIMIT 1"

    # Someone hands the support view to analysts by hand.
    superuser.execute(f"GRANT SELECT ON {support_view} TO ps_analyst")
    with _as(superuser, "ps_analyst") as session:
        assert session.execute(read).fetchone() is not None

    # The next deployment grants each view to its own audience role only.
    second = _create_policy(admin_client, target, "transactions", **audiences)
    _approve(admin_client, second)
    deployment, status = _deploy(admin_client, db, second)
    assert status == "DEPLOYED", deployment.error_code
    with _as(superuser, "ps_analyst") as session:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            session.execute(read)
    with _as(superuser, "ps_support") as session:
        assert session.execute(read).fetchone() is not None


@pytest.mark.parametrize(
    ("audiences", "expose", "withdraw"),
    [
        # Membership lets support staff read the general reader's view as well.
        (
            {"reader": {"account_id": "KEEP"}, "support": {"account_id": "KEEP"}},
            ["GRANT ps_reader TO ps_support"],
            ["REVOKE ps_reader FROM ps_support"],
        ),
        # An audience the policy gives no view to must have no way to the table.
        (
            {"reader": {"account_id": "KEEP"}},
            [
                "GRANT USAGE ON SCHEMA enterprise TO ps_analyst",
                "GRANT SELECT (note) ON enterprise.transactions TO ps_analyst",
            ],
            [
                "REVOKE SELECT (note) ON enterprise.transactions FROM ps_analyst",
                "REVOKE USAGE ON SCHEMA enterprise FROM ps_analyst",
            ],
        ),
    ],
    ids=["reads-another-audiences-view", "unused-audience-reads-source"],
)
def test_deployment_fails_when_an_audience_role_can_read_too_much(
    admin_client, db, superuser, audiences, expose, withdraw
):
    target = _register(admin_client)
    policy_id = _create_policy(admin_client, target, "transactions", **audiences)
    _approve(admin_client, policy_id)
    for statement in expose:
        superuser.execute(statement)
    try:
        failed, status = _deploy(admin_client, db, policy_id)
        _assert_nothing_deployed(superuser, failed, status, "ACCESS_VERIFICATION_FAILED")
    finally:
        for statement in withdraw:
            superuser.execute(statement)
    # With the exposure removed, the unchanged approved version deploys on retry.
    assert _deploy(admin_client, db, policy_id)[1] == "DEPLOYED"


def test_rule_audiences_are_validated_and_reader_only_policies_are_unchanged(admin_client, db):
    target = _register(admin_client)

    def rejected(rules):
        response = _post_policy(admin_client, target, "customers", rules)
        assert response.status_code == 422, response.text
        return response.json()["detail"]

    keep = {"column_name": "email", "action": "KEEP"}
    # One rule per column and audience; the default audience is the reader.
    assert rejected([keep, keep]) == "DUPLICATE_RULE"
    assert rejected([keep, {**keep, "audience": "reader"}]) == "DUPLICATE_RULE"
    assert (
        rejected([{**keep, "audience": "support"}, {**keep, "audience": "support"}])
        == "DUPLICATE_RULE"
    )
    assert (
        rejected([keep, {"column_name": "nope", "action": "KEEP", "audience": "analyst"}])
        == "UNKNOWN_COLUMN"
    )
    for audience in ("admin", "", "READER", "support; DROP ROLE ps_reader"):
        detail = rejected([{**keep, "audience": audience}])
        assert isinstance(detail, list) and detail[0]["loc"][-1] == "audience"

    # A reader-only policy, written exactly as before audiences existed.
    reader_only = _post_policy(
        admin_client,
        target,
        "customers",
        [
            {"column_name": "id", "action": "KEEP"},
            {"column_name": "email", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
            {"column_name": "phone", "action": "MASK_PHONE"},
        ],
    )
    assert reader_only.status_code == 201, reader_only.text
    policy_id = reader_only.json()["id"]
    assert {rule["audience"] for rule in reader_only.json()["rules"]} == {"reader"}
    preview = _preview(admin_client, policy_id).json()
    assert (preview["audience"], preview["role"]) == ("reader", "ps_reader")
    assert preview["audiences"] == ["reader"]
    # Its approved fingerprint is the one the compiler produced before audiences,
    # so a policy approved by an earlier release still matches at deployment.
    content = json.dumps(
        {
            "source_schema": "enterprise",
            "source_table": "customers",
            "view_schema": "privacyshield_masked",
            "view_name": preview["view_name"],
            "columns": [
                {
                    "name": column["name"],
                    "source_column": column["source_column"],
                    "action": column["action"],
                    "pseudonym_domain": column["pseudonym_domain"],
                }
                for column in preview["columns"]
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert _approve(admin_client, policy_id) == hashlib.sha256(content.encode()).hexdigest()

    # It has a view for the reader and for nobody else.
    path = f"/api/v1/policies/{policy_id}"
    for audience in ("support", "analyst"):
        for endpoint in ("/preview", "/preview/samples", "/protected-output"):
            response = admin_client.get(f"{path}{endpoint}?audience={audience}")
            assert response.status_code == 404, response.text
            assert response.json()["detail"] == "AUDIENCE_NOT_IN_POLICY"
    # An audience outside the fixed set is rejected before anything is looked up.
    for endpoint in ("/preview", "/preview/samples", "/protected-output"):
        assert admin_client.get(f"{path}{endpoint}?audience=admin").status_code == 422

    # Rules for support alone: the reader still gets a view, with every column NULL.
    support_only = _create_policy(
        admin_client, target, "customers", support={"email": "MASK_EMAIL"}
    )
    reader_view = _preview(admin_client, support_only).json()
    assert reader_view["audiences"] == ["reader", "support"]
    assert {column["action"] for column in reader_view["columns"]} == {"NULLIFY"}
    support_view = _preview(admin_client, support_only, "support").json()
    actions = {column["name"]: column["action"] for column in support_view["columns"]}
    assert actions["email"] == "MASK_EMAIL"
    assert set(actions.values()) == {"MASK_EMAIL", "NULLIFY"}

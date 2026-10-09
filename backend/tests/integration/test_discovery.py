"""Real target PostgreSQL checks; source fixtures are inspected without mutation."""

import json
import os
import secrets
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import decrypt_credential, encrypt_credential, hash_password
from app.main import app
from app.models import AuditEvent, DatabaseConnection, SchemaSnapshot, User
from app.services.discovery.catalog import DiscoveryError, discover_catalog, target_session

pytestmark = pytest.mark.integration


@pytest.fixture
def target_config():
    password = os.environ.get("TEST_TARGET_SCANNER_PASSWORD")
    if not password:
        pytest.fail("TEST_TARGET_SCANNER_PASSWORD is required for real discovery integration tests")
    return {
        "name": f"discovery-{uuid.uuid4().hex}",
        "host": os.environ.get("TEST_TARGET_HOST", "target-db"),
        "port": int(os.environ.get("TEST_TARGET_PORT", "5432")),
        "database_name": "enterprise_demo",
        "ssl_mode": "disable",
        "scanner_username": "ps_scanner",
        "scanner_password": password,
    }


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def client_for_role(db, monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    clients = []

    def create(role="ADMIN"):
        password = secrets.token_urlsafe(24)
        user = User(
            email=f"discovery-{uuid.uuid4().hex}@example.com",
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
        return client

    yield create
    for client in clients:
        client.close()


def register(client, config):
    response = client.post("/api/v1/connections", json=config)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_connection_credentials_encrypted_and_never_returned(target_config, client_for_role, db):
    client = client_for_role()
    connection_id = register(client, target_config)
    record = db.get(DatabaseConnection, uuid.UUID(connection_id))
    assert record.scanner_password_ciphertext != target_config["scanner_password"]
    assert (
        decrypt_credential(record.scanner_password_ciphertext) == target_config["scanner_password"]
    )
    response = client.get("/api/v1/connections?page_size=100")
    assert response.status_code == 200
    assert target_config["scanner_password"] not in response.text
    assert record.scanner_password_ciphertext not in response.text
    assert all("password" not in key for item in response.json()["items"] for key in item)
    conflict = client.post("/api/v1/connections", json=target_config)
    assert conflict.status_code == 409
    assert target_config["scanner_password"] not in conflict.text
    assert client.get("/api/v1/connections?page_size=101").status_code == 422


def test_discovery_real_schema_composite_keys_and_immutable_snapshots(
    target_config, client_for_role, db
):
    client = client_for_role()
    connection_id = register(client, target_config)
    path = f"/api/v1/connections/{connection_id}"
    assert client.get(path + "/schema").status_code == 404
    tested = client.post(path + "/test")
    assert tested.status_code == 200, tested.text
    assert tested.json()["table_count"] == 4
    discovered = client.post(path + "/discover", json={"schemas": ["enterprise"]})
    assert discovered.status_code == 200, discovered.text
    first = discovered.json()
    tables = {table["name"]: table for table in first["catalog"]["tables"]}
    assert set(tables) == {"customers", "accounts", "transactions", "support_records"}
    assert tables["transactions"]["primary_key"] == ["account_id", "sequence_number"]
    composite = next(
        key
        for key in tables["support_records"]["foreign_keys"]
        if key["referenced_table"] == "transactions"
    )
    assert composite["columns"] == ["related_account_id", "related_sequence_number"]
    assert composite["referenced_columns"] == ["account_id", "sequence_number"]
    profile = next(
        column for column in tables["customers"]["columns"] if column["name"] == "profile"
    )
    assert profile["is_jsonb"] is True and profile["nullable"] is False
    assert all(table["schema"] == "enterprise" for table in tables.values())
    assert "customer1@example.com" not in discovered.text
    assert target_config["scanner_password"] not in discovered.text
    second = client.post(path + "/discover", json={"schemas": ["enterprise"]}).json()
    assert first["snapshot_id"] != second["snapshot_id"]
    assert first["fingerprint"] == second["fingerprint"]
    assert client.get(path + "/schema").json()["snapshot_id"] == second["snapshot_id"]
    assert (
        db.scalar(
            select(func.count())
            .select_from(SchemaSnapshot)
            .where(
                SchemaSnapshot.connection_id == uuid.UUID(connection_id),
            )
        )
        == 2
    )
    audit = db.scalar(
        select(AuditEvent).where(AuditEvent.subject_id == uuid.UUID(second["snapshot_id"]))
    )
    assert audit.event_type == "SCHEMA_DISCOVERED"
    assert target_config["scanner_password"] not in json.dumps(audit.details)


@pytest.mark.parametrize("role", ["ANALYST", "AUDITOR"])
def test_connection_rbac_prevents_unauthorized_writes(target_config, client_for_role, role):
    admin = client_for_role()
    connection_id = register(admin, target_config)
    user = client_for_role(role)
    path = f"/api/v1/connections/{connection_id}"
    assert user.get("/api/v1/connections").status_code == 200
    assert user.post("/api/v1/connections", json=target_config).status_code == 403
    assert user.patch(path, json={"is_active": False}).status_code == 403
    assert user.post(path + "/test").status_code == 403
    assert user.post(path + "/discover").status_code == (200 if role == "ANALYST" else 403)
    admin.post(path + "/discover", json={"schemas": ["enterprise"]})
    assert user.get(path + "/schema").status_code == 200


def test_connection_update_deactivation_and_credentials(target_config, client_for_role, db):
    client = client_for_role()
    connection_id = register(client, target_config)
    path = f"/api/v1/connections/{connection_id}"
    assert client.patch(path, json={"scanner_username": "new-role"}).status_code == 422
    replacement = secrets.token_urlsafe(24)
    updated = client.patch(path, json={"scanner_password": replacement, "is_active": False})
    assert updated.status_code == 200
    assert replacement not in updated.text
    assert client.post(path + "/test").status_code == 409
    assert client.post(path + "/discover").status_code == 409
    db.expire_all()
    record = db.get(DatabaseConnection, uuid.UUID(connection_id))
    assert decrypt_credential(record.scanner_password_ciphertext) == replacement
    assert client.patch(path, json={"deployer_username": "deployer"}).status_code == 422
    assert (
        client.patch(
            path, json={"deployer_username": "deployer", "deployer_password": replacement}
        ).status_code
        == 200
    )
    assert (
        client.patch(path, json={"deployer_username": None, "deployer_password": None}).status_code
        == 200
    )
    db.expire_all()
    assert record.deployer_password_ciphertext is None


def test_host_and_schema_scope_guards(target_config, client_for_role):
    client = client_for_role()
    denied = client.post(
        "/api/v1/connections", json=target_config | {"host": "unregistered.example"}
    )
    assert denied.status_code == 422
    connection_id = register(client, target_config)
    path = f"/api/v1/connections/{connection_id}"
    for schemas in [
        ["pg_catalog"],
        ["privacyshield_private"],
        ['enterprise"; DROP TABLE users; --'],
    ]:
        response = client.post(path + "/discover", json={"schemas": schemas})
        assert response.status_code == 422
    assert client.post(path + "/discover", json={"schemas": ["enterprise"]}).status_code == 200


def test_invalid_target_auth_error_is_sanitized(target_config, client_for_role):
    client = client_for_role()
    missing = target_config | {"scanner_username": f"missing_{uuid.uuid4().hex}"}
    connection_id = register(client, missing)
    response = client.post(f"/api/v1/connections/{connection_id}/test")
    assert response.status_code == 502
    assert target_config["scanner_password"] not in response.text
    assert missing["scanner_username"] not in response.text
    assert response.json()["detail"] == "Target database connection or metadata query failed"


@pytest.mark.parametrize(
    "username,password_env",
    [
        ("postgres", "TEST_TARGET_SUPERUSER_PASSWORD"),
        ("ps_deployer", "TEST_TARGET_DEPLOYER_PASSWORD"),
    ],
)
def test_privileged_or_owner_capable_scanner_is_rejected(
    target_config, client_for_role, username, password_env
):
    password = os.environ.get(password_env)
    if not password:
        pytest.fail(f"{password_env} is required for scanner least-privilege integration checks")
    client = client_for_role()
    connection_id = register(
        client,
        target_config
        | {
            "scanner_username": username,
            "scanner_password": password,
        },
    )
    response = client.post(
        f"/api/v1/connections/{connection_id}/test", json={"schemas": ["enterprise"]}
    )
    assert response.status_code == 422, response.text
    assert password not in response.text


def test_target_transactions_read_only_and_caps_enforced(target_config, monkeypatch):
    record = DatabaseConnection(
        **{key: value for key, value in target_config.items() if key != "scanner_password"},
        scanner_password_ciphertext=encrypt_credential(target_config["scanner_password"]),
        created_by=uuid.uuid4(),
    )
    with target_session(record) as target:
        assert (
            target.execute("SHOW transaction_read_only").fetchone()["transaction_read_only"] == "on"
        )
        assert target.execute("SHOW statement_timeout").fetchone()["statement_timeout"] == "10s"
    monkeypatch.setattr("app.services.discovery.catalog.MAX_TABLES", 1)
    with pytest.raises(DiscoveryError, match="table limit"):
        discover_catalog(record, ["enterprise"])


def test_quoted_identifiers_and_inherited_write_or_ownership_are_detected(target_config):
    password = os.environ.get("TEST_TARGET_SUPERUSER_PASSWORD")
    assert password, (
        "Real target admin credential is required for isolated test fixture provisioning"
    )
    suffix = uuid.uuid4().hex[:16]
    schema_name = f"ps_test_{suffix}"
    scanner, writer = f"ps_test_scan_{suffix}", f"ps_test_write_{suffix}"
    scanner_password = secrets.token_urlsafe(24)
    table_name = 'Customer; "quoted"'
    qualified = sql.Identifier(schema_name, table_name)
    with psycopg.connect(
        host=target_config["host"],
        port=target_config["port"],
        dbname="enterprise_demo",
        user="postgres",
        password=password,
        connect_timeout=5,
        autocommit=True,
    ) as admin:
        try:
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN NOINHERIT PASSWORD {}").format(
                    sql.Identifier(scanner),
                    sql.Literal(scanner_password),
                )
            )
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(writer)))
            admin.execute(
                sql.SQL("GRANT CONNECT ON DATABASE enterprise_demo TO {}").format(
                    sql.Identifier(scanner),
                )
            )
            admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name)))
            admin.execute(
                sql.SQL(
                    'CREATE TABLE {} ("Customer ID" bigint PRIMARY KEY, "full name" text)'
                ).format(qualified)
            )
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}, {}").format(
                    sql.Identifier(schema_name),
                    sql.Identifier(scanner),
                    sql.Identifier(writer),
                )
            )
            admin.execute(
                sql.SQL("GRANT SELECT ON {} TO {}").format(qualified, sql.Identifier(scanner))
            )
            record = DatabaseConnection(
                name="isolated discovery fixture",
                host=target_config["host"],
                port=target_config["port"],
                database_name="enterprise_demo",
                ssl_mode="disable",
                scanner_username=scanner,
                scanner_password_ciphertext=encrypt_credential(scanner_password),
                created_by=uuid.uuid4(),
            )
            admin.execute(
                sql.SQL("INSERT INTO {} VALUES (1, 'Synthetic test row')").format(qualified)
            )
            discovered = discover_catalog(record, [schema_name])
            # A new populated table without ANALYZE has unknown statistics, not zero rows.
            assert discovered["tables"][0]["row_estimate"] == -1
            assert discovered["tables"][0]["name"] == table_name
            assert discovered["tables"][0]["primary_key"] == ["Customer ID"]
            assert discovered["tables"][0]["columns"][1]["name"] == "full name"
            admin.execute(
                sql.SQL('GRANT UPDATE ("full name") ON {} TO {}').format(
                    qualified,
                    sql.Identifier(writer),
                )
            )
            admin.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(writer), sql.Identifier(scanner))
            )
            with pytest.raises(DiscoveryError, match="must not own or modify"):
                discover_catalog(record, [schema_name])
            admin.execute(
                sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(writer), sql.Identifier(scanner))
            )
            admin.execute(
                sql.SQL("ALTER TABLE {} OWNER TO {}").format(qualified, sql.Identifier(scanner))
            )
            with pytest.raises(DiscoveryError, match="must not own or modify"):
                discover_catalog(record, [schema_name])
        finally:
            # Exact test-owned names only; existing source tables are never changed.
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name))
            )
            for role in [scanner, writer]:
                admin.execute(
                    sql.SQL("REVOKE CONNECT ON DATABASE enterprise_demo FROM {}").format(
                        sql.Identifier(role)
                    )
                )
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))

"""The single-service deployment, end to end, on a server that looks like a new managed one.

One PostgreSQL instance, an admin user that is **not** a superuser (CREATEDB and
CREATEROLE only), one environment secret, no shell, no Redis, no worker. The
first test runs the bootstrap; the second starts ``scripts/render/start-all.sh``
exactly as the hosted image does and uses the product over HTTP, including a
kill in the middle of a scan.

The Celery worker used by the other integration tests cannot reach this server,
so every job here is necessarily run by the process under test.
"""

import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass

import httpx
import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row

from app.render_bootstrap import SECRET_LABELS, derive_secret
from tests.support import hosted
from tests.support.pristine import RESERVED_ROLES, PristineServer, pristine_server

pytestmark = pytest.mark.integration

EXTERNAL_URL = "https://privacy-shield-test.onrender.com"
ADMIN_EMAIL = "owner@example.com"


@dataclass
class Instance:
    server: PristineServer
    admin_role: str
    admin_password: str
    control_db: str
    app_secret: str
    admin_login_password: str

    @property
    def admin_url(self) -> str:
        return (
            f"postgresql://{self.admin_role}:{self.admin_password}"
            f"@{self.server.host}:{self.server.port}/{self.control_db}"
        )

    def secret(self, name: str) -> str:
        return derive_secret(self.app_secret, name)

    def connect_as(self, role: str, secret_name: str, dbname: str, **kwargs):
        return psycopg.connect(
            host=self.server.host,
            port=self.server.port,
            user=role,
            password=self.secret(secret_name),
            dbname=dbname,
            connect_timeout=5,
            autocommit=True,
            **kwargs,
        )

    def all_secrets(self) -> list[str]:
        return [
            self.app_secret,
            self.admin_password,
            self.admin_login_password,
            *(self.secret(name) for name in SECRET_LABELS),
        ]

    def bootstrap_env(self, runtime_file) -> dict[str, str]:
        # Deliberately not inherited: these are the only variables a deployment sets.
        return hosted.child_environment(
            {
                "CONTROL_ADMIN_URL": self.admin_url,
                "APP_SECRET": self.app_secret,
                "BOOTSTRAP_DB_SSLMODE": "disable",  # the test server has no TLS
                "PS_RUNTIME_ENV_FILE": str(runtime_file),
            },
            inherit=False,
        )


@pytest.fixture(scope="module")
def server():
    with pristine_server() as found:
        yield found


def _provision(server: PristineServer, *, createdb: bool) -> Instance:
    """An admin role that owns one database, as a managed platform hands out."""
    suffix = uuid.uuid4().hex[:8]
    created = Instance(
        server=server,
        admin_role="render_admin_" + suffix,
        admin_password=secrets.token_hex(16),
        control_db="render_main_" + suffix,
        app_secret=secrets.token_urlsafe(40),
        admin_login_password=secrets.token_urlsafe(18),
    )
    attributes = "LOGIN CREATEROLE" + (" CREATEDB" if createdb else "")
    with server.connect() as connection:
        connection.execute(
            sql.SQL("CREATE ROLE {} {} PASSWORD {}").format(
                sql.Identifier(created.admin_role),
                sql.SQL(attributes),
                sql.Literal(created.admin_password),
            )
        )
        connection.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(created.control_db), sql.Identifier(created.admin_role)
            )
        )
    return created


def _remove(server: PristineServer, created: Instance) -> None:
    """Return the server to its empty state: exactly what was made, nothing else."""
    with server.connect() as connection:
        for database in (created.control_db, "enterprise_demo"):
            connection.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database))
            )
        # Every ps_ role the bootstrap made, including any added later.
        provisioned = connection.execute(
            "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname LIKE 'ps\\_%'"
        ).fetchall()
        for role in (*(row[0] for row in provisioned), created.admin_role):
            connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@pytest.fixture(scope="module")
def instance(server):
    # What Render documents for its Postgres user: may create databases and
    # roles, is not a superuser, owns one database.
    created = _provision(server, createdb=True)
    try:
        yield created
    finally:
        if not server.disposable:
            _remove(server, created)  # a provided server outlives the test


def _run_bootstrap(instance: Instance, runtime_file) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "app.render_bootstrap"],
        cwd=hosted.BACKEND_ROOT,
        env=instance.bootstrap_env(runtime_file),
        capture_output=True,
        text=True,
        timeout=180,
    )


def _state(instance: Instance) -> dict:
    """Everything the bootstrap is responsible for, as comparable data."""
    state = {}
    with instance.server.connect() as c:
        state["roles"] = c.execute(
            "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,"
            " rolreplication, rolbypassrls, rolconfig::text FROM pg_catalog.pg_roles"
            " WHERE rolname !~ '^pg_' ORDER BY 1"
        ).fetchall()
        state["memberships"] = c.execute(
            "SELECT roleid::regrole::text, member::regrole::text, grantor::regrole::text,"
            " admin_option, inherit_option, set_option FROM pg_catalog.pg_auth_members"
            " WHERE roleid::regrole::text !~ '^pg_' ORDER BY 1, 2, 3"
        ).fetchall()
        state["databases"] = c.execute(
            "SELECT datname, datdba::regrole::text, datacl::text FROM pg_catalog.pg_database"
            " ORDER BY 1"
        ).fetchall()
    for database in (instance.control_db, "enterprise_demo"):
        with instance.server.connect(database) as c:
            state[database] = {
                "schemas": c.execute(
                    "SELECT nspname, nspowner::regrole::text, nspacl::text"
                    " FROM pg_catalog.pg_namespace WHERE nspname !~ '^pg_'"
                    " AND nspname <> 'information_schema' ORDER BY 1"
                ).fetchall(),
                "relations": c.execute(
                    "SELECT n.nspname, c.relname, c.relkind::text, c.relowner::regrole::text,"
                    " c.relacl::text FROM pg_catalog.pg_class c"
                    " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                    " WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"
                    " AND c.relkind IN ('r', 'v', 'S') ORDER BY 1, 2"
                ).fetchall(),
                "extensions": c.execute(
                    "SELECT extname, extnamespace::regnamespace::text FROM pg_catalog.pg_extension"
                    " ORDER BY 1"
                ).fetchall(),
            }
    with instance.server.connect("enterprise_demo") as c:
        state["demo_rows"] = [
            c.execute(
                sql.SQL("SELECT count(*) FROM enterprise.{}").format(sql.Identifier(t))
            ).fetchone()[0]
            for t in ("customers", "accounts", "transactions", "support_records")
        ]
        state["pseudonym_keys"] = c.execute(
            "SELECT domain, key_version, encode(key, 'hex')"
            " FROM privacyshield_private.pseudonym_keys ORDER BY 1"
        ).fetchall()
    with instance.server.connect(instance.control_db) as c:
        state["migration"] = c.execute("SELECT version_num FROM alembic_version").fetchall()
    return json.loads(json.dumps(state, default=str))


def _refused(connection, statement: str) -> str:
    """The SQLSTATE that rejected ``statement``; fails if it was allowed."""
    try:
        with connection.transaction():
            connection.execute(statement)
    except psycopg.Error as exc:
        return exc.sqlstate
    pytest.fail(f"Statement was allowed but must be refused: {statement}")


DENIED = "42501"  # insufficient_privilege


def test_admin_without_createdb_still_gets_a_restricted_application_role(server, tmp_path):
    """The fallback: ownership cannot be handed to ps_migrator. Runs first, and
    removes everything it made, because role names are shared by the whole server."""
    limited = _provision(server, createdb=False)
    runtime_file = tmp_path / "runtime_env"
    try:
        for attempt in (1, 2):  # the fallback must be repeatable too
            result = _run_bootstrap(limited, runtime_file)
            output = result.stdout + result.stderr
            assert result.returncode == 0, output
            assert "Control-plane ownership handoff unavailable" in output
            assert "Migrations will run as the admin user" in output
            # No CREATEDB: the demo database cannot be created, and the log says so.
            assert "Cannot create database enterprise_demo" in output
            assert "needs the CREATEDB attribute" in output
            assert ("creating role ps_app" in output) is (attempt == 1)
            for value in limited.all_secrets():
                assert value not in output
        runtime = runtime_file.read_text()
        assert "export PS_TARGET_READY=0" in runtime
        assert re.search(r"^export DATABASE_URL='postgresql\+psycopg://ps_app:", runtime, re.M)
        # The one thing lost: migrations use the admin account, not ps_migrator.
        assert (
            f"export MIGRATION_DATABASE_URL='postgresql+psycopg://{limited.admin_role}:" in runtime
        )

        with server.connect(limited.control_db) as connection:
            owners = connection.execute(
                "SELECT (SELECT datdba::regrole::text FROM pg_catalog.pg_database"
                " WHERE datname = current_database()),"
                " (SELECT relowner::regrole::text FROM pg_catalog.pg_class"
                " WHERE relname = 'audit_events')"
            ).fetchone()
        assert owners == (limited.admin_role, limited.admin_role)
        # The application role owns nothing, so its audit trail stays append-only.
        with limited.connect_as("ps_app", "APP_DATABASE_PASSWORD", limited.control_db) as app:
            app.execute(
                "INSERT INTO audit_events (id, event_type, subject_type, correlation_id, details)"
                " VALUES (gen_random_uuid(), 'FALLBACK_CHECK', 'test', gen_random_uuid(), '{}')"
            )
            assert _refused(app, "UPDATE audit_events SET event_type = 'x'") == DENIED
            assert _refused(app, "DELETE FROM audit_events") == DENIED
            assert _refused(app, "TRUNCATE audit_events") == DENIED
            assert _refused(app, "ALTER TABLE users ADD COLUMN t int") == DENIED
            assert _refused(app, "CREATE TABLE public.t (id int)") == DENIED
    finally:
        _remove(server, limited)


def test_bootstrap_as_non_superuser_provisions_one_instance(instance, tmp_path):
    runtime_file = tmp_path / "runtime_env"

    first = _run_bootstrap(instance, runtime_file)
    assert first.returncode == 0, first.stdout + first.stderr
    output = first.stdout + first.stderr
    assert "Bootstrap: the admin user is not a superuser" in output
    assert "Bootstrap: creating database enterprise_demo" in output
    for role in RESERVED_ROLES:
        assert f"Bootstrap: creating role {role}" in output
    assert "Bootstrap: control database is now owned by ps_migrator" in output
    assert "Bootstrap complete." in output
    assert "handoff unavailable" not in output and "provisioning failed" not in output
    for value in instance.all_secrets():
        assert value not in output

    # The runtime environment is private to the service user and carries the
    # least-privilege URLs, never the admin credentials.
    assert stat.S_IMODE(runtime_file.stat().st_mode) == 0o600
    runtime = runtime_file.read_text()
    assert re.search(r"^export DATABASE_URL='postgresql\+psycopg://ps_app:", runtime, re.M)
    assert re.search(
        r"^export MIGRATION_DATABASE_URL='postgresql\+psycopg://ps_migrator:", runtime, re.M
    )
    assert "export PS_TARGET_DATABASE=enterprise_demo" in runtime
    assert "export PS_TARGET_READY=1" in runtime
    assert instance.admin_role not in runtime and instance.admin_password not in runtime
    assert instance.app_secret not in runtime

    # A second run succeeds and leaves every role, grant, owner, table and row as it was.
    before = _state(instance)
    second = _run_bootstrap(instance, runtime_file)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "creating" not in second.stdout + second.stderr
    assert _state(instance) == before

    # Ownership was handed to the migration role; nothing the application uses is privileged.
    databases = {name: owner for name, owner, _ in before["databases"]}
    assert databases[instance.control_db] == "ps_migrator"
    assert databases["enterprise_demo"] == instance.admin_role
    roles = {row[0]: row for row in before["roles"]}
    for role in RESERVED_ROLES:
        _, superuser, _, createrole, createdb, can_login, replication, bypassrls, _ = roles[role]
        assert not (superuser or createrole or createdb or replication or bypassrls), role
        # The view owner and the two audience group roles are never logged in to.
        assert can_login is (role not in {"ps_view_owner", "ps_support", "ps_analyst"})
    assert before["demo_rows"] == [100, 100, 100, 100]

    # --- target database: reader, scanner, deployer
    with instance.connect_as("ps_reader", "READER_PASSWORD", "enterprise_demo") as reader:
        assert _refused(reader, "SELECT * FROM enterprise.customers LIMIT 1") == DENIED
        assert _refused(reader, "SELECT * FROM privacyshield_private.pseudonym_keys") == DENIED
        assert _refused(reader, "CREATE TABLE privacyshield_masked.t (id int)") == DENIED
    with instance.connect_as("ps_scanner", "SCANNER_PASSWORD", "enterprise_demo") as scanner:
        assert scanner.execute("SELECT count(*) FROM enterprise.customers").fetchone()[0] == 100
        assert scanner.execute("SHOW default_transaction_read_only").fetchone()[0] == "on"
        assert _refused(scanner, "UPDATE enterprise.customers SET phone = 'x'") == "25006"
        # Even with the session default switched off, the grants allow no write.
        scanner.execute("SET default_transaction_read_only = off")
        assert _refused(scanner, "UPDATE enterprise.customers SET phone = 'x'") == DENIED
        assert _refused(scanner, "DELETE FROM enterprise.support_records") == DENIED
        assert (
            _refused(scanner, "INSERT INTO enterprise.transactions VALUES (1, 99, 1, 'x')")
            == DENIED
        )
        assert _refused(scanner, "CREATE TABLE enterprise.t (id int)") == DENIED
        assert _refused(scanner, "SELECT * FROM privacyshield_private.pseudonym_keys") == DENIED
    with instance.connect_as("ps_deployer", "DEPLOYER_PASSWORD", "enterprise_demo") as deployer:
        # NOINHERIT: nothing until it explicitly assumes the view-owner role.
        assert _refused(deployer, "SELECT * FROM enterprise.customers LIMIT 1") == DENIED
        deployer.execute("SET ROLE ps_view_owner")
        assert deployer.execute("SELECT count(*) FROM enterprise.customers").fetchone()[0] == 100
        assert _refused(deployer, "UPDATE enterprise.customers SET phone = 'x'") == DENIED

    # --- control database: audit rows are append-only for the application role
    with instance.connect_as("ps_app", "APP_DATABASE_PASSWORD", instance.control_db) as app:
        app.execute(
            "INSERT INTO audit_events (id, event_type, subject_type, correlation_id, details)"
            " VALUES (gen_random_uuid(), 'BOOTSTRAP_CHECK', 'test', gen_random_uuid(), '{}')"
        )
        assert _refused(app, "UPDATE audit_events SET event_type = 'x'") == DENIED
        assert _refused(app, "DELETE FROM audit_events") == DENIED
        assert _refused(app, "TRUNCATE audit_events") == DENIED
        assert _refused(app, "CREATE TABLE public.t (id int)") == DENIED
        assert _refused(app, "ALTER TABLE users ADD COLUMN t int") == DENIED
        assert _refused(app, "DROP TABLE audit_events") == DENIED

    # --- one instance, two databases: no role can open the other side's database
    for role, secret_name, database in (
        ("ps_reader", "READER_PASSWORD", instance.control_db),
        ("ps_scanner", "SCANNER_PASSWORD", instance.control_db),
        ("ps_deployer", "DEPLOYER_PASSWORD", instance.control_db),
        ("ps_app", "APP_DATABASE_PASSWORD", "enterprise_demo"),
        ("ps_migrator", "MIGRATOR_PASSWORD", "enterprise_demo"),
    ):
        with pytest.raises(psycopg.OperationalError, match="CONNECT privilege"):
            instance.connect_as(role, secret_name, database).close()

    # --- administrator settings are validated before anything is written
    def seed(**variables):
        result = subprocess.run(
            ["sh", "-c", '. "$1"; exec python -m app.render_seed', "sh", str(runtime_file)],
            cwd=hosted.BACKEND_ROOT,
            env=instance.bootstrap_env(runtime_file) | variables,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode, result.stdout + result.stderr

    code, text = seed()
    assert code == 0, text
    assert "ADMIN_EMAIL and ADMIN_PASSWORD are not set; no account created" in text
    assert "Demo connection: no administrator yet; skipped until one exists" in text
    code, text = seed(ADMIN_EMAIL=ADMIN_EMAIL)
    assert code == 1 and "Setup failed: ADMIN_PASSWORD is not set" in text
    code, text = seed(ADMIN_EMAIL="not-an-email", ADMIN_PASSWORD="long enough password")
    assert code == 1 and "Setup failed: ADMIN_EMAIL is not a valid email address" in text
    code, text = seed(ADMIN_EMAIL=ADMIN_EMAIL, ADMIN_PASSWORD="too-short-1")
    assert code == 1, text
    assert "ADMIN_PASSWORD was rejected: Passwords must contain 12 to 128 characters" in text
    assert "too-short-1" not in text
    with instance.server.connect(instance.control_db) as connection:
        assert connection.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM database_connections").fetchone()[0] == 0


def _start_script(instance: Instance, tmp_path, static_dir, name: str, **overrides):
    port = hosted.free_port()
    env = instance.bootstrap_env(tmp_path / f"{name}.runtime_env")
    env.update(
        {
            "PORT": str(port),
            "STATIC_DIR": str(static_dir),
            "ADMIN_EMAIL": ADMIN_EMAIL,
            "ADMIN_PASSWORD": instance.admin_login_password,
            "RENDER_EXTERNAL_URL": EXTERNAL_URL,
            # Nothing listens here: the deployment has no Redis.
            "REDIS_URL": f"redis://127.0.0.1:{hosted.closed_port()}/0",
            "OLLAMA_BASE_URL": os.environ["TEST_OLLAMA_BASE_URL"],
        }
    )
    env.update(overrides)
    server = hosted.ServerProcess(
        ["sh", "scripts/render/start-all.sh"], env, tmp_path / f"{name}.log", port
    )
    server.start(ready_path="/health", timeout=180)
    return server


def _scan_row(instance: Instance, scan_id: str) -> dict:
    with instance.server.connect(instance.control_db) as connection:
        connection.row_factory = dict_row
        return connection.execute(
            "SELECT status, attempt_count FROM scan_jobs WHERE id = %s", (scan_id,)
        ).fetchone()


def test_start_script_serves_the_whole_product_from_one_process(instance, tmp_path):
    assert os.environ.get("TEST_OLLAMA_BASE_URL"), "Controlled HTTP Ollama double required"
    with httpx.Client(base_url=os.environ["TEST_OLLAMA_BASE_URL"], trust_env=False) as model:
        assert model.post("/control", json={"mode": "valid"}).status_code == 200
    static_dir = hosted.make_static_dir(tmp_path / "static")
    servers = []
    try:
        # ------------------------------------------------------------ first start
        first = _start_script(instance, tmp_path, static_dir, "first")
        servers.append(first)
        log = first.log()
        assert "Bootstrap complete." in log
        assert "Administrator created" in log
        assert "Demo connection registered" in log
        assert "the scanner role can see 4 tables" in log
        assert f"Serving frontend from {static_dir}, jobs run in-process" in log

        with httpx.Client(base_url=first.base_url, timeout=10, trust_env=False) as anonymous:
            health = anonymous.get("/health")
            assert (health.status_code, health.text) == (200, "ok")
            assert health.headers["content-type"].startswith("text/plain")
            ready = anonymous.get("/api/v1/health/ready")
            assert ready.status_code == 200
            assert ready.json()["checks"] == {"database": "ok", "redis": "not_used", "jobs": "ok"}
            page = anonymous.get("/connections")  # a browser route: the app shell
            assert page.status_code == 200 and '<div id="root">' in page.text
            assert "script-src 'self'" in page.headers["content-security-policy"]
            missing = anonymous.get("/api/v1/does-not-exist")
            assert missing.status_code == 404 and missing.json() == {"detail": "Not Found"}

        # The browser talks to https://<name>.onrender.com; the proxy forwards plain HTTP.
        session = hosted.ApiSession(first.base_url, EXTERNAL_URL)
        attacker = hosted.ApiSession(first.base_url, "https://attacker.example")
        rejected = attacker.login(ADMIN_EMAIL, instance.admin_login_password)
        assert rejected.status_code == 403
        attacker.close()
        assert session.login(ADMIN_EMAIL, instance.admin_login_password).status_code == 200
        session_cookie = next(c for c in session.set_cookie_headers if c.startswith("ps_session="))
        assert "Secure" in session_cookie and "HttpOnly" in session_cookie
        assert session.get("/api/v1/auth/me").json()["role"] == "ADMIN"

        connections = session.get("/api/v1/connections").json()["items"]
        assert len(connections) == 1
        demo = connections[0]
        assert demo["name"] == "Synthetic enterprise"
        assert (demo["host"], demo["port"]) == (instance.server.host, instance.server.port)
        assert demo["database_name"] == "enterprise_demo" and demo["ssl_mode"] == "disable"
        assert (demo["scanner_username"], demo["deployer_username"]) == (
            "ps_scanner",
            "ps_deployer",
        )
        assert not any("password" in key for key in demo)

        # ------------------------------------- a scan is interrupted by a hard kill
        snapshot_id = hosted.discover(session, demo["id"])
        scan_id = hosted.queue_scan(session, demo["id"], snapshot_id)
        # RUNNING is committed before the detector loads, so there is time to observe it.
        session.wait_for(
            f"/api/v1/scans/{scan_id}",
            lambda body: body["status"] != "QUEUED",
            timeout=30,
            interval=0.02,
        )
        first.kill()
        interrupted = _scan_row(instance, scan_id)
        assert interrupted == {"status": "RUNNING", "attempt_count": 1}, interrupted
        assert f"Job started: scan {scan_id}" in first.log()
        assert f"Job ended: scan {scan_id}" not in first.log()
        # The existing rule re-dispatches a row whose last dispatch is over 30 seconds
        # old. Age it instead of sleeping; nothing else about the row is touched.
        with instance.server.connect(instance.control_db) as connection:
            connection.execute(
                "UPDATE scan_jobs SET dispatch_attempted_at = now() - interval '5 minutes'"
                " WHERE id = %s",
                (scan_id,),
            )

        # ----------------------------------------------------------- second start
        # A changed ADMIN_PASSWORD must not reset the existing administrator.
        second = _start_script(
            instance, tmp_path, static_dir, "second", ADMIN_PASSWORD="a-different-password-123"
        )
        servers.append(second)
        log = second.log()
        assert "Administrator already exists; its password was left unchanged" in log
        assert "Demo connection already registered; left unchanged" in log
        assert "creating" not in log
        session.client.close()
        session.client = httpx.Client(base_url=second.base_url, timeout=30, trust_env=False)
        # Same APP_SECRET, same derived key: the earlier session and CSRF token still work.
        assert session.get("/api/v1/auth/me").status_code == 200
        stranger = hosted.ApiSession(second.base_url, EXTERNAL_URL)
        assert stranger.login(ADMIN_EMAIL, "a-different-password-123").status_code == 401
        assert stranger.login(ADMIN_EMAIL, instance.admin_login_password).status_code == 200
        stranger.close()

        # The startup sweep finds the abandoned row and runs it as a second attempt.
        scan = hosted.wait_scan(session, scan_id)
        assert scan["status"] == "COMPLETED", scan
        assert _scan_row(instance, scan_id) == {"status": "COMPLETED", "attempt_count": 2}
        assert f"Job started: scan {scan_id}" in second.log()
        findings = session.get(f"/api/v1/scans/{scan_id}/results?page=1&page_size=100").json()
        columns = {item["column_name"] for item in findings["items"]}
        assert {"email", "phone"} <= columns

        classification = hosted.classify(session, scan_id)
        assert classification["status"] == "COMPLETED", classification

        policy, deployment, preview = hosted.deploy_policy(session, demo["id"], snapshot_id)
        assert policy["status"] == "DEPLOYED", policy
        assert deployment["status"] == "COMPLETED", deployment

        # No Celery beat exists here: the in-process sweep is what seals audit events
        # into the hash chain. Checked in the database first, because the verify
        # endpoint seals before it reads and would hide a sweep that never did.
        deadline = time.monotonic() + 45
        while True:
            with instance.server.connect(instance.control_db) as connection:
                sealed, events = connection.execute(
                    "SELECT (SELECT count(*) FROM audit_chain), (SELECT count(*) FROM audit_events)"
                ).fetchone()
            if sealed == events or time.monotonic() > deadline:
                break
            time.sleep(1)
        assert sealed == events > 5, (sealed, events)
        chain = session.get("/api/v1/audit-events/verify").json()
        assert chain["status"] == "INTACT" and chain["pending"] == 0, chain
        assert chain["sealed"] == events
        session.close()

        view = f'{preview["view_schema"]}."{preview["view_name"]}"'
        with instance.connect_as(
            "ps_reader", "READER_PASSWORD", "enterprise_demo", row_factory=dict_row
        ) as reader:
            rows = reader.execute(
                f"SELECT account_number, balance FROM {view} ORDER BY id LIMIT 5"
            ).fetchall()
            assert rows and all(row["account_number"] == "[REDACTED]" for row in rows)
            assert all(row["balance"] is None for row in rows)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                reader.execute("SELECT * FROM enterprise.accounts LIMIT 1")
        # After real use the application role still cannot rewrite its audit trail.
        with instance.connect_as("ps_app", "APP_DATABASE_PASSWORD", instance.control_db) as app:
            assert app.execute("SELECT count(*) FROM audit_events").fetchone()[0] > 5
            assert _refused(app, "UPDATE audit_events SET event_type = 'x'") == DENIED
            assert _refused(app, "DELETE FROM audit_events") == DENIED

        # ------------------------------------------------------------- clean stop
        assert second.terminate(timeout=40) in (0, -15)
        assert "Application shutdown complete." in second.log()

        # Nothing secret and no source value in either start's output.
        for server in servers:
            text = server.log()
            for value in (*instance.all_secrets(), "a-different-password-123"):
                assert value not in text
            assert "customer1@example.com" not in text and "Synthetic Customer" not in text
    finally:
        for server in servers:
            server.kill()
        time.sleep(0.2)

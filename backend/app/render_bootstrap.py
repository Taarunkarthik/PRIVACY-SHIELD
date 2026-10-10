"""One-time, idempotent provisioning for hosted (Render) deployments.

Docker entrypoint init scripts do not run on managed platforms, so the API and
worker start through this module before serving: it creates the least-privilege
roles, schemas, extension, and synthetic fixtures on the control and target
databases, derives the runtime connection URLs, and applies migrations.

It never prints passwords. It is safe to run concurrently (a Postgres advisory
lock serializes the two processes) and safe to re-run.
"""

import logging
import os
import subprocess
import sys
from contextlib import contextmanager
from urllib.parse import quote, unquote, urlsplit

import psycopg
from psycopg import sql

logger = logging.getLogger("privacyshield.bootstrap")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

RUNTIME_ENV_FILE = "/tmp/ps_runtime_env"
LOCK_KEY = 0x9A17C0DE


class BootstrapError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise BootstrapError(f"{name} is required for the hosted bootstrap")
    return value


def _conninfo(url: str) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql"):
        raise BootstrapError("Admin database URL must be a postgres URL")
    return {
        "host": parts.hostname or "localhost",
        "port": parts.port or 5432,
        "user": unquote(parts.username or "postgres"),
        "password": unquote(parts.password or ""),
        "dbname": (parts.path or "/").lstrip("/") or "postgres",
    }


def _sslmode() -> str:
    # Managed platforms require TLS; local verification can opt out.
    return os.environ.get("BOOTSTRAP_DB_SSLMODE", "require")


def _runtime_url(admin_url: str, user: str, password: str) -> str:
    parts = urlsplit(admin_url)
    host = parts.hostname or "localhost"
    port = parts.port or 5432
    dbname = (parts.path or "/").lstrip("/")
    return (
        f"postgresql+psycopg://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@{host}:{port}/{dbname}?sslmode={_sslmode()}"
    )


@contextmanager
def _admin(url: str, dbname: str | None = None):
    params = _conninfo(url)
    if dbname:
        params["dbname"] = dbname
    with psycopg.connect(**params, autocommit=True, connect_timeout=10) as connection:
        yield connection


def _role_exists(connection: psycopg.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", (name,)
    ).fetchone()
    return bool(row)


def _ensure_role(
    connection: psycopg.Connection,
    name: str,
    password: str,
    *,
    login: bool,
    noinherit: bool = False,
) -> None:
    # role names are fixed constants, never request input, so interpolation is safe.
    # Utility statements (CREATE/ALTER ROLE) reject bind parameters, so the
    # password is composed as a safely quoted SQL literal.
    attrs = ("LOGIN" if login else "NOLOGIN") + (" NOINHERIT" if noinherit else "")
    attrs += " NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
    if not _role_exists(connection, name):
        connection.execute(
            sql.SQL("CREATE ROLE {} {}").format(sql.Identifier(name), sql.SQL(attrs))
        )
    # Passwords are applied on every run so a rotated secret takes effect.
    connection.execute(
        sql.SQL("ALTER ROLE {} WITH {} PASSWORD {}").format(
            sql.Identifier(name), sql.SQL(attrs), sql.Literal(password)
        )
    )


def provision_control(admin_url: str, app_password: str, migrator_password: str) -> tuple[str, str]:
    """Create control-plane roles. Returns (database_url, migration_database_url)."""
    with _admin(admin_url) as connection:
        _ensure_role(connection, "ps_migrator", migrator_password, login=True)
        _ensure_role(connection, "ps_app", app_password, login=True)
        dbname = _conninfo(admin_url)["dbname"]
        owner = connection.execute("SELECT current_user").fetchone()[0]
        try:
            # Best effort: hand ownership to the migration role so runtime roles
            # stay least-privileged. Managed platforms may forbid this.
            connection.execute(f"GRANT ps_migrator TO {owner}")
            connection.execute(f"ALTER DATABASE {dbname} OWNER TO ps_migrator")
            connection.execute("ALTER SCHEMA public OWNER TO ps_migrator")
            connection.execute(f"REVOKE ALL ON DATABASE {dbname} FROM PUBLIC")
            connection.execute(f"GRANT CONNECT ON DATABASE {dbname} TO ps_migrator, ps_app")
            connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            connection.execute("GRANT USAGE ON SCHEMA public TO ps_app")
            owned = True
        except psycopg.Error as exc:
            logger.warning(
                "Control-plane ownership handoff unavailable (%s); running as the database owner.",
                type(exc).__name__,
            )
            owned = False
    if owned:
        return (
            _runtime_url(admin_url, "ps_app", app_password),
            _runtime_url(admin_url, "ps_migrator", migrator_password),
        )
    # Fallback: the database owner runs both migrations and the app. Recorded as
    # a deployment limitation; oversight is weaker than the least-privilege path.
    owner_url = _conninfo(admin_url)
    owner_runtime = (
        f"postgresql+psycopg://{quote(owner_url['user'], safe='')}:"
        f"{quote(owner_url['password'], safe='')}@{owner_url['host']}:{owner_url['port']}"
        f"/{owner_url['dbname']}?sslmode={_sslmode()}"
    )
    return owner_runtime, owner_runtime


TARGET_DEMO_ROWS = """
INSERT INTO enterprise.customers (full_name,email,phone,pan,aadhaar,address,profile)
SELECT 'Synthetic Customer ' || n,
       'customer' || n || '@example.com',
       '+91 90000 ' || lpad(n::text, 5, '0'),
       'ABCDE' || lpad(n::text,4,'0') || 'F',
       '2345 6789 ' || lpad(n::text,4,'0'),
       n || ' Example Street, Demo City',
       jsonb_build_object('contact', jsonb_build_object('email','alternate' || n || '@example.org'),
                          'preferences', jsonb_build_object('newsletter', n % 2 = 0))
FROM generate_series(1,100) AS n;
INSERT INTO enterprise.accounts(customer_id,account_number,balance)
SELECT id, 'DEMO' || lpad(id::text,12,'0'), id * 123.45 FROM enterprise.customers;
INSERT INTO enterprise.transactions(account_id,sequence_number,amount,note)
SELECT id, 1, 25.00, 'Synthetic payment reference' FROM enterprise.accounts;
INSERT INTO enterprise.support_records(customer_id,related_account_id,related_sequence_number,body)
SELECT id,id,1,'Please contact customer' || id || '@example.com about my demo account.'
FROM enterprise.customers;
"""


def provision_target(
    admin_url: str, scanner_password: str, deployer_password: str, reader_password: str
) -> None:
    """Create the target roles, schemas, pgcrypto, and synthetic fixtures."""
    with _admin(admin_url) as connection:
        _ensure_role(connection, "ps_scanner", scanner_password, login=True)
        _ensure_role(connection, "ps_view_owner", "unused-nologin", login=False)
        _ensure_role(connection, "ps_deployer", deployer_password, login=True, noinherit=True)
        _ensure_role(connection, "ps_reader", reader_password, login=True)
        connection.execute("GRANT ps_view_owner TO ps_deployer")
        connection.execute("REVOKE ALL ON DATABASE enterprise_demo FROM PUBLIC")
        connection.execute(
            "GRANT CONNECT ON DATABASE enterprise_demo TO ps_scanner, ps_deployer, ps_reader"
        )
        connection.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        connection.execute("CREATE SCHEMA IF NOT EXISTS enterprise")
        connection.execute(
            "CREATE SCHEMA IF NOT EXISTS privacyshield_masked AUTHORIZATION ps_view_owner"
        )
        connection.execute(
            "CREATE SCHEMA IF NOT EXISTS privacyshield_private AUTHORIZATION ps_view_owner"
        )
        connection.execute("CREATE SCHEMA IF NOT EXISTS extensions")
        connection.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions")
        connection.execute("GRANT USAGE ON SCHEMA extensions TO ps_view_owner, ps_reader")
        connection.execute("GRANT USAGE ON SCHEMA enterprise TO ps_scanner, ps_view_owner")
        connection.execute("GRANT USAGE ON SCHEMA privacyshield_masked TO ps_reader")
        for role, timeout in (("ps_scanner", "10s"), ("ps_deployer", "30s"), ("ps_reader", "10s")):
            connection.execute(f"ALTER ROLE {role} SET statement_timeout = '{timeout}'")
        connection.execute("ALTER ROLE ps_scanner SET default_transaction_read_only = on")

        if connection.execute("SELECT to_regclass('enterprise.customers')").fetchone()[0] is None:
            connection.execute(
                "CREATE TABLE enterprise.customers ("
                "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                "full_name text NOT NULL, email text NOT NULL UNIQUE, phone text, pan text,"
                "aadhaar text, address text, profile jsonb NOT NULL DEFAULT '{}'::jsonb,"
                "created_at timestamptz NOT NULL DEFAULT now())"
            )
            connection.execute(
                "CREATE TABLE enterprise.accounts ("
                "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                "customer_id bigint NOT NULL REFERENCES enterprise.customers(id),"
                "account_number text NOT NULL UNIQUE,"
                " balance numeric(14,2) NOT NULL CHECK (balance >= 0),"
                "currency char(3) NOT NULL DEFAULT 'INR')"
            )
            connection.execute(
                "CREATE TABLE enterprise.transactions ("
                "account_id bigint NOT NULL REFERENCES enterprise.accounts(id),"
                "sequence_number integer NOT NULL CHECK (sequence_number > 0),"
                "amount numeric(14,2) NOT NULL, note text,"
                "PRIMARY KEY (account_id, sequence_number))"
            )
            connection.execute(
                "CREATE TABLE enterprise.support_records ("
                "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                "customer_id bigint NOT NULL REFERENCES enterprise.customers(id),"
                "related_account_id bigint, related_sequence_number integer, body text NOT NULL,"
                "FOREIGN KEY (related_account_id, related_sequence_number)"
                " REFERENCES enterprise.transactions(account_id, sequence_number))"
            )
            connection.execute(
                "CREATE INDEX ix_accounts_customer_id ON enterprise.accounts(customer_id)"
            )
            connection.execute(
                "CREATE INDEX ix_support_customer_id ON enterprise.support_records(customer_id)"
            )
            connection.execute(
                "CREATE INDEX ix_support_transaction ON enterprise.support_records"
                "(related_account_id, related_sequence_number)"
            )
            connection.execute(TARGET_DEMO_ROWS)

        connection.execute(
            "GRANT SELECT ON ALL TABLES IN SCHEMA enterprise TO ps_scanner, ps_view_owner"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS privacyshield_private.pseudonym_keys ("
            "domain text PRIMARY KEY, key_version integer NOT NULL CHECK (key_version > 0),"
            "key bytea NOT NULL CHECK (octet_length(key) = 32))"
        )
        connection.execute(
            "ALTER TABLE privacyshield_private.pseudonym_keys OWNER TO ps_view_owner"
        )
        connection.execute(
            "INSERT INTO privacyshield_private.pseudonym_keys(domain,key_version,key)"
            " SELECT 'demo', 1, extensions.gen_random_bytes(32)"
            " WHERE NOT EXISTS"
            " (SELECT 1 FROM privacyshield_private.pseudonym_keys WHERE domain='demo')"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS privacyshield_private.deployment_receipts ("
            "deployment_id uuid PRIMARY KEY, plan_hash text NOT NULL,"
            "deployed_at timestamptz NOT NULL DEFAULT now())"
        )
        connection.execute(
            "ALTER TABLE privacyshield_private.deployment_receipts OWNER TO ps_view_owner"
        )


def apply_migrations(migration_url: str, app_url: str) -> None:
    env = os.environ | {"MIGRATION_DATABASE_URL": migration_url, "DATABASE_URL": app_url}
    result = subprocess.run(["alembic", "upgrade", "head"], env=env, cwd="/app")
    if result.returncode:
        raise BootstrapError("alembic upgrade head failed during bootstrap")


def write_runtime_env(database_url: str, migration_url: str, target_host: str) -> None:
    with open(RUNTIME_ENV_FILE, "w", encoding="utf-8") as stream:
        stream.write(f"DATABASE_URL='{database_url}'\n")
        stream.write(f"MIGRATION_DATABASE_URL='{migration_url}'\n")
        stream.write(f"TARGET_ALLOWED_HOSTS='{target_host}'\n")


def main() -> int:
    control_admin = _require("CONTROL_ADMIN_URL")
    target_admin = _require("TARGET_ADMIN_URL")
    app_password = _require("APP_DATABASE_PASSWORD")
    migrator_password = _require("MIGRATOR_PASSWORD")
    scanner_password = _require("SCANNER_PASSWORD")
    deployer_password = _require("DEPLOYER_PASSWORD")
    reader_password = _require("READER_PASSWORD")

    with _admin(control_admin) as lock_connection:
        lock_connection.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))
        try:
            database_url, migration_url = provision_control(
                control_admin, app_password, migrator_password
            )
            try:
                provision_target(target_admin, scanner_password, deployer_password, reader_password)
            except psycopg.Error as exc:
                # The target demo needs its own least-privilege roles; without
                # them the API still runs but target scanning/masking cannot.
                logger.warning(
                    "Target provisioning failed (%s); target scans will not work"
                    " until it succeeds.",
                    type(exc).__name__,
                )
            apply_migrations(migration_url, database_url)
            write_runtime_env(database_url, migration_url, _conninfo(target_admin)["host"])
            logger.info("Bootstrap complete.")
        finally:
            lock_connection.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, psycopg.Error) as exc:
        logger.error("Bootstrap failed: %s", exc)
        sys.exit(1)

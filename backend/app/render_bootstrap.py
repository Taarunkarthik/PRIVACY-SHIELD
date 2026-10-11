"""One-time, idempotent provisioning for hosted (Render) deployments.

Docker entrypoint init scripts do not run on managed platforms, so the API and
worker start through this module before serving: it creates the least-privilege
roles, schemas, extension, and synthetic fixtures on the control and target
databases, derives the runtime connection URLs, and applies migrations.

Two layouts are supported:

* two database instances: ``CONTROL_ADMIN_URL`` and ``TARGET_ADMIN_URL``;
* one instance (a free plan allows only one): ``CONTROL_ADMIN_URL`` alone. The
  synthetic target then lives in a second database, ``enterprise_demo``, on the
  same server, created here if it is missing.

The admin user does not have to be a superuser. A managed-platform user with
CREATEDB and CREATEROLE is enough; the statements below are written to work for
that user as well as for a superuser.

Secrets that are not set explicitly are derived from ``APP_SECRET``, so a
deployment needs one secret instead of six and keeps the same values across
restarts.

It never prints passwords. It is safe to run concurrently (a Postgres advisory
lock serializes the two processes) and safe to re-run.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import shlex
import subprocess
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import psycopg
from cryptography.fernet import Fernet
from psycopg import sql

logger = logging.getLogger("privacyshield.bootstrap")

# Where the values for the server process are written. The start scripts source
# this file; PS_RUNTIME_ENV_FILE moves it (used by tests that run side by side).
RUNTIME_ENV_FILE = os.environ.get("PS_RUNTIME_ENV_FILE") or "/tmp/ps_runtime_env"
LOCK_KEY = 0x9A17C0DE
TARGET_DATABASE = "enterprise_demo"
SSL_MODES = ("disable", "require", "verify-ca", "verify-full")
MIN_APP_SECRET_LENGTH = 32
# One label per derived secret. Changing a label changes that secret on every
# existing deployment, so these stay as they are.
SECRET_LABELS = {
    "CREDENTIAL_ENCRYPTION_KEY": "credential-encryption-key",
    "APP_DATABASE_PASSWORD": "app-database-password",
    "MIGRATOR_PASSWORD": "migrator-password",
    "SCANNER_PASSWORD": "scanner-password",
    "DEPLOYER_PASSWORD": "deployer-password",
    "READER_PASSWORD": "reader-password",
}


class BootstrapError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise BootstrapError(f"{name} is required for the hosted bootstrap")
    return value


def describe(exc: BaseException) -> str:
    """A log-safe description of a database error.

    ``str(exc)`` can quote the failing statement, and role statements contain
    passwords, so only the server's message, detail and SQLSTATE are used.
    """
    diag = getattr(exc, "diag", None)
    primary = getattr(diag, "message_primary", None)
    if primary:
        detail = getattr(diag, "message_detail", None)
        state = getattr(diag, "sqlstate", None)
        return (
            primary + (f" ({detail})" if detail else "") + (f" [SQLSTATE {state}]" if state else "")
        )
    if isinstance(exc, psycopg.OperationalError):
        # A failed connection has no statement; libpq's text names host and user only.
        return " ".join(str(exc).split())[:300] or type(exc).__name__
    return type(exc).__name__


def derive_secret(app_secret: str, name: str) -> str:
    """HMAC-SHA256(APP_SECRET, label): deterministic, and distinct for each name."""
    digest = hmac.new(
        app_secret.encode("utf-8"),
        f"privacyshield:{SECRET_LABELS[name]}:v1".encode("ascii"),
        hashlib.sha256,
    ).digest()
    if name == "CREDENTIAL_ENCRYPTION_KEY":
        return base64.urlsafe_b64encode(digest).decode("ascii")  # a 32-byte Fernet key
    return digest.hex()


def resolve_secrets(environ: Mapping[str, str]) -> dict[str, str]:
    """Every secret the deployment needs: the explicit value if set, else derived."""
    app_secret = (environ.get("APP_SECRET") or "").strip()
    if app_secret and len(app_secret) < MIN_APP_SECRET_LENGTH:
        raise BootstrapError(
            f"APP_SECRET is {len(app_secret)} characters long; it must be at least"
            f" {MIN_APP_SECRET_LENGTH}. Set a longer random value and redeploy."
        )
    resolved = {}
    for name in SECRET_LABELS:
        explicit = environ.get(name)
        if explicit:
            resolved[name] = explicit
        elif app_secret:
            resolved[name] = derive_secret(app_secret, name)
        else:
            raise BootstrapError(
                f"Set APP_SECRET (one random value of at least {MIN_APP_SECRET_LENGTH}"
                f" characters), or set {name} explicitly."
            )
    try:
        Fernet(resolved["CREDENTIAL_ENCRYPTION_KEY"].encode("ascii"))
    except (ValueError, UnicodeError):
        raise BootstrapError(
            "CREDENTIAL_ENCRYPTION_KEY is set but is not a valid Fernet key. Delete"
            " that variable to derive the key from APP_SECRET."
        ) from None
    return resolved


def _conninfo(url: str) -> dict:
    try:
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
    except ValueError:
        # urlsplit quotes the part it could not read, which can be a piece of the
        # password (one containing "/", "?" or "#" must be percent-encoded).
        raise BootstrapError(
            "Admin database URL could not be read. Copy the Internal Database URL"
            " exactly, and percent-encode any / ? # @ : in a password you typed."
        ) from None


def _sslmode() -> str:
    # Managed platforms require TLS; local verification can opt out.
    mode = os.environ.get("BOOTSTRAP_DB_SSLMODE") or "require"
    if mode not in SSL_MODES:
        raise BootstrapError(f"BOOTSTRAP_DB_SSLMODE must be one of: {', '.join(SSL_MODES)}")
    return mode


def _with_database(admin_url: str, dbname: str) -> str:
    """The same server and credentials as ``admin_url``, for another database."""
    return urlsplit(admin_url)._replace(path="/" + dbname, query="", fragment="").geturl()


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
    try:
        # The same TLS mode as the runtime URLs, so a server that cannot provide
        # it fails here, with an explanation, instead of later inside the app.
        connection = psycopg.connect(
            **params, sslmode=_sslmode(), autocommit=True, connect_timeout=10
        )
    except psycopg.OperationalError as exc:
        raise BootstrapError(
            f"Cannot connect to database {params['dbname']} on {params['host']}:"
            f"{params['port']} as {params['user']}: {describe(exc)}. Check that the"
            " value is the database's Internal Database URL and that the database is"
            " available and in the same region as this service."
        ) from None
    with connection:
        yield connection


def _is_superuser(connection: psycopg.Connection) -> bool:
    return bool(
        connection.execute(
            "SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user"
        ).fetchone()[0]
    )


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
    superuser, may_createdb, may_bypassrls = connection.execute(
        "SELECT rolsuper, rolsuper OR rolcreatedb, rolsuper OR rolbypassrls"
        " FROM pg_catalog.pg_roles WHERE rolname = current_user"
    ).fetchone()
    attrs = ("LOGIN" if login else "NOLOGIN") + (" NOINHERIT" if noinherit else "")
    restricted = " NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
    if not _role_exists(connection, name):
        logger.info("Bootstrap: creating role %s", name)
        try:
            connection.execute(
                sql.SQL("CREATE ROLE {} {}").format(
                    sql.Identifier(name), sql.SQL(attrs + restricted)
                )
            )
        except psycopg.errors.InsufficientPrivilege as exc:
            raise BootstrapError(
                f"This database user cannot create roles ({describe(exc)}). It needs the"
                " CREATEROLE attribute; PrivacyShield cannot separate scanner, deployer"
                " and reader access without its own roles."
            ) from None
    # ALTER ROLE refuses NOSUPERUSER, NOCREATEDB and NOBYPASSRLS from a user who
    # lacks the attribute itself, even though they only restate the default. So
    # each one is stated only if this user holds it, and the result is checked
    # below instead of assumed.
    alterable = (
        attrs
        + (" NOSUPERUSER" if superuser else "")
        + (" NOCREATEDB" if may_createdb else "")
        + " NOCREATEROLE"
        + (" NOBYPASSRLS" if may_bypassrls else "")
    )
    try:
        # Passwords are applied on every run so a rotated secret takes effect.
        # A role that cannot log in gets no password at all.
        connection.execute(
            sql.SQL("ALTER ROLE {} WITH {} PASSWORD {}").format(
                sql.Identifier(name),
                sql.SQL(alterable),
                sql.Literal(password) if login else sql.SQL("NULL"),
            )
        )
        if not login and not superuser:
            # PostgreSQL 16+: creating a role gives its creator ADMIN OPTION but
            # not the right to act as it. Owning schemas and tables on its behalf
            # (AUTHORIZATION, OWNER TO) needs an explicit membership.
            connection.execute(sql.SQL("GRANT {} TO CURRENT_USER").format(sql.Identifier(name)))
    except psycopg.errors.InsufficientPrivilege as exc:
        raise BootstrapError(
            f"Role {name} exists but this database user may not manage it"
            f" ({describe(exc)}). It was probably created by a different user. Use a"
            " new database, or the user that created the role."
        ) from None
    elevated = connection.execute(
        "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication"
        " FROM pg_catalog.pg_roles WHERE rolname = %s",
        (name,),
    ).fetchone()[0]
    if elevated:
        raise BootstrapError(
            f"Role {name} has administrative attributes that this database user cannot"
            " remove. Drop the role as a superuser, or use a new database."
        )


def _owns_database_and_schema(connection: psycopg.Connection, role: str) -> bool:
    """Whether ``role`` owns the current database and creates in ``public``."""
    return bool(
        connection.execute(
            "SELECT pg_catalog.pg_get_userbyid(d.datdba) = %(role)s"
            " AND pg_catalog.has_schema_privilege(%(role)s, 'public', 'CREATE')"
            " FROM pg_catalog.pg_database d WHERE d.datname = current_database()",
            {"role": role},
        ).fetchone()[0]
    )


def ensure_database(connection: psycopg.Connection, name: str) -> None:
    """Create a database on the connected server if it does not exist."""
    exists = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (name,)
    ).fetchone()
    if exists:
        return
    logger.info("Bootstrap: creating database %s", name)
    try:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    except psycopg.Error as exc:
        raise BootstrapError(
            f"Cannot create database {name} ({describe(exc)}). The user in"
            " CONTROL_ADMIN_URL needs the CREATEDB attribute, or set TARGET_ADMIN_URL"
            " to a second database instance."
        ) from None


def provision_control(admin_url: str, app_password: str, migrator_password: str) -> tuple[str, str]:
    """Create control-plane roles. Returns (database_url, migration_database_url)."""
    with _admin(admin_url) as connection:
        _ensure_role(connection, "ps_migrator", migrator_password, login=True)
        _ensure_role(connection, "ps_app", app_password, login=True)
        database = sql.Identifier(connection.execute("SELECT current_database()").fetchone()[0])
        if not _owns_database_and_schema(connection, "ps_migrator"):
            try:
                # Hand ownership to the migration role so runtime roles stay
                # least-privileged. A non-superuser needs CREATEDB for this and
                # must itself be a member of the new owner (the GRANT).
                connection.execute("GRANT ps_migrator TO CURRENT_USER")
                connection.execute(
                    sql.SQL("ALTER DATABASE {} OWNER TO ps_migrator").format(database)
                )
                connection.execute("ALTER SCHEMA public OWNER TO ps_migrator")
                logger.info("Bootstrap: control database is now owned by ps_migrator")
            except psycopg.Error as exc:
                logger.warning(
                    "Control-plane ownership handoff unavailable (%s). Migrations will run"
                    " as the admin user; the application still runs as ps_app.",
                    describe(exc),
                )
        try:
            # In a single-instance deployment the target roles exist on this server
            # too. Without CONNECT they cannot open the control database at all.
            connection.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(database))
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO ps_migrator, ps_app").format(database)
            )
            connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            connection.execute("GRANT USAGE ON SCHEMA public TO ps_app")
        except psycopg.Error as exc:
            raise BootstrapError(
                "The user in CONTROL_ADMIN_URL cannot manage privileges on its database"
                f" ({describe(exc)}). It must own the database or be a superuser."
            ) from None
        migrator_can_migrate = connection.execute(
            "SELECT pg_catalog.has_schema_privilege('ps_migrator', 'public', 'CREATE')"
        ).fetchone()[0]
    app_url = _runtime_url(admin_url, "ps_app", app_password)
    if migrator_can_migrate:
        return app_url, _runtime_url(admin_url, "ps_migrator", migrator_password)
    # Fallback: the admin user owns the schema and runs the migrations. The
    # application still connects as ps_app, with only the table privileges the
    # migrations grant, so it cannot alter the schema or rewrite audit rows.
    # What is lost is the separate migration credential: schema changes are
    # made with the instance's admin account instead of a dedicated role.
    admin = _conninfo(admin_url)
    return app_url, _runtime_url(admin_url, admin["user"], admin["password"])


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
        # Masking audiences (docs/masking-audiences.md): passwordless group roles
        # an operator grants to their own users. Created once, never altered.
        for audience_role in ("ps_support", "ps_analyst"):
            if not _role_exists(connection, audience_role):
                logger.info("Bootstrap: creating role %s", audience_role)
                connection.execute(
                    f"CREATE ROLE {audience_role} NOLOGIN NOSUPERUSER NOCREATEDB"
                    " NOCREATEROLE NOBYPASSRLS"
                )
            connection.execute(f"GRANT USAGE ON SCHEMA privacyshield_masked TO {audience_role}")
        for role, timeout in (("ps_scanner", "10s"), ("ps_deployer", "30s"), ("ps_reader", "10s")):
            connection.execute(f"ALTER ROLE {role} SET statement_timeout = '{timeout}'")
        connection.execute("ALTER ROLE ps_scanner SET default_transaction_read_only = on")

        if connection.execute("SELECT to_regclass('enterprise.customers')").fetchone()[0] is None:
            logger.info("Bootstrap: creating the synthetic demo tables")
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
    # alembic.ini sits beside the app package: /app in the image, backend/ in a checkout.
    backend_root = Path(__file__).resolve().parent.parent
    env = os.environ | {"MIGRATION_DATABASE_URL": migration_url, "DATABASE_URL": app_url}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"], env=env, cwd=backend_root
    )
    if result.returncode:
        raise BootstrapError(
            "Database migrations failed (alembic upgrade head); the lines above show why"
        )


def _allowed_hosts(target_host: str) -> str:
    """The operator's TARGET_ALLOWED_HOSTS, if any, plus the provisioned target."""
    configured = (os.environ.get("TARGET_ALLOWED_HOSTS") or "").strip()
    try:
        hosts = json.loads(configured) if configured.startswith("[") else configured.split(",")
    except ValueError:
        hosts = []
    hosts = [str(host).strip() for host in hosts if str(host).strip()]
    return ",".join(dict.fromkeys([*hosts, target_host]))


def write_runtime_env(
    database_url: str,
    migration_url: str,
    target: dict,
    encryption_key: str,
    *,
    target_ready: bool,
) -> None:
    """Write the values the start script exports before it starts the server.

    The file holds credentials, so it is created readable by this user only.
    The ``PS_TARGET_*`` values are not secret: they tell the seeding step where
    the demo database is.
    """
    values = {
        "DATABASE_URL": database_url,
        "MIGRATION_DATABASE_URL": migration_url,
        "CREDENTIAL_ENCRYPTION_KEY": encryption_key,
        "TARGET_ALLOWED_HOSTS": _allowed_hosts(target["host"]),
        "PS_TARGET_HOST": target["host"],
        "PS_TARGET_PORT": str(target["port"]),
        "PS_TARGET_DATABASE": target["dbname"],
        "PS_TARGET_SSLMODE": _sslmode(),
        "PS_TARGET_READY": "1" if target_ready else "0",
    }
    descriptor = os.open(RUNTIME_ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.chmod(RUNTIME_ENV_FILE, 0o600)
        for name, value in values.items():
            # "export" matters: the start scripts source this file and then exec
            # the server, which only inherits exported variables.
            stream.write(f"export {name}={shlex.quote(value)}\n")


def main() -> int:
    control_admin = _require("CONTROL_ADMIN_URL")
    secrets = resolve_secrets(os.environ)
    _sslmode()  # Reject an invalid mode before any connection is attempted.
    control = _conninfo(control_admin)
    target_admin = os.environ.get("TARGET_ADMIN_URL") or None
    single_instance = target_admin is None
    if single_instance:
        if control["dbname"] == TARGET_DATABASE:
            raise BootstrapError(
                f"The database in CONTROL_ADMIN_URL is named {TARGET_DATABASE}, the name"
                " reserved for the synthetic demo data. Create the database under a"
                " different name."
            )
        target_admin = _with_database(control_admin, TARGET_DATABASE)
    target = _conninfo(target_admin)
    logger.info(
        "Bootstrap: control database %s on %s:%s (TLS mode %s)",
        control["dbname"],
        control["host"],
        control["port"],
        _sslmode(),
    )

    with _admin(control_admin) as lock_connection:
        lock_connection.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))
        try:
            if not _is_superuser(lock_connection):
                logger.info("Bootstrap: the admin user is not a superuser (expected on Render)")
            database_url, migration_url = provision_control(
                control_admin, secrets["APP_DATABASE_PASSWORD"], secrets["MIGRATOR_PASSWORD"]
            )
            target_ready = False
            try:
                if single_instance:
                    ensure_database(lock_connection, TARGET_DATABASE)
                provision_target(
                    target_admin,
                    secrets["SCANNER_PASSWORD"],
                    secrets["DEPLOYER_PASSWORD"],
                    secrets["READER_PASSWORD"],
                )
                target_ready = True
                logger.info(
                    "Bootstrap: demo database %s is ready on %s:%s",
                    target["dbname"],
                    target["host"],
                    target["port"],
                )
            except (psycopg.Error, BootstrapError) as exc:
                # The target demo needs its own least-privilege roles; without
                # them the API still runs but target scanning/masking cannot.
                logger.warning(
                    "Target provisioning failed (%s); target scans will not work"
                    " until it succeeds.",
                    exc if isinstance(exc, BootstrapError) else describe(exc),
                )
            logger.info("Bootstrap: applying database migrations")
            apply_migrations(migration_url, database_url)
            write_runtime_env(
                database_url,
                migration_url,
                target,
                secrets["CREDENTIAL_ENCRYPTION_KEY"],
                target_ready=target_ready,
            )
            logger.info("Bootstrap complete.")
        finally:
            lock_connection.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
    return 0


if __name__ == "__main__":
    # Configured here, not on import, so importing this module has no side effects.
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        raise SystemExit(main())
    except BootstrapError as exc:
        logger.error("Bootstrap failed: %s", exc)
        sys.exit(1)
    except psycopg.Error as exc:
        logger.error("Bootstrap failed: %s", describe(exc))
        sys.exit(1)

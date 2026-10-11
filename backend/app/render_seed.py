"""First-run setup for a hosted deployment that has no shell.

Runs after ``app.render_bootstrap`` with the runtime environment loaded, and
before the server starts:

1. creates the administrator named by ``ADMIN_EMAIL`` / ``ADMIN_PASSWORD`` if no
   user has that email. An existing user is left alone; its password is never
   reset from the environment;
2. registers the synthetic demo database as the connection "Synthetic
   enterprise", owned by an administrator, if no connection has that name.

Both steps are idempotent, use the application's own models, validation, hashing
and credential encryption, and never log a password.
"""

import logging
import os
import sys
from uuid import UUID

from cryptography.fernet import InvalidToken
from email_validator import EmailNotValidError, validate_email
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.cli import create_admin
from app.core.audit import record_event
from app.core.database import session_factory
from app.core.security import decrypt_credential, encrypt_credential
from app.demo_datasets import dataset_for
from app.models import DatabaseConnection, User
from app.render_bootstrap import BootstrapError, resolve_secrets
from app.schemas.connections import ConnectionCreate
from app.services.discovery.catalog import DiscoveryError, discover_catalog, validate_target_host

logger = logging.getLogger("privacyshield.setup")

DEMO_CONNECTION_NAME = "Synthetic enterprise"
DEMO_SCHEMAS = ["enterprise"]


class SetupError(RuntimeError):
    """A configuration problem the operator has to fix; the message says how."""


def ensure_admin(email: str | None, password: str | None) -> bool:
    """Create the configured administrator if absent. True if it was created."""
    if not email and not password:
        logger.info("Administrator: ADMIN_EMAIL and ADMIN_PASSWORD are not set; no account created")
        return False
    if not email or not password:
        missing = "ADMIN_PASSWORD" if email else "ADMIN_EMAIL"
        raise SetupError(f"{missing} is not set. Set both ADMIN_EMAIL and ADMIN_PASSWORD.")
    try:
        normalized = validate_email(email, check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        raise SetupError("ADMIN_EMAIL is not a valid email address.") from None
    with session_factory()() as db:
        existing = db.execute(
            select(User.role, User.is_active).where(User.email == normalized)
        ).first()
    if existing:
        logger.info("Administrator already exists; its password was left unchanged")
        if existing.role != "ADMIN" or not existing.is_active:
            # Changed on the Users page since it was created. It is left as it is:
            # startup must never hand back access an administrator took away.
            logger.warning(
                "The ADMIN_EMAIL account is no longer an active administrator;"
                " it was not changed. Another administrator can restore it on the Users page."
            )
        return False
    try:
        # The CLI's own function: validated email, 12 to 128 characters, Argon2,
        # and an ADMIN_BOOTSTRAPPED audit event.
        create_admin(normalized, password)
    except ValueError as exc:
        # Fixed text about the allowed length; the value itself is never echoed.
        raise SetupError(f"ADMIN_PASSWORD was rejected: {exc}.") from None
    logger.info("Administrator created")
    return True


def _owner(db, preferred_email: str | None) -> UUID | None:
    """The configured administrator if present, else the earliest active one."""
    if preferred_email:
        try:
            normalized = validate_email(preferred_email, check_deliverability=False)
        except EmailNotValidError:
            normalized = None
        if normalized is not None:
            found = db.scalar(
                select(User.id).where(
                    User.email == normalized.normalized.lower(),
                    User.role == "ADMIN",
                    User.is_active.is_(True),
                )
            )
            if found:
                return found
    return db.scalar(
        select(User.id)
        .where(User.role == "ADMIN", User.is_active.is_(True))
        .order_by(User.created_at, User.id)
        .limit(1)
    )


def ensure_demo_connection(
    *,
    host: str,
    port: int,
    database: str,
    ssl_mode: str,
    scanner_password: str,
    deployer_password: str,
    owner_email: str | None = None,
    name: str = DEMO_CONNECTION_NAME,
    schemas: list[str] | None = None,
) -> bool:
    """Register a demo target under ``name`` if absent. True if it was created."""
    schemas = schemas or DEMO_SCHEMAS
    with session_factory()() as db:
        existing = db.scalar(select(DatabaseConnection).where(DatabaseConnection.name == name))
        if existing is not None:
            try:
                decrypt_credential(existing.scanner_password_ciphertext)
                if existing.deployer_password_ciphertext:
                    decrypt_credential(existing.deployer_password_ciphertext)
            except InvalidToken:
                # The encryption key changed (a new APP_SECRET), so the stored
                # values are unreadable for good. Nothing is lost by replacing them.
                existing.scanner_password_ciphertext = encrypt_credential(scanner_password)
                existing.deployer_password_ciphertext = encrypt_credential(deployer_password)
                record_event(
                    db,
                    actor_id=None,
                    event_type="CONNECTION_UPDATED",
                    subject_type="database_connection",
                    subject_id=existing.id,
                )
                db.commit()
                logger.warning(
                    "Demo connection: stored credentials could not be read with the current"
                    " key (APP_SECRET changed); they were re-encrypted"
                )
                return False
            logger.info("Demo connection already registered; left unchanged")
            return False
        owner = _owner(db, owner_email)
        if owner is None:
            logger.info("Demo connection: no administrator yet; skipped until one exists")
            return False
        try:
            payload = ConnectionCreate(
                name=name,
                host=host,
                port=port,
                database_name=database,
                ssl_mode=ssl_mode,
                scanner_username="ps_scanner",
                scanner_password=scanner_password,
                deployer_username="ps_deployer",
                deployer_password=deployer_password,
            )
            validate_target_host(payload.host)
        except (ValidationError, DiscoveryError):
            # Neither message carries a credential; both are fixed validation text.
            raise SetupError(
                "Demo connection: the target host, port or TLS mode is not acceptable to"
                " the application. Check TARGET_ALLOWED_HOSTS and BOOTSTRAP_DB_SSLMODE."
            ) from None
        record = DatabaseConnection(
            **payload.model_dump(exclude={"scanner_password", "deployer_password"}),
            created_by=owner,
            scanner_password_ciphertext=encrypt_credential(scanner_password),
            deployer_password_ciphertext=encrypt_credential(deployer_password),
        )
        db.add(record)
        db.flush()
        record_event(
            db,
            actor_id=owner,
            event_type="CONNECTION_CREATED",
            subject_type="database_connection",
            subject_id=record.id,
        )
        db.commit()
        logger.info("Demo connection registered: %s on %s:%s", database, payload.host, port)
        try:
            tables = len(discover_catalog(record, schemas)["tables"])
            logger.info("Demo connection checked: the scanner role can see %d tables", tables)
        except DiscoveryError as exc:
            # Not fatal: the connection can be tested again from the Connections page.
            logger.warning("Demo connection registered but not reachable yet: %s", exc.message)
        return True


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    email = (os.environ.get("ADMIN_EMAIL") or "").strip() or None
    password = os.environ.get("ADMIN_PASSWORD") or None
    try:
        ensure_admin(email, password)
        if os.environ.get("PS_TARGET_READY") != "1" or not os.environ.get("PS_TARGET_HOST"):
            logger.warning(
                "Demo connection: the demo database was not provisioned (see the"
                " Bootstrap lines above); not registered"
            )
            return 0
        secrets = resolve_secrets(os.environ)
        ensure_demo_connection(
            host=os.environ["PS_TARGET_HOST"],
            port=int(os.environ.get("PS_TARGET_PORT") or 5432),
            database=os.environ.get("PS_TARGET_DATABASE") or "enterprise_demo",
            ssl_mode=os.environ.get("PS_TARGET_SSLMODE") or "require",
            scanner_password=secrets["SCANNER_PASSWORD"],
            deployer_password=secrets["DEPLOYER_PASSWORD"],
            owner_email=email,
        )
        # The further demo databases the bootstrap made on the same server.
        for database in filter(None, (os.environ.get("PS_DEMO_DATABASES") or "").split(",")):
            dataset = dataset_for(database)
            if dataset is None:
                continue
            ensure_demo_connection(
                host=os.environ["PS_TARGET_HOST"],
                port=int(os.environ.get("PS_TARGET_PORT") or 5432),
                database=dataset.database,
                ssl_mode=os.environ.get("PS_TARGET_SSLMODE") or "require",
                scanner_password=secrets["SCANNER_PASSWORD"],
                deployer_password=secrets["DEPLOYER_PASSWORD"],
                owner_email=email,
                name=dataset.connection_name,
                schemas=[dataset.schema],
            )
    except (SetupError, BootstrapError) as exc:
        logger.error("Setup failed: %s", exc)
        return 1
    except SQLAlchemyError as exc:
        # Driver text can include connection details; the type is enough to act on.
        logger.error(
            "Setup failed: the application database is not usable (%s). Check the"
            " Bootstrap lines above.",
            type(exc).__name__,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

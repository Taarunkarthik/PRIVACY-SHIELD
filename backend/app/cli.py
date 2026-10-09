"""Administrative CLI. Passwords are never accepted as command-line arguments."""

import argparse
import getpass
import sys
from pathlib import Path

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core.audit import record_event
from app.core.database import session_factory
from app.core.security import hash_password
from app.models import User


def create_admin(email: str, password: str) -> None:
    normalized = validate_email(email, check_deliverability=False).normalized.lower()
    encoded = hash_password(password)
    with session_factory()() as db:
        if db.scalar(select(User.id).where(User.email == normalized)):
            raise ValueError("An account with this email already exists; no changes made")
        user = User(email=normalized, password_hash=encoded, role="ADMIN")
        db.add(user)
        db.flush()
        record_event(
            db,
            actor_id=user.id,
            event_type="ADMIN_BOOTSTRAPPED",
            subject_type="user",
            subject_id=user.id,
        )
        db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="PrivacyShield administration")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser(
        "create-admin", help="Create an administrator without a default password"
    )
    admin.add_argument("--email", required=True)
    admin.add_argument(
        "--password-file", type=Path, help="Read a protected secret file for automation"
    )
    args = parser.parse_args()
    try:
        if args.password_file:
            password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
        else:
            password = getpass.getpass("Administrator password (12–128 characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise ValueError("Passwords did not match")
        create_admin(args.email, password)
    except (ValueError, EmailNotValidError) as exc:
        # Validation errors contain fixed messages only, never password content.
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, SQLAlchemyError):
        print(
            "Administrator creation failed; verify file access and database readiness",
            file=sys.stderr,
        )
        return 1
    print("Administrator created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

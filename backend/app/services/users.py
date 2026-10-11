"""Accounts and their roles, managed by an administrator.

There is no self-service sign-up: an administrator creates each account and
chooses its role. Every change is one transaction with its audit event.

Two rules keep the workspace from locking itself out:

* an administrator cannot change their own role or deactivate themselves;
* the last active administrator cannot be demoted or deactivated.

The first makes the second unreachable for a single request, since the person
acting stays an administrator. Two administrators acting on each other at the
same moment could still leave none, so changes to accounts are serialised with
a transaction-level advisory lock and the actor is read again under it.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import record_event
from app.core.security import hash_password
from app.models import User, UserSession
from app.schemas.users import UserCreate, UserPatch

# One fixed key ("PSAC"), so every process takes the same lock.
_ACCOUNTS_LOCK = 0x50534143


class UserFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def list_users(db: Session, *, page: int, page_size: int) -> tuple[list[User], int]:
    total = db.scalar(select(func.count()).select_from(User)) or 0
    items = db.scalars(
        select(User)
        .order_by(User.created_at, User.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return list(items), total


def _acting_administrator(db: Session, actor: User) -> User:
    """Serialise account changes and confirm the actor may still make one.

    Called after anything slow (hashing a password). Between the request being
    authenticated and this point another administrator may have deactivated or
    demoted the person acting; under the lock that can no longer change.
    """
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _ACCOUNTS_LOCK})
    acting = db.get(User, actor.id, populate_existing=True)
    if acting is None or not acting.is_active or acting.role != "ADMIN":
        raise UserFailure("INSUFFICIENT_PERMISSIONS")
    return acting


def create_user(db: Session, actor: User, payload: UserCreate) -> User:
    # Hashed before any lock or write: Argon2 takes a noticeable fraction of a second.
    encoded = hash_password(payload.password.get_secret_value())
    acting = _acting_administrator(db, actor)
    if db.scalar(select(User.id).where(User.email == payload.email)):
        raise UserFailure("EMAIL_IN_USE")
    user = User(email=payload.email, password_hash=encoded, role=payload.role)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        # Only reachable if an account is created outside this lock (the CLI).
        raise UserFailure("EMAIL_IN_USE") from None
    # The event type names the role, because the audit log carries no details:
    # creating an administrator must not look like creating an auditor.
    record_event(
        db,
        actor_id=acting.id,
        event_type=f"USER_CREATED_AS_{user.role}",
        subject_type="user",
        subject_id=user.id,
    )
    db.commit()
    db.refresh(user)
    return user


def _revoke_sessions(db: Session, user_id: UUID, *, keep: UUID | None = None) -> None:
    statement = (
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    if keep is not None:
        statement = statement.where(UserSession.id != keep)
    db.execute(statement)


def _other_active_admins(db: Session, user_id: UUID) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == "ADMIN", User.is_active.is_(True), User.id != user_id)
        )
        or 0
    )


def update_user(
    db: Session,
    actor: User,
    user_id: UUID,
    payload: UserPatch,
    *,
    current_session_id: UUID | None = None,
) -> User:
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise UserFailure("NOTHING_TO_CHANGE")
    encoded = (
        hash_password(payload.password.get_secret_value()) if payload.password is not None else None
    )
    acting = _acting_administrator(db, actor)
    target = db.get(User, user_id, populate_existing=True)
    if target is None:
        raise UserFailure("USER_NOT_FOUND")

    new_role = changes.get("role", target.role)
    new_active = changes.get("is_active", target.is_active)
    loses_admin = (
        target.is_active and target.role == "ADMIN" and not (new_active and new_role == "ADMIN")
    )
    if target.id == acting.id and (new_role != target.role or new_active != target.is_active):
        raise UserFailure("OWN_ACCESS")
    if loses_admin and not _other_active_admins(db, target.id):
        raise UserFailure("LAST_ADMIN")

    events = []
    if new_role != target.role:
        target.role = new_role
        events.append(f"USER_ROLE_SET_{new_role}")
    if new_active != target.is_active:
        target.is_active = new_active
        events.append("USER_REACTIVATED" if new_active else "USER_DEACTIVATED")
        if not new_active:
            _revoke_sessions(db, target.id)
    if encoded is not None:
        target.password_hash = encoded
        events.append("USER_PASSWORD_RESET")
        # Whoever knew the old password is signed out. An administrator changing
        # their own password keeps the session they are using.
        keep = current_session_id if target.id == acting.id else None
        _revoke_sessions(db, target.id, keep=keep)
    for event_type in events:
        record_event(
            db, actor_id=acting.id, event_type=event_type, subject_type="user", subject_id=target.id
        )
    db.commit()
    db.refresh(target)
    return target

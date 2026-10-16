"""Unattended control-plane maintenance shared by the inline sweep and Celery beat.

Nothing here performs a user action, so nothing here writes an audit event: the
audit log records what people did, and a deletion of expired sessions is system
housekeeping. Each function is safe to call from any process at any time and is
expected to fail soft — a database blip leaves the rows for the next run.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import session_factory
from app.models import UserSession

logger = logging.getLogger("privacyshield")

# A session revoked a moment ago may still be needed by an in-flight request
# that loaded it just before sign-out. Keep revoked rows for this grace period
# so pruning can never yank a session out from under a live request.
REVOKED_SESSION_GRACE = timedelta(days=1)


def prune_expired_sessions(
    *,
    grace: timedelta = REVOKED_SESSION_GRACE,
    now: datetime | None = None,
) -> int:
    """Delete sessions that are past ``expires_at`` or long since revoked.

    A row is removed when ``expires_at < now`` or ``revoked_at < now - grace``.
    The grace period means a just-revoked session is never removed while a request
    that already read it may still be finishing. Returns the number of rows
    deleted. A database error is logged and swallowed (the next sweep retries);
    this function never raises out of a periodic sweeper.
    """
    if grace < timedelta(0):
        raise ValueError("grace must not be negative")
    reference = datetime.now(UTC) if now is None else now
    revoked_before = reference - grace
    db = session_factory()()
    try:
        result = db.execute(
            delete(UserSession).where(
                or_(
                    UserSession.expires_at < reference,
                    UserSession.revoked_at < revoked_before,
                )
            )
        )
        db.commit()
        return int(result.rowcount or 0)
    except SQLAlchemyError as exc:
        db.rollback()
        # Rowcounts and timestamps are not secrets, but keep the message to the
        # exception type: the driver's text can quote values from the statement.
        logger.warning("Session pruning skipped (%s)", type(exc).__name__)
        return 0
    finally:
        db.close()

from uuid import UUID

from sqlalchemy.orm import Session

from app.models import AuditEvent


def record_event(
    db: Session,
    *,
    actor_id: UUID | None,
    event_type: str,
    subject_type: str,
    subject_id: UUID | None = None,
) -> None:
    """Append in the caller's transaction; never accept arbitrary request payloads."""
    db.add(
        AuditEvent(
            actor_id=actor_id,
            event_type=event_type,
            subject_type=subject_type,
            subject_id=subject_id,
            details={},
        )
    )

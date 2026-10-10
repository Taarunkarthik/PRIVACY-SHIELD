"""Operator settings and bounded custom detection patterns.

Only bounded, non-secret values are persisted. Pattern regexes are validated
before storage and are never logged; scanning compiles enabled patterns once.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import record_event
from app.models import AppSettings, CustomPattern, User
from app.schemas.settings import (
    MAX_CUSTOM_PATTERNS,
    CustomPatternResponse,
    SettingsPatch,
    SettingsResponse,
)

DEFAULT_WORKSPACE_NAME = "Privacy workspace"
DEFAULT_RETENTION_DAYS = 365


class SettingsFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _settings_row(db: Session) -> AppSettings | None:
    return db.scalar(select(AppSettings).limit(1))


def get_or_create_settings(db: Session, user: User) -> AppSettings:
    """Return the singleton row, creating bounded defaults on first use."""
    row = _settings_row(db)
    if row is not None:
        return row
    row = AppSettings(
        workspace_name=DEFAULT_WORKSPACE_NAME,
        retention_days=DEFAULT_RETENTION_DAYS,
        updated_by=user.id,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        # Another request created the singleton first; adopt it.
        db.rollback()
        row = _settings_row(db)
        if row is None:
            raise SettingsFailure("SETTINGS_CONFLICT") from None
        return row
    record_event(
        db,
        actor_id=user.id,
        event_type="SETTINGS_CREATED",
        subject_type="app_settings",
        subject_id=row.id,
    )
    db.commit()
    return row


def _patterns(db: Session) -> list[CustomPattern]:
    return list(
        db.scalars(
            select(CustomPattern).order_by(CustomPattern.name, CustomPattern.id)
        )
    )


def _response(db: Session, row: AppSettings) -> SettingsResponse:
    return SettingsResponse(
        workspace_name=row.workspace_name,
        retention_days=row.retention_days,
        custom_patterns=[
            CustomPatternResponse.model_validate(pattern) for pattern in _patterns(db)
        ],
    )


def read_settings(db: Session, user: User) -> SettingsResponse:
    row = get_or_create_settings(db, user)
    return _response(db, row)


def _reconcile_patterns(db: Session, user: User, items: list) -> None:
    existing = {pattern.id: pattern for pattern in _patterns(db)}
    by_name = {pattern.name: pattern for pattern in existing.values()}
    keep: set[UUID] = set()
    seen_names: set[str] = set()
    for item in items:
        if item.name in seen_names:
            raise SettingsFailure("DUPLICATE_PATTERN_NAME")
        seen_names.add(item.name)
        match = existing.get(item.id) if item.id is not None else None
        if item.id is not None and match is None:
            raise SettingsFailure("PATTERN_NOT_FOUND")
        if match is None:
            match = by_name.get(item.name)
        if match is None:
            created = CustomPattern(
                name=item.name,
                category=item.category,
                regex=item.regex,
                enabled=item.enabled,
                created_by=user.id,
            )
            db.add(created)
            db.flush()
            keep.add(created.id)
            by_name[item.name] = created
            continue
        collide = by_name.get(item.name)
        if collide is not None and collide.id != match.id:
            raise SettingsFailure("DUPLICATE_PATTERN_NAME")
        match.name = item.name
        match.category = item.category
        match.regex = item.regex
        match.enabled = item.enabled
        keep.add(match.id)
        by_name[item.name] = match
    for pattern_id, pattern in existing.items():
        if pattern_id not in keep:
            db.delete(pattern)


def update_settings(db: Session, user: User, payload: SettingsPatch) -> SettingsResponse:
    get_or_create_settings(db, user)
    row = db.scalar(select(AppSettings).with_for_update())
    if row is None:
        raise SettingsFailure("SETTINGS_CONFLICT")
    if payload.workspace_name is not None:
        row.workspace_name = payload.workspace_name
    if payload.retention_days is not None:
        row.retention_days = payload.retention_days
    if "custom_patterns" in payload.model_fields_set and payload.custom_patterns is not None:
        if len(payload.custom_patterns) > MAX_CUSTOM_PATTERNS:
            raise SettingsFailure("TOO_MANY_PATTERNS")
        _reconcile_patterns(db, user, payload.custom_patterns)
    row.updated_by = user.id
    row.updated_at = datetime.now(UTC)
    record_event(
        db,
        actor_id=user.id,
        event_type="SETTINGS_UPDATED",
        subject_type="app_settings",
        subject_id=row.id,
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise SettingsFailure("PATTERN_CONFLICT") from None
    return _response(db, row)


def enabled_custom_patterns(
    db: Session, limit: int = MAX_CUSTOM_PATTERNS
) -> list[tuple[str, str, str]]:
    """Return ``(name, category, regex)`` for enabled patterns, bounded and stable.

    Intended for a scan to compile once before sampling; the caller must never
    log or retain the regex text alongside source values.
    """
    rows = db.execute(
        select(CustomPattern.name, CustomPattern.category, CustomPattern.regex)
        .where(CustomPattern.enabled.is_(True))
        .order_by(CustomPattern.name, CustomPattern.id)
        .limit(limit)
    ).all()
    return [(row[0], row[1], row[2]) for row in rows]

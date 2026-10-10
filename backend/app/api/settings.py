from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, require_roles
from app.core.database import get_db
from app.models import User
from app.schemas.settings import SettingsPatch, SettingsResponse
from app.services.settings.service import SettingsFailure, read_settings, update_settings

router = APIRouter(prefix="/settings", tags=["Settings"])

_FAILURE_STATUS = {
    "SETTINGS_CONFLICT": 409,
    "PATTERN_CONFLICT": 409,
    "DUPLICATE_PATTERN_NAME": 409,
    "PATTERN_NOT_FOUND": 422,
    "TOO_MANY_PATTERNS": 422,
}


def _handle_failure(exc: SettingsFailure) -> None:
    raise HTTPException(_FAILURE_STATUS.get(exc.code, 400), exc.code) from None


@router.get("", response_model=SettingsResponse)
def get_settings(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> SettingsResponse:
    return read_settings(db, user)


@router.patch("", response_model=SettingsResponse)
def patch_settings(
    payload: SettingsPatch,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> SettingsResponse:
    try:
        return update_settings(db, user, payload)
    except SettingsFailure as exc:
        _handle_failure(exc)

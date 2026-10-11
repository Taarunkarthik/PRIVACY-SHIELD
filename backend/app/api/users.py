from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.dependencies import require_roles
from app.core.database import get_db
from app.models import User
from app.schemas.users import UserCreate, UserItem, UserPage, UserPatch
from app.services.users import UserFailure, create_user, list_users, update_user

router = APIRouter(prefix="/users", tags=["Users"])

_FAILURE_STATUS = {
    "EMAIL_IN_USE": 409,
    "OWN_ACCESS": 409,
    "LAST_ADMIN": 409,
    "USER_NOT_FOUND": 404,
    "NOTHING_TO_CHANGE": 422,
    "INSUFFICIENT_PERMISSIONS": 403,
}


def _handle_failure(exc: UserFailure) -> None:
    raise HTTPException(_FAILURE_STATUS.get(exc.code, 400), exc.code) from None


@router.get("", response_model=UserPage)
def get_users(
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=50, ge=1, le=100),
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> UserPage:
    items, total = list_users(db, page=page, page_size=page_size)
    return UserPage(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=UserItem, status_code=201)
def post_user(
    payload: UserCreate,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> User:
    try:
        return create_user(db, user, payload)
    except UserFailure as exc:
        # Ends the transaction, which is what releases the accounts lock.
        db.rollback()
        _handle_failure(exc)


@router.patch("/{user_id}", response_model=UserItem)
def patch_user(
    user_id: UUID,
    payload: UserPatch,
    request: Request,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> User:
    try:
        return update_user(
            db, user, user_id, payload, current_session_id=request.state.user_session.id
        )
    except UserFailure as exc:
        db.rollback()
        _handle_failure(exc)

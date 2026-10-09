import hmac
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import SESSION_COOKIE, csrf_token, token_hash
from app.models import User, UserSession


def verify_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin not in get_settings().allowed_origins:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin is not allowed")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE, "")
    if not 32 <= len(token) <= 128:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    row = db.execute(
        select(User, UserSession)
        .join(UserSession, UserSession.user_id == User.id)
        .where(
            UserSession.token_hash == token_hash(token),
            UserSession.expires_at > datetime.now(UTC),
            UserSession.revoked_at.is_(None),
            User.is_active.is_(True),
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    user, session = row
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        verify_origin(request)
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), csrf_token(token).encode("ascii")):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token is missing or invalid")
    request.state.user_session = session
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return dependency

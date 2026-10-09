import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, verify_origin
from app.core.audit import record_event
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    csrf_token,
    password_hasher,
    session_token,
    token_hash,
    verify_password,
)
from app.models import User, UserSession
from app.schemas.auth import LoginRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginThrottle:
    """Bounded per-process throttle for the single-process local deployment."""

    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> None:
        settings = get_settings()
        now = time.monotonic()
        cutoff = now - settings.login_window_seconds
        with self._lock:
            # Expired clients are removed to bound storage for the local app.
            for key in list(self._attempts):
                if self._attempts[key][-1] <= cutoff:
                    del self._attempts[key]
            if client not in self._attempts and len(self._attempts) >= 10000:
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again later")
            attempts = self._attempts.setdefault(client, deque())
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= settings.login_attempt_limit:
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Try again later",
                    headers={"Retry-After": str(settings.login_window_seconds)},
                )
            attempts.append(now)


login_throttle = LoginThrottle()


def user_response(user: User, token: str) -> UserResponse:
    return UserResponse(id=user.id, email=user.email, role=user.role, csrf_token=csrf_token(token))


@router.post("/login", response_model=UserResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> UserResponse:
    verify_origin(request)
    login_throttle.check(request.client.host if request.client else "unknown")
    user = db.scalar(select(User).where(User.email == str(payload.email)))
    valid_password = verify_password(
        payload.password.get_secret_value(),
        user.password_hash if user is not None else None,
    )
    if not valid_password or user is None or not user.is_active:
        record_event(db, actor_id=None, event_type="AUTH_LOGIN_FAILED", subject_type="session")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(payload.password.get_secret_value())
    # Rotate an existing browser session on every successful login.
    previous = request.cookies.get(SESSION_COOKIE)
    if previous and len(previous) <= 128:
        old = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(previous)))
        if old is not None:
            old.revoked_at = datetime.now(UTC)
    settings = get_settings()
    token = session_token()
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=token_hash(token),
            expires_at=datetime.now(UTC) + timedelta(hours=settings.session_hours),
        )
    )
    record_event(db, actor_id=user.id, event_type="AUTH_LOGIN", subject_type="session")
    db.commit()
    for key, value, httponly in (
        (SESSION_COOKIE, token, True),
        (CSRF_COOKIE, csrf_token(token), False),
    ):
        response.set_cookie(
            key,
            value,
            max_age=settings.session_hours * 3600,
            httponly=httponly,
            secure=settings.cookie_secure,
            samesite="lax",
            path="/",
        )
    return user_response(user, token)


@router.get("/me", response_model=UserResponse)
def me(request: Request, user: User = Depends(current_user)) -> UserResponse:
    return user_response(user, request.cookies[SESSION_COOKIE])


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> None:
    request.state.user_session.revoked_at = datetime.now(UTC)
    record_event(db, actor_id=user.id, event_type="AUTH_LOGOUT", subject_type="session")
    db.commit()
    settings = get_settings()
    response.delete_cookie(
        SESSION_COOKIE, secure=settings.cookie_secure, httponly=True, samesite="lax"
    )
    response.delete_cookie(CSRF_COOKIE, secure=settings.cookie_secure, samesite="lax")

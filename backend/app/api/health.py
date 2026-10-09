from fastapi import APIRouter
from fastapi.responses import JSONResponse
from redis import Redis
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import get_engine

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready() -> JSONResponse:
    checks = {"database": "unavailable", "redis": "unavailable"}
    try:
        with get_engine().connect() as connection:
            # Table read also verifies migrations and runtime role grants.
            connection.execute(text("SELECT id FROM users LIMIT 1"))
        checks["database"] = "ok"
    except Exception:
        pass  # Do not expose DSNs, database exceptions, or broker credentials.
    try:
        with Redis.from_url(
            get_settings().redis_url.get_secret_value(),
            socket_connect_timeout=2,
            socket_timeout=2,
        ) as redis:
            redis.ping()
        checks["redis"] = "ok"
    except Exception:
        pass
    healthy = all(value == "ok" for value in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "unavailable", "checks": checks},
    )

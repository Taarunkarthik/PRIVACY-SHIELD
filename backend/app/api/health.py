from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import get_engine

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


def _redis_ready() -> bool:
    # Imported here so a deployment without Redis (JOB_RUNNER=inline) never loads the client.
    from redis import Redis

    try:
        with Redis.from_url(
            get_settings().redis_url.get_secret_value(),
            socket_connect_timeout=2,
            socket_timeout=2,
        ) as redis:
            redis.ping()
        return True
    except Exception:
        return False


@router.get("/ready")
def ready() -> JSONResponse:
    inline = get_settings().job_runner == "inline"
    # "not_used": this deployment runs jobs in the API process and has no Redis.
    checks = {"database": "unavailable", "redis": "not_used" if inline else "unavailable"}
    try:
        with get_engine().connect() as connection:
            # Table read also verifies migrations and runtime role grants.
            connection.execute(text("SELECT id FROM users LIMIT 1"))
        checks["database"] = "ok"
    except Exception:
        pass  # Do not expose DSNs, database exceptions, or broker credentials.
    if inline:
        from app.workers import inline as job_runner

        # Without its job threads the process would accept work it never runs.
        checks["jobs"] = job_runner.status()
    elif _redis_ready():
        checks["redis"] = "ok"
    healthy = all(value in ("ok", "not_used") for value in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "unavailable", "checks": checks},
    )

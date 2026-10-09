from celery import Celery
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import get_engine

settings = get_settings()
celery_app = Celery(
    "privacyshield",
    broker=settings.redis_url.get_secret_value(),
    backend=settings.redis_url.get_secret_value(),
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    result_expires=3600,
    task_soft_time_limit=240,
    task_time_limit=300,
)


@celery_app.task(name="privacyshield.smoke")
def smoke(message: str = "foundation") -> dict[str, str]:
    """Exercise a real worker's PostgreSQL connection without reading source data."""
    if not isinstance(message, str) or len(message) > 120:
        raise ValueError("Smoke message must be text of at most 120 characters")
    with get_engine().connect() as connection:
        connection.execute(text("SELECT id FROM users LIMIT 1"))
    return {"status": "ok", "message": message}

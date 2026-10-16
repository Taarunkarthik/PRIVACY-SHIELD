import logging
from uuid import UUID

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
    task_default_queue=settings.celery_queue,
    broker_connection_timeout=2,
    broker_transport_options={"socket_connect_timeout": 2, "socket_timeout": 2},
    task_soft_time_limit=240,
    task_time_limit=300,
    beat_schedule={
        "dispatch-durable-scans": {"task": "privacyshield.dispatch_scans", "schedule": 15.0},
        "dispatch-durable-classifications": {
            "task": "privacyshield.dispatch_classifications",
            "schedule": 15.0,
        },
        "dispatch-deployments": {
            "task": "privacyshield.dispatch_deployments",
            "schedule": 15.0,
        },
        "seal-audit-chain": {"task": "privacyshield.seal_audit_chain", "schedule": 15.0},
        # Rides the same sweep cadence as the chain sealer; the delete itself is
        # idempotent and bounded, so 15 s carries no extra risk.
        "prune-sessions": {"task": "privacyshield.prune_sessions", "schedule": 15.0},
    },
)


@celery_app.task(name="privacyshield.smoke")
def smoke(message: str = "foundation") -> dict[str, str]:
    """Exercise a real worker's PostgreSQL connection without reading source data."""
    if not isinstance(message, str) or len(message) > 120:
        raise ValueError("Smoke message must be text of at most 120 characters")
    with get_engine().connect() as connection:
        connection.execute(text("SELECT id FROM users LIMIT 1"))
    return {"status": "ok", "message": message}


@celery_app.task(name="privacyshield.scan", ignore_result=True, soft_time_limit=600, time_limit=660)
def scan(job_id: str) -> None:
    from app.services.scanning.jobs import run_scan

    try:
        run_scan(UUID(job_id))
    except Exception:
        # Database outages leave durable state for reconciliation. Never log source exceptions.
        logging.getLogger("privacyshield").error(
            "Scan execution interrupted; reconciliation pending"
        )


@celery_app.task(name="privacyshield.dispatch_scans", ignore_result=True)
def dispatch_scans() -> None:
    from app.services.scanning.jobs import dispatch_scan_jobs

    dispatch_scan_jobs()


@celery_app.task(
    name="privacyshield.classify", ignore_result=True, soft_time_limit=900, time_limit=1050
)
def classify(job_id: str) -> None:
    from app.services.classification.jobs import run_classification

    try:
        run_classification(UUID(job_id))
    except Exception:
        logging.getLogger("privacyshield").error(
            "Classification interrupted; reconciliation pending"
        )


@celery_app.task(name="privacyshield.dispatch_classifications", ignore_result=True)
def dispatch_classifications() -> None:
    from app.services.classification.jobs import dispatch_classification_jobs

    dispatch_classification_jobs()


@celery_app.task(
    name="privacyshield.deploy", ignore_result=True, soft_time_limit=120, time_limit=150
)
def deploy(deployment_id: str) -> None:
    from app.services.policies.execution import run_deployment

    try:
        run_deployment(UUID(deployment_id))
    except Exception:
        logging.getLogger("privacyshield").error(
            "Deployment interrupted; reconciliation pending"
        )


@celery_app.task(name="privacyshield.dispatch_deployments", ignore_result=True)
def dispatch_deployments() -> None:
    from app.services.policies.jobs import dispatch_deployments

    dispatch_deployments()


@celery_app.task(name="privacyshield.seal_audit_chain", ignore_result=True)
def seal_audit_chain() -> None:
    from sqlalchemy.exc import SQLAlchemyError

    from app.services.audit_chain import seal_audit_chain as seal

    try:
        seal()
    except SQLAlchemyError:
        # Unsealed events stay unsealed and are picked up by the next run.
        logging.getLogger("privacyshield").error(
            "Audit chain sealing interrupted; retried on the next run"
        )


@celery_app.task(name="privacyshield.prune_sessions", ignore_result=True)
def prune_sessions() -> None:
    from app.services.maintenance import prune_expired_sessions

    # The service already fails soft; the wrapper keeps a beat task from ever
    # propagating and marks the run as handled either way.
    prune_expired_sessions()

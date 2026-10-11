"""Durable deployment jobs and control-plane state transitions."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import or_, select

from app.core.audit import record_event
from app.core.config import get_settings
from app.core.database import session_factory
from app.models import MaskingPolicy, PolicyDeployment
from app.services.scanning.jobs import DISPATCH_INTERVAL_SECONDS, scan_lock

ACTIVE_DEPLOYMENT_STATES = ("QUEUED", "RUNNING", "RECONCILING")
SAFE_ERROR_CODES = {
    "CONNECTION_INACTIVE",
    "CONNECTION_CHANGED",
    "SCHEMA_DRIFT",
    "TABLE_TOO_WIDE",
    "VIEW_OWNER_UNAVAILABLE",
    "ACCESS_VERIFICATION_FAILED",
    "AUDIENCE_ROLE_MISSING",
    "AUDIENCE_VIEW_IN_USE",
    "TARGET_UNAVAILABLE",
    "DEPLOYMENT_FAILED",
    "DEPLOYMENT_TIMEOUT",
    "RECEIPT_CONFLICT",
    "ATTEMPT_LIMIT_EXCEEDED",
    "POLICY_NOT_APPROVED",
    "POLICY_NOT_FOUND",
    "IDEMPOTENCY_CONFLICT",
    "INVALID_PLAN",
}


def enqueue_deployment(deployment_id: UUID, *, force: bool = False) -> bool:
    """Publish a deployment task, guarded by a per-deployment advisory lock."""
    with scan_lock(deployment_id, "deployment") as lease:
        if not lease:
            return False
        with session_factory()() as db:
            deployment = db.get(PolicyDeployment, deployment_id)
            if deployment is None or deployment.status not in ACTIVE_DEPLOYMENT_STATES:
                return False
            now = datetime.now(UTC)
            meta = dict(deployment.target_receipt or {})
            dispatched_at = meta.get("dispatched_at")
            if (
                not force
                and dispatched_at
                and datetime.fromisoformat(dispatched_at)
                > now - timedelta(seconds=DISPATCH_INTERVAL_SECONDS)
            ):
                return False
            meta["dispatched_at"] = now.isoformat()
            deployment.target_receipt = meta
            db.commit()
    try:
        if get_settings().job_runner == "inline":
            from app.workers.inline import submit

            return submit("deploy", deployment_id)
        from app.workers.celery_app import celery_app

        celery_app.send_task(
            "privacyshield.deploy",
            args=[str(deployment_id)],
            task_id="deploy-" + str(deployment_id),
            retry=False,
            ignore_result=True,
        )
        return True
    except Exception:
        return False


def dispatch_deployments() -> int:
    cutoff = (datetime.now(UTC) - timedelta(seconds=DISPATCH_INTERVAL_SECONDS)).isoformat()
    with session_factory()() as db:
        ids = db.scalars(
            select(PolicyDeployment.id)
            .where(
                PolicyDeployment.status.in_(ACTIVE_DEPLOYMENT_STATES),
                or_(
                    PolicyDeployment.target_receipt.is_(None),
                    PolicyDeployment.target_receipt["dispatched_at"].astext < cutoff,
                ),
            )
            .order_by(PolicyDeployment.created_at)
            .limit(10)
        ).all()
    return sum(enqueue_deployment(deployment_id) for deployment_id in ids)


def complete_deployment(deployment_id: UUID, receipt: dict) -> bool:
    with session_factory()() as db:
        deployment = db.get(PolicyDeployment, deployment_id)
        if deployment is None or deployment.status not in ("RUNNING", "RECONCILING"):
            return False
        meta = dict(deployment.target_receipt or {})
        meta.update(receipt)
        deployment.status = "COMPLETED"
        deployment.target_receipt = meta
        deployment.finished_at = datetime.now(UTC)
        deployment.error_code = None
        policy = db.get(MaskingPolicy, deployment.policy_id)
        if policy is not None and policy.status == "APPROVED":
            policy.status = "DEPLOYED"
        record_event(
            db,
            actor_id=deployment.requested_by,
            event_type="DEPLOYMENT_COMPLETED",
            subject_type="policy_deployment",
            subject_id=deployment_id,
        )
        db.commit()
        return True


def fail_deployment(deployment_id: UUID, code: str) -> bool:
    safe_code = code if code in SAFE_ERROR_CODES else "DEPLOYMENT_FAILED"
    with session_factory()() as db:
        deployment = db.get(PolicyDeployment, deployment_id)
        if deployment is None or deployment.status not in ACTIVE_DEPLOYMENT_STATES:
            return False
        deployment.status = "FAILED"
        deployment.error_code = safe_code
        deployment.finished_at = datetime.now(UTC)
        policy = db.get(MaskingPolicy, deployment.policy_id)
        if policy is not None and policy.status == "APPROVED":
            policy.status = "FAILED"
        record_event(
            db,
            actor_id=deployment.requested_by,
            event_type="DEPLOYMENT_FAILED",
            subject_type="policy_deployment",
            subject_id=deployment_id,
        )
        db.commit()
        return True

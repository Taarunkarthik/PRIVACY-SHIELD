"""Fenced, durable advisory classification using metadata-only model inputs."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from billiard.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func, or_, select

from app.core.audit import record_event
from app.core.config import get_settings
from app.core.database import session_factory
from app.models import (
    ClassificationJob,
    ClassificationJobItem,
    PIIClassification,
    ScanJob,
    ScanResult,
    SchemaSnapshot,
)
from app.services.scanning.jobs import DISPATCH_INTERVAL_SECONDS, MAX_ATTEMPTS, scan_lock

SAFE_ERROR_CODES = {
    "OLLAMA_UNAVAILABLE",
    "OLLAMA_TIMEOUT",
    "OLLAMA_HTTP_ERROR",
    "AI_INVALID_RESPONSE",
    "AI_RESPONSE_TOO_LARGE",
    "AI_INPUT_INVALID",
    "AI_INPUT_TOO_LARGE",
    "AI_MODEL_MISMATCH",
    "CLASSIFICATION_FAILED",
    "CLASSIFICATION_TIMEOUT",
    "RESULT_METADATA_MISMATCH",
    "SCAN_NOT_COMPLETED",
    "ATTEMPT_LIMIT_EXCEEDED",
    "PROMPT_VERSION_CHANGED",
}
STOP_ERRORS = {"OLLAMA_UNAVAILABLE", "OLLAMA_TIMEOUT", "OLLAMA_HTTP_ERROR", "AI_MODEL_MISMATCH"}
# Value shapes and the prompt paragraph that explains them have not been run
# against the real model. Set this to False to send exactly the request that
# was verified under prompt v3; stored shapes are then left unused.
SEND_SHAPES = True


class ClassificationFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def enqueue_classification(job_id: UUID, *, force=False) -> bool:
    with scan_lock(job_id, "classification") as lease:
        if not lease:
            return False
        with session_factory()() as db:
            job = db.get(ClassificationJob, job_id)
            if job is None or job.status not in {"QUEUED", "RUNNING"}:
                return False
            now = datetime.now(UTC)
            if (
                not force
                and job.dispatch_attempted_at
                and job.dispatch_attempted_at > now - timedelta(seconds=DISPATCH_INTERVAL_SECONDS)
            ):
                return False
            job.dispatch_attempted_at = now
            db.commit()
    try:
        from app.workers.celery_app import celery_app

        celery_app.send_task(
            "privacyshield.classify",
            args=[str(job_id)],
            task_id="classify-" + str(job_id),
            queue=get_settings().celery_queue,
            retry=False,
            ignore_result=True,
        )
        return True
    except Exception:
        return False


def dispatch_classification_jobs() -> int:
    cutoff = datetime.now(UTC) - timedelta(seconds=DISPATCH_INTERVAL_SECONDS)
    with session_factory()() as db:
        ids = db.scalars(
            select(ClassificationJob.id)
            .where(
                ClassificationJob.status.in_(["QUEUED", "RUNNING"]),
                or_(
                    ClassificationJob.dispatch_attempted_at.is_(None),
                    ClassificationJob.dispatch_attempted_at < cutoff,
                ),
            )
            .order_by(ClassificationJob.created_at)
            .limit(50)
        ).all()
    return sum(enqueue_classification(job_id) for job_id in ids)


def fenced_job(db, job_id: UUID, attempt: int, statuses=("RUNNING",)) -> ClassificationJob | None:
    job = db.scalar(
        select(ClassificationJob).where(ClassificationJob.id == job_id).with_for_update()
    )
    if job is None or job.status not in statuses or job.attempt_count != attempt:
        return None
    return job


def update_counts(db, job: ClassificationJob) -> None:
    counts = dict(
        db.execute(
            select(ClassificationJobItem.status, func.count())
            .where(
                ClassificationJobItem.job_id == job.id,
            )
            .group_by(ClassificationJobItem.status)
        ).all()
    )
    job.completed_results = counts.get("COMPLETED", 0)
    job.failed_results = counts.get("FAILED", 0)
    job.progress = min(
        100, int(100 * (job.completed_results + job.failed_results) / job.total_results)
    )


def persist_decision(job_id: UUID, attempt: int, result_id: UUID, decision) -> bool:
    with session_factory()() as db:
        job = fenced_job(db, job_id, attempt)
        if job is None:
            return False
        item = db.get(ClassificationJobItem, (job_id, result_id))
        if item is None or item.status != "PENDING":
            return False
        db.add(
            PIIClassification(
                job_id=job_id,
                scan_result_id=result_id,
                category=decision.category,
                risk=decision.risk,
                recommendation=decision.recommendation,
                confidence=decision.confidence,
                reason=decision.reason,
                requires_approval=True,
                model=job.model,
                prompt_version=job.prompt_version,
            )
        )
        item.status = "COMPLETED"
        db.flush()
        update_counts(db, job)
        record_event(
            db,
            actor_id=job.requested_by,
            event_type="CLASSIFICATION_ACCEPTED",
            subject_type="classification_job",
            subject_id=job_id,
        )
        db.commit()
        return True


def persist_failure(job_id: UUID, attempt: int, code: str, result_id: UUID | None = None) -> bool:
    code = code if code in SAFE_ERROR_CODES else "CLASSIFICATION_FAILED"
    with session_factory()() as db:
        job = fenced_job(db, job_id, attempt, statuses=("QUEUED", "RUNNING"))
        if job is None:
            return False
        query = select(ClassificationJobItem).where(
            ClassificationJobItem.job_id == job_id, ClassificationJobItem.status == "PENDING"
        )
        if result_id is not None:
            query = query.where(ClassificationJobItem.scan_result_id == result_id)
        for item in db.scalars(query):
            item.status = "FAILED"
            item.error_code = code
        job.error_code = job.error_code or code
        db.flush()
        update_counts(db, job)
        db.commit()
        return True


def finish_job(job_id: UUID, attempt: int) -> bool:
    with session_factory()() as db:
        job = fenced_job(db, job_id, attempt, statuses=("QUEUED", "RUNNING"))
        if job is None:
            return False
        update_counts(db, job)
        if job.completed_results + job.failed_results != job.total_results:
            return False
        job.status = (
            "COMPLETED"
            if job.failed_results == 0
            else "PARTIAL"
            if job.completed_results
            else "FAILED"
        )
        job.finished_at = datetime.now(UTC)
        record_event(
            db,
            actor_id=job.requested_by,
            event_type="CLASSIFICATION_" + job.status,
            subject_type="classification_job",
            subject_id=job_id,
        )
        db.commit()
        return True


def evidence_for_result(db, job: ClassificationJob, result_id: UUID) -> dict:
    scan = db.get(ScanJob, job.scan_job_id)
    if scan is None or scan.status != "COMPLETED":
        raise ClassificationFailure("SCAN_NOT_COMPLETED")
    result = db.get(ScanResult, result_id)
    if result is None or result.scan_job_id != scan.id:
        raise ClassificationFailure("RESULT_METADATA_MISMATCH")
    snapshot = db.get(SchemaSnapshot, scan.snapshot_id)
    table = next(
        (
            item
            for item in snapshot.catalog["tables"]
            if item["schema"] == result.schema_name and item["name"] == result.table_name
        ),
        None,
    )
    column = (
        next((item for item in table["columns"] if item["name"] == result.column_name), None)
        if table
        else None
    )
    if column is None:
        raise ClassificationFailure("RESULT_METADATA_MISMATCH")
    evidence = {
        "result_id": str(result.id),
        "schema_name": result.schema_name,
        "table_name": result.table_name,
        "column_name": result.column_name,
        "json_path": result.json_path,
        "data_type": column["data_type"],
        "is_primary_key": column["is_primary_key"],
        "is_foreign_key": any(column["name"] in key["columns"] for key in table["foreign_keys"]),
        "nullable": True if result.json_path else column["nullable"],
        "sampled_rows": result.sampled_rows,
        "matching_rows": result.matching_rows,
        "category_counts": result.category_counts,
        "detector_confidence": result.confidence,
        "coverage": result.sanitized_evidence.get("coverage", {}),
    }
    # Optional evidence: absent for JSON, for unread columns and for scans
    # stored before shapes existed. The adapter validates every shape against
    # a fixed alphabet and rejects the column if one does not pass.
    shapes = result.sanitized_evidence.get("shapes")
    if SEND_SHAPES and shapes and not result.json_path:
        evidence["shapes"] = shapes
    return evidence


def run_classification(job_id: UUID) -> None:
    from app.services.classification.adapter import PROMPT_VERSION, AdapterError, classify_columns

    with scan_lock(job_id, "classification") as lease:
        if not lease:
            return
        attempt = None
        try:
            with session_factory()() as db:
                job = db.scalar(
                    select(ClassificationJob)
                    .where(ClassificationJob.id == job_id)
                    .with_for_update()
                )
                if job is None or job.status not in {"QUEUED", "RUNNING"}:
                    return
                attempt = job.attempt_count
                if attempt >= MAX_ATTEMPTS:
                    raise ClassificationFailure("ATTEMPT_LIMIT_EXCEEDED")
                if job.prompt_version != PROMPT_VERSION:
                    raise ClassificationFailure("PROMPT_VERSION_CHANGED")
                job.status = "RUNNING"
                job.attempt_count += 1
                attempt = job.attempt_count
                job.started_at = job.started_at or datetime.now(UTC)
                model = job.model
                record_event(
                    db,
                    actor_id=job.requested_by,
                    event_type="CLASSIFICATION_STARTED",
                    subject_type="classification_job",
                    subject_id=job_id,
                )
                pending_ids = db.scalars(
                    select(ClassificationJobItem.scan_result_id)
                    .where(
                        ClassificationJobItem.job_id == job_id,
                        ClassificationJobItem.status == "PENDING",
                    )
                    .order_by(ClassificationJobItem.scan_result_id)
                ).all()
                db.commit()
            for result_id in pending_ids:
                if not lease.valid():
                    return
                with session_factory()() as db:
                    current = db.get(ClassificationJob, job_id)
                    evidence = evidence_for_result(db, current, result_id)
                try:
                    # One column per call keeps the small CPU model's identity binding reliable.
                    decisions = classify_columns(
                        [evidence], base_url=get_settings().ollama_base_url, model=model
                    )
                    if (
                        len(decisions) != 1
                        or any(
                            getattr(decisions[0], key) != evidence[key]
                            for key in (
                                "result_id",
                                "schema_name",
                                "table_name",
                                "column_name",
                                "json_path",
                            )
                        )
                        or decisions[0].requires_human_approval is not True
                    ):
                        raise ClassificationFailure("AI_INVALID_RESPONSE")
                    if not lease.valid() or not persist_decision(
                        job_id, attempt, result_id, decisions[0]
                    ):
                        return
                except AdapterError as exc:
                    if not lease.valid():
                        return
                    code = exc.code if exc.code in SAFE_ERROR_CODES else "CLASSIFICATION_FAILED"
                    if not persist_failure(
                        job_id, attempt, code, None if code in STOP_ERRORS else result_id
                    ):
                        return
                    if code in STOP_ERRORS:
                        break
            if lease.valid():
                finish_job(job_id, attempt)
        except ClassificationFailure as exc:
            if attempt is not None and lease.valid():
                persist_failure(job_id, attempt, exc.code)
                finish_job(job_id, attempt)
        except SoftTimeLimitExceeded:
            if attempt is not None and lease.valid():
                persist_failure(job_id, attempt, "CLASSIFICATION_TIMEOUT")
                finish_job(job_id, attempt)
        except Exception:
            if attempt is not None and lease.valid():
                persist_failure(job_id, attempt, "CLASSIFICATION_FAILED")
                finish_job(job_id, attempt)

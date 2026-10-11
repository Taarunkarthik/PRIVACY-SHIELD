"""Durable scan state and idempotent worker execution."""

import hashlib
import json
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from billiard.exceptions import SoftTimeLimitExceeded
from psycopg import errors, sql
from sqlalchemy import delete, or_, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from app.core.audit import record_event
from app.core.config import get_settings
from app.core.database import get_engine, session_factory
from app.models import DatabaseConnection, ScanJob, ScanResult, SchemaSnapshot
from app.services.discovery.catalog import (
    DiscoveryError,
    catalog_fingerprint,
    discover_catalog_in_session,
    target_session,
)
from app.services.scanning.sampling import sample_seed, sample_table

MAX_RESULTS = 20000
MAX_ATTEMPTS = 3
DISPATCH_INTERVAL_SECONDS = 30


class ScanFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def connection_fingerprint(connection: DatabaseConnection) -> str:
    values = {
        name: getattr(connection, name)
        for name in (
            "host",
            "port",
            "database_name",
            "scanner_username",
            "ssl_mode",
        )
    }
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def advisory_key(job_id: UUID, namespace: str = "scan") -> int:
    return int.from_bytes(
        hashlib.sha256(b"privacyshield:" + namespace.encode() + b":" + job_id.bytes).digest()[:8],
        "big",
        signed=True,
    )


@contextmanager
def scan_lock(job_id: UUID, namespace: str = "scan"):
    # Hold a dedicated session lock across target reads and short control-plane transactions.
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        backend_pid = connection.scalar(text("SELECT pg_backend_pid()"))
        locked = connection.scalar(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": advisory_key(job_id, namespace)}
        )
        try:
            yield ScanLease(connection, advisory_key(job_id, namespace), backend_pid, bool(locked))
        finally:
            if locked:
                try:
                    connection.execute(
                        text("SELECT pg_advisory_unlock(:key)"),
                        {"key": advisory_key(job_id, namespace)},
                    )
                except SQLAlchemyError:
                    connection.invalidate()


@dataclass
class ScanLease:
    connection: Connection
    key: int
    backend_pid: int
    acquired: bool

    def __bool__(self) -> bool:
        return self.acquired

    def valid(self) -> bool:
        if not self.acquired:
            return False
        unsigned = self.key & ((1 << 64) - 1)
        try:
            return bool(
                self.connection.scalar(
                    text("""
                SELECT pg_backend_pid() = :pid AND EXISTS (
                    SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = :pid
                    AND classid::bigint = :high AND objid::bigint = :low
                    AND objsubid = 1 AND granted
                )
            """),
                    {"pid": self.backend_pid, "high": unsigned >> 32, "low": unsigned & 0xFFFFFFFF},
                )
            )
        except SQLAlchemyError:
            return False


def enqueue_scan(job_id: UUID, *, force: bool = False) -> bool:
    with scan_lock(job_id) as locked:
        if not locked:
            return False
        with session_factory()() as db:
            job = db.get(ScanJob, job_id)
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
    # Release the lock before publishing so an immediately scheduled worker can acquire it.
    try:
        from app.workers.celery_app import celery_app

        celery_app.send_task(
            "privacyshield.scan",
            args=[str(job_id)],
            task_id="scan-" + str(job_id),
            queue=get_settings().celery_queue,
            retry=False,
            ignore_result=True,
        )
        return True
    except Exception:
        # The committed QUEUED/RUNNING row is retried by the periodic dispatcher.
        return False


def dispatch_scan_jobs() -> int:
    cutoff = datetime.now(UTC) - timedelta(seconds=DISPATCH_INTERVAL_SECONDS)
    with session_factory()() as db:
        ids = db.scalars(
            select(ScanJob.id)
            .where(
                ScanJob.status.in_(["QUEUED", "RUNNING"]),
                or_(
                    ScanJob.dispatch_attempted_at.is_(None), ScanJob.dispatch_attempted_at < cutoff
                ),
            )
            .order_by(ScanJob.created_at)
            .limit(50)
        ).all()
    return sum(enqueue_scan(job_id) for job_id in ids)


def fenced_job(db, job_id: UUID, attempt: int, statuses=("RUNNING",)) -> ScanJob | None:
    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
    if job is None or job.status not in statuses or job.attempt_count != attempt:
        return None
    return job


def persist_progress(job_id: UUID, attempt: int, progress: int) -> bool:
    with session_factory()() as db:
        job = fenced_job(db, job_id, attempt)
        if job is None:
            return False
        job.progress = progress
        db.commit()
        return True


def complete_scan(job_id: UUID, attempt: int, results: list[dict]) -> bool:
    with session_factory()() as db:
        job = fenced_job(db, job_id, attempt)
        if job is None:
            return False
        db.add_all(ScanResult(scan_job_id=job_id, **result) for result in results)
        job.status = "COMPLETED"
        job.progress = 100
        job.finished_at = datetime.now(UTC)
        record_event(
            db,
            actor_id=job.requested_by,
            event_type="SCAN_COMPLETED",
            subject_type="scan_job",
            subject_id=job_id,
        )
        db.commit()
        return True


def mark_failed(job_id: UUID, code: str, attempt: int) -> bool:
    with session_factory()() as db:
        job = fenced_job(db, job_id, attempt, statuses=("QUEUED", "RUNNING"))
        if job is None:
            return False
        job.status = "FAILED"
        job.error_code = code
        job.finished_at = datetime.now(UTC)
        # No raw samples or exception strings become audit details or API errors.
        db.execute(delete(ScanResult).where(ScanResult.scan_job_id == job_id))
        record_event(
            db,
            actor_id=job.requested_by,
            event_type="SCAN_FAILED",
            subject_type="scan_job",
            subject_id=job_id,
        )
        db.commit()
        return True


def run_scan(job_id: UUID) -> None:
    with scan_lock(job_id) as locked:
        if not locked:
            return
        attempt = None
        try:
            with session_factory()() as db:
                job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
                if job is None or job.status not in {"QUEUED", "RUNNING"}:
                    return
                attempt = job.attempt_count
                if job.attempt_count >= MAX_ATTEMPTS:
                    raise ScanFailure("ATTEMPT_LIMIT_EXCEEDED")
                connection = db.get(DatabaseConnection, job.connection_id)
                snapshot = db.get(SchemaSnapshot, job.snapshot_id)
                if connection is None or not connection.is_active:
                    raise ScanFailure("CONNECTION_INACTIVE")
                if connection_fingerprint(connection) != job.connection_fingerprint:
                    raise ScanFailure("CONNECTION_CHANGED")
                job.status = "RUNNING"
                job.attempt_count += 1
                attempt = job.attempt_count
                job.started_at = datetime.now(UTC)
                job.finished_at = None
                job.error_code = None
                job.progress = 0
                sample_limit = job.sample_limit
                requested_by = job.requested_by
                db.execute(delete(ScanResult).where(ScanResult.scan_job_id == job_id))
                record_event(
                    db,
                    actor_id=requested_by,
                    event_type="SCAN_STARTED",
                    subject_type="scan_job",
                    subject_id=job_id,
                )
                db.commit()
            if not locked.valid():
                return  # The replacement worker will recover the durable RUNNING attempt.
            results = []
            with target_session(connection) as target:
                # Prevent ALTER/DROP of selected relations between catalog validation and sampling.
                # ACCESS SHARE is a read lock, permitted for the scanner's SELECT-only role.
                for table in snapshot.catalog["tables"]:
                    try:
                        target.execute(
                            sql.SQL("LOCK TABLE {} IN ACCESS SHARE MODE").format(
                                sql.Identifier(table["schema"], table["name"]),
                            )
                        )
                    except (errors.UndefinedTable, errors.InvalidSchemaName):
                        raise ScanFailure("SCHEMA_DRIFT") from None
                catalog = discover_catalog_in_session(target, snapshot.catalog["schemas"])
                if catalog_fingerprint(catalog) != snapshot.fingerprint:
                    raise ScanFailure("SCHEMA_DRIFT")
                tables = catalog["tables"]
                # Seeded by the job: a retry of this scan reads the same rows,
                # while a new scan reads a different random sample.
                seed = sample_seed(str(job_id))
                for index, table in enumerate(tables):
                    for result in sample_table(target, table, sample_limit, seed=seed):
                        if len(results) >= MAX_RESULTS:
                            raise ScanFailure("RESULT_LIMIT_EXCEEDED")
                        results.append(result)
                    if not locked.valid() or not persist_progress(
                        job_id,
                        attempt,
                        min(99, int(100 * (index + 1) / len(tables))),
                    ):
                        return
            # Row fencing closes the gap if the advisory-lock connection dies after this check.
            if locked.valid():
                complete_scan(job_id, attempt, results)
        except ScanFailure as exc:
            if attempt is not None and locked.valid():
                mark_failed(job_id, exc.code, attempt)
        except DiscoveryError as exc:
            if attempt is not None and locked.valid():
                mark_failed(
                    job_id,
                    "SOURCE_ACCESS_DENIED" if exc.status_code == 422 else "TARGET_UNAVAILABLE",
                    attempt,
                )
        except SoftTimeLimitExceeded:
            if attempt is not None and locked.valid():
                mark_failed(job_id, "SCAN_TIMEOUT", attempt)
        except Exception:
            if attempt is not None and locked.valid():
                mark_failed(job_id, "SCAN_FAILED", attempt)

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.connections import find_connection
from app.api.dependencies import current_user, require_roles
from app.core.audit import record_event
from app.core.database import get_db
from app.models import ScanJob, ScanResult, SchemaSnapshot, User
from app.schemas.scans import ScanCreate, ScanPage, ScanResponse, ScanResultPage, ScanResultResponse
from app.services.scanning.jobs import connection_fingerprint, enqueue_scan

router = APIRouter(prefix="/scans", tags=["PII scans"])


def find_scan(db: Session, job_id: UUID) -> ScanJob:
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(404, "Scan job not found")
    return job


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(
    payload: ScanCreate,
    user: User = Depends(require_roles("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> ScanJob:
    connection = find_connection(db, payload.connection_id, lock=True)
    if not connection.is_active:
        raise HTTPException(409, "Reactivate this connection before scanning")
    snapshot = db.get(SchemaSnapshot, payload.snapshot_id)
    if snapshot is None or snapshot.connection_id != connection.id:
        raise HTTPException(422, "Select a schema snapshot belonging to this connection")
    job = ScanJob(
        connection_id=connection.id,
        snapshot_id=snapshot.id,
        requested_by=user.id,
        sample_limit=payload.sample_limit,
        connection_fingerprint=connection_fingerprint(connection),
    )
    db.add(job)
    db.flush()
    record_event(
        db, actor_id=user.id, event_type="SCAN_QUEUED", subject_type="scan_job", subject_id=job.id
    )
    db.commit()
    enqueue_scan(job.id, force=True)
    return job


@router.get("", response_model=ScanPage)
def list_scans(
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    connection_id: UUID | None = None,
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"] | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ScanPage:
    filters = [ScanJob.connection_id == connection_id] if connection_id else []
    if status:
        filters.append(ScanJob.status == status)
    total = db.scalar(select(func.count()).select_from(ScanJob).where(*filters)) or 0
    items = db.scalars(
        select(ScanJob)
        .where(*filters)
        .order_by(
            ScanJob.created_at.desc(),
            ScanJob.id.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return ScanPage(
        items=[ScanResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{job_id}", response_model=ScanResponse)
def scan_status(
    job_id: UUID,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ScanJob:
    return find_scan(db, job_id)


@router.get("/{job_id}/results", response_model=ScanResultPage)
def scan_results(
    job_id: UUID,
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ScanResultPage:
    job = find_scan(db, job_id)
    if job.status != "COMPLETED":
        return ScanResultPage(items=[], total=0, page=page, page_size=page_size)
    total = (
        db.scalar(
            select(func.count()).select_from(ScanResult).where(ScanResult.scan_job_id == job_id)
        )
        or 0
    )
    items = db.scalars(
        select(ScanResult)
        .where(ScanResult.scan_job_id == job_id)
        .order_by(
            ScanResult.schema_name,
            ScanResult.table_name,
            ScanResult.column_name,
            ScanResult.json_path,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return ScanResultPage(
        items=[ScanResultResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )

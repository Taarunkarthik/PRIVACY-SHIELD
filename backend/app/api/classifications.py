from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, require_roles
from app.api.scans import find_scan
from app.core.audit import record_event
from app.core.config import get_settings
from app.core.database import get_db
from app.models import ClassificationJob, ClassificationJobItem, PIIClassification, ScanResult, User
from app.schemas.classifications import (
    ClassificationCreate,
    ClassificationJobPage,
    ClassificationJobResponse,
    ClassificationPage,
    ClassificationResponse,
)
from app.services.classification.jobs import enqueue_classification

router = APIRouter(tags=["AI advisory classification"])


@router.post("/scans/{scan_id}/classify", response_model=ClassificationJobResponse, status_code=202)
def create_classification(
    scan_id: UUID,
    payload: ClassificationCreate | None = None,
    user: User = Depends(require_roles("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> ClassificationJob:
    from app.services.classification.adapter import PROMPT_VERSION

    scan = find_scan(db, scan_id)
    if scan.status != "COMPLETED":
        raise HTTPException(409, "Only a completed scan can be classified")
    selected = payload.result_ids if payload else None
    query = select(ScanResult.id).where(ScanResult.scan_job_id == scan_id)
    if selected is None:
        query = (
            query.where(ScanResult.json_path == "")
            .order_by(
                ScanResult.schema_name,
                ScanResult.table_name,
                ScanResult.column_name,
            )
            .limit(50)
        )
    else:
        query = query.where(ScanResult.id.in_(selected))
    ids = db.scalars(query).all()
    if not ids or selected is not None and len(ids) != len(selected):
        raise HTTPException(422, "Select results belonging to this completed scan")
    job = ClassificationJob(
        scan_job_id=scan_id,
        requested_by=user.id,
        total_results=len(ids),
        model=get_settings().ollama_model,
        prompt_version=PROMPT_VERSION,
    )
    db.add(job)
    db.flush()
    db.add_all(
        ClassificationJobItem(job_id=job.id, scan_job_id=scan_id, scan_result_id=result_id)
        for result_id in ids
    )
    record_event(
        db,
        actor_id=user.id,
        event_type="CLASSIFICATION_QUEUED",
        subject_type="classification_job",
        subject_id=job.id,
    )
    db.commit()
    enqueue_classification(job.id, force=True)
    return job


@router.get("/classification-jobs", response_model=ClassificationJobPage)
def list_classification_jobs(
    scan_id: UUID | None = None,
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ClassificationJobPage:
    filters = [ClassificationJob.scan_job_id == scan_id] if scan_id else []
    total = db.scalar(select(func.count()).select_from(ClassificationJob).where(*filters)) or 0
    items = db.scalars(
        select(ClassificationJob)
        .where(*filters)
        .order_by(
            ClassificationJob.created_at.desc(),
            ClassificationJob.id.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return ClassificationJobPage(
        items=[ClassificationJobResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/classification-jobs/{job_id}", response_model=ClassificationJobResponse)
def classification_status(
    job_id: UUID,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ClassificationJob:
    job = db.get(ClassificationJob, job_id)
    if job is None:
        raise HTTPException(404, "Classification job not found")
    return job


@router.get("/classifications", response_model=ClassificationPage)
def list_classifications(
    scan_id: UUID | None = None,
    job_id: UUID | None = None,
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ClassificationPage:
    filters = []
    if scan_id:
        filters.append(ScanResult.scan_job_id == scan_id)
    if job_id:
        filters.append(PIIClassification.job_id == job_id)
    join = PIIClassification.scan_result_id == ScanResult.id
    total = (
        db.scalar(
            select(func.count())
            .select_from(PIIClassification)
            .join(ScanResult, join)
            .where(*filters)
        )
        or 0
    )
    rows = db.execute(
        select(PIIClassification, ScanResult)
        .join(ScanResult, join)
        .where(*filters)
        .order_by(
            PIIClassification.created_at.desc(),
            PIIClassification.id.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [
        ClassificationResponse(
            id=item.id,
            job_id=item.job_id,
            scan_result_id=item.scan_result_id,
            scan_id=result.scan_job_id,
            schema_name=result.schema_name,
            table_name=result.table_name,
            column_name=result.column_name,
            json_path=result.json_path,
            category=item.category,
            risk=item.risk,
            recommendation=item.recommendation,
            confidence=item.confidence,
            reason=item.reason,
            model=item.model,
            prompt_version=item.prompt_version,
            requires_approval=item.requires_approval,
            created_at=item.created_at,
        )
        for item, result in rows
    ]
    return ClassificationPage(items=items, total=total, page=page, page_size=page_size)

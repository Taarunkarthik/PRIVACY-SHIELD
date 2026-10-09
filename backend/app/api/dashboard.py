from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import current_user
from app.core.database import get_db
from app.models import DatabaseConnection, MaskingPolicy, ScanJob, ScanResult, SchemaSnapshot, User

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class DashboardSummary(BaseModel):
    databases: int
    tables: int
    sensitive_columns: int
    pending_approvals: int
    deployed_policies: int
    scan_jobs: int


@router.get("/summary", response_model=DashboardSummary)
def summary(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> DashboardSummary:
    latest_snapshots = db.scalars(
        select(SchemaSnapshot)
        .join(DatabaseConnection)
        .where(DatabaseConnection.is_active.is_(True))
        .distinct(SchemaSnapshot.connection_id)
        .order_by(SchemaSnapshot.connection_id, SchemaSnapshot.created_at.desc())
    ).all()
    latest_jobs = (
        select(ScanJob.id)
        .where(ScanJob.status == "COMPLETED")
        .distinct(ScanJob.connection_id)
        .order_by(ScanJob.connection_id, ScanJob.created_at.desc())
    )
    sensitive = (
        select(
            ScanResult.scan_job_id,
            ScanResult.schema_name,
            ScanResult.table_name,
            ScanResult.column_name,
        )
        .where(ScanResult.scan_job_id.in_(latest_jobs), ScanResult.matching_rows > 0)
        .distinct()
        .subquery()
    )
    return DashboardSummary(
        databases=db.scalar(
            select(func.count())
            .select_from(DatabaseConnection)
            .where(DatabaseConnection.is_active.is_(True))
        )
        or 0,
        tables=sum(len(snapshot.catalog.get("tables", [])) for snapshot in latest_snapshots),
        sensitive_columns=db.scalar(select(func.count()).select_from(sensitive)) or 0,
        pending_approvals=db.scalar(
            select(func.count())
            .select_from(MaskingPolicy)
            .where(MaskingPolicy.status == "PENDING_APPROVAL")
        )
        or 0,
        deployed_policies=db.scalar(
            select(func.count())
            .select_from(MaskingPolicy)
            .where(MaskingPolicy.status == "DEPLOYED")
        )
        or 0,
        scan_jobs=db.scalar(select(func.count()).select_from(ScanJob)) or 0,
    )

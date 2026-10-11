from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import current_user
from app.core.database import get_db
from app.models import (
    AuditEvent,
    DatabaseConnection,
    MaskingPolicy,
    PIIClassification,
    PolicyDeployment,
    PolicyRule,
    ScanJob,
    ScanResult,
    SchemaSnapshot,
    User,
)
from app.services.policies.suggestions import dominant_category

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
POLICY_STATUSES = ("DRAFT", "PENDING_APPROVAL", "APPROVED", "DEPLOYED", "REJECTED", "FAILED")
# Risk by detected category: government and card identifiers rank above contact
# details, which rank above names and places.
CATEGORY_RISK = {
    "AADHAAR_CANDIDATE": "CRITICAL",
    "PAN_CANDIDATE": "CRITICAL",
    "CREDIT_CARD": "CRITICAL",
    "BANK_ACCOUNT": "HIGH",
    "IBAN_CODE": "HIGH",
    "EMAIL_ADDRESS": "HIGH",
    "PHONE_NUMBER": "HIGH",
    "PERSON": "MEDIUM",
    "LOCATION": "MEDIUM",
}
DEFAULT_RISK = "MEDIUM"
RECENT_EVENT_LIMIT = 6


class CategoryCount(BaseModel):
    category: str
    columns: int


class RiskCount(BaseModel):
    risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    columns: int


class StatusCount(BaseModel):
    status: str
    policies: int


class Coverage(BaseModel):
    sensitive_columns: int
    protected_columns: int


class RecentEvent(BaseModel):
    event_type: str
    subject_type: str
    created_at: datetime


class DashboardInsights(BaseModel):
    """Breakdowns behind the overview totals; counts only, never source values."""

    categories: list[CategoryCount]
    risks: list[RiskCount]
    # How many of the columns also had an advisory classification to weigh.
    risks_from_ai: int
    policy_status: list[StatusCount]
    coverage: Coverage
    recent_activity: list[RecentEvent]


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


def _column_risk(category_counts: dict, ai_risk: str | None) -> str:
    """The highest risk level among everything detected in a column.

    A column holding names in most rows and Aadhaar numbers in a few is as
    sensitive as its Aadhaar numbers, so the most frequent category alone would
    understate it. An advisory classification can raise the level, never lower it.
    """
    levels = [CATEGORY_RISK.get(category, DEFAULT_RISK) for category in category_counts]
    if ai_risk in RISK_LEVELS:
        levels.append(ai_risk)
    return min(levels or [DEFAULT_RISK], key=RISK_LEVELS.index)


def _deployed_rules(db: Session) -> dict[tuple, dict[str, str]]:
    """Rules of the policy most recently deployed for each table.

    Keyed by target database and table, not by connection record: a view belongs
    to a table, and two connections to one database share it.
    """
    deployed = db.execute(
        select(
            MaskingPolicy.id,
            DatabaseConnection.host,
            DatabaseConnection.port,
            DatabaseConnection.database_name,
            MaskingPolicy.schema_name,
            MaskingPolicy.table_name,
        )
        .join(PolicyDeployment, PolicyDeployment.policy_id == MaskingPolicy.id)
        .join(DatabaseConnection, DatabaseConnection.id == MaskingPolicy.connection_id)
        .where(PolicyDeployment.status == "COMPLETED")
        .order_by(PolicyDeployment.finished_at.desc(), PolicyDeployment.id.desc())
    ).all()
    latest: dict[tuple, object] = {}
    for policy_id, *table in deployed:
        latest.setdefault(tuple(table), policy_id)
    if not latest:
        return {}
    rules: dict[object, dict[str, str]] = {policy_id: {} for policy_id in latest.values()}
    for rule in db.scalars(select(PolicyRule).where(PolicyRule.policy_id.in_(rules))):
        rules[rule.policy_id][rule.column_name] = rule.action
    return {table: rules[policy_id] for table, policy_id in latest.items()}


@router.get("/insights", response_model=DashboardInsights)
def insights(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> DashboardInsights:
    # Same definition as the overview total: the latest completed scan of each
    # connection, one entry per column that had at least one matching row.
    latest_jobs = (
        select(ScanJob.id)
        .where(ScanJob.status == "COMPLETED")
        .distinct(ScanJob.connection_id)
        .order_by(ScanJob.connection_id, ScanJob.created_at.desc())
    )
    sensitive = db.execute(
        select(
            ScanResult,
            DatabaseConnection.host,
            DatabaseConnection.port,
            DatabaseConnection.database_name,
        )
        .join(ScanJob, ScanJob.id == ScanResult.scan_job_id)
        .join(DatabaseConnection, DatabaseConnection.id == ScanJob.connection_id)
        .where(
            ScanResult.scan_job_id.in_(latest_jobs),
            ScanResult.json_path == "",
            ScanResult.matching_rows > 0,
        )
    ).all()
    ai_risk: dict[object, str] = {}
    if sensitive:
        classified = db.execute(
            select(PIIClassification.scan_result_id, PIIClassification.risk)
            .where(PIIClassification.scan_result_id.in_([row[0].id for row in sensitive]))
            .order_by(PIIClassification.created_at, PIIClassification.id)
        )
        # Later rows overwrite earlier ones, leaving the newest per column.
        ai_risk = dict(classified.all())
    deployed = _deployed_rules(db)

    categories: dict[str, int] = {}
    risks = dict.fromkeys(RISK_LEVELS, 0)
    protected = 0
    for result, *database in sensitive:
        category = dominant_category(result.category_counts) or "OTHER"
        categories[category] = categories.get(category, 0) + 1
        risks[_column_risk(result.category_counts, ai_risk.get(result.id))] += 1
        rules = deployed.get((*database, result.schema_name, result.table_name))
        # In a deployed view a column without a rule is NULL, so only KEEP exposes it.
        if rules is not None and rules.get(result.column_name) != "KEEP":
            protected += 1

    status_counts = dict(
        db.execute(select(MaskingPolicy.status, func.count()).group_by(MaskingPolicy.status)).all()
    )
    events = db.scalars(
        select(AuditEvent)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(RECENT_EVENT_LIMIT)
    ).all()
    return DashboardInsights(
        categories=[
            CategoryCount(category=name, columns=count)
            for name, count in sorted(categories.items(), key=lambda item: (-item[1], item[0]))
        ],
        risks=[RiskCount(risk=level, columns=risks[level]) for level in RISK_LEVELS],
        risks_from_ai=sum(1 for row in sensitive if row[0].id in ai_risk),
        policy_status=[
            StatusCount(status=status, policies=status_counts.get(status, 0))
            for status in POLICY_STATUSES
        ],
        coverage=Coverage(sensitive_columns=len(sensitive), protected_columns=protected),
        recent_activity=[
            RecentEvent(
                event_type=event.event_type,
                subject_type=event.subject_type,
                created_at=event.created_at,
            )
            for event in events
        ],
    )

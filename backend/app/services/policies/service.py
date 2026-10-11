"""Policy CRUD, approval workflow, and control-plane deployment orchestration.

The control plane never stores source values. Compilation reads only the saved
catalog snapshot and the policy's own rules.
"""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import record_event
from app.models import (
    AuditEvent,
    DatabaseConnection,
    MaskingPolicy,
    PolicyApproval,
    PolicyDeployment,
    PolicyRule,
    SchemaSnapshot,
    User,
)
from app.schemas.policies import (
    AuditEventResponse,
    DeploymentResponse,
    PolicyCreate,
    PolicyPreview,
    PolicyPreviewColumn,
    PolicyResponse,
    PolicyRuleResponse,
)
from app.services.policies.compiler import (
    READER_AUDIENCE,
    AudienceView,
    ColumnDecision,
    CompiledPlan,
    CompileError,
    compile_plan,
)
from app.services.policies.jobs import enqueue_deployment

ACTIVE_DEPLOYMENT_STATES = ("QUEUED", "RUNNING", "RECONCILING")
MAX_PLAN_COLUMNS = 500


class PolicyFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _snapshot_for_policy(db: Session, policy: MaskingPolicy) -> SchemaSnapshot | None:
    return db.scalar(
        select(SchemaSnapshot)
        .where(
            SchemaSnapshot.connection_id == policy.connection_id,
            SchemaSnapshot.fingerprint == policy.schema_fingerprint,
        )
        .order_by(SchemaSnapshot.created_at.desc(), SchemaSnapshot.id.desc())
    )


def _table_columns(
    snapshot: SchemaSnapshot, schema_name: str, table_name: str
) -> list[dict] | None:
    for table in snapshot.catalog.get("tables", []):
        if table["schema"] == schema_name and table["name"] == table_name:
            return table["columns"]
    return None


def policy_catalog_columns(db: Session, policy: MaskingPolicy) -> dict[str, dict]:
    """Catalog metadata for the policy's table, keyed by column name."""
    snapshot = _snapshot_for_policy(db, policy)
    columns = _table_columns(snapshot, policy.schema_name, policy.table_name) if snapshot else None
    return {column["name"]: column for column in columns or []}


def build_plan(db: Session, policy: MaskingPolicy) -> CompiledPlan:
    """Rebuild the compiled plan for a policy from its saved schema and rules."""
    snapshot = _snapshot_for_policy(db, policy)
    if snapshot is None:
        raise PolicyFailure("SCHEMA_DRIFT")
    columns = _table_columns(snapshot, policy.schema_name, policy.table_name)
    if columns is None:
        raise PolicyFailure("SCHEMA_DRIFT")
    if len(columns) > MAX_PLAN_COLUMNS:
        raise PolicyFailure("TABLE_TOO_WIDE")
    rules: dict[str, dict[str, PolicyRule]] = {}
    for rule in db.scalars(select(PolicyRule).where(PolicyRule.policy_id == policy.id)):
        rules.setdefault(rule.audience, {})[rule.column_name] = rule

    def decisions(audience: str) -> list[ColumnDecision]:
        # Within one audience's view, a column without a rule for it is NULL.
        own = rules.get(audience, {})
        return [
            ColumnDecision(
                name=column["name"],
                data_type=column["data_type"],
                action=own[column["name"]].action if column["name"] in own else "NULLIFY",
                pseudonym_domain=(
                    own[column["name"]].pseudonym_domain if column["name"] in own else None
                ),
                source_column=column["name"],
            )
            for column in columns
        ]

    try:
        return compile_plan(
            source_schema=policy.schema_name,
            source_table=policy.table_name,
            # The reader always has a view, even with no rule of its own.
            columns=decisions(READER_AUDIENCE),
            # Another audience has a view only if it has at least one rule. The
            # compiler rejects an audience outside the fixed set.
            audience_columns={
                audience: decisions(audience) for audience in rules if audience != READER_AUDIENCE
            },
        )
    except CompileError as exc:
        raise PolicyFailure("INVALID_PLAN") from exc


def audience_view(plan: CompiledPlan, audience: str) -> AudienceView:
    """One audience's view of a compiled policy, or a bounded failure if it has none."""
    view = plan.view_for(audience)
    if view is None:
        raise PolicyFailure("AUDIENCE_NOT_IN_POLICY")
    return view


def _next_version(db: Session, connection_id: UUID, schema_name: str, table_name: str) -> int:
    latest = db.scalar(
        select(func.max(MaskingPolicy.version)).where(
            MaskingPolicy.connection_id == connection_id,
            MaskingPolicy.schema_name == schema_name,
            MaskingPolicy.table_name == table_name,
        )
    )
    return (latest or 0) + 1


def create_policy(db: Session, user: User, payload: PolicyCreate) -> MaskingPolicy:
    """Create a new DRAFT policy with explicit per-column rules."""
    connection = db.get(DatabaseConnection, payload.connection_id)
    if connection is None or not connection.is_active:
        raise PolicyFailure("CONNECTION_INACTIVE")
    snapshot = db.get(SchemaSnapshot, payload.snapshot_id)
    if snapshot is None or snapshot.connection_id != connection.id:
        raise PolicyFailure("SCHEMA_DRIFT")
    columns = _table_columns(snapshot, payload.schema_name, payload.table_name)
    if columns is None:
        raise PolicyFailure("TABLE_NOT_FOUND")
    known = {column["name"] for column in columns}
    # A column may have one rule per audience.
    seen: set[tuple[str, str]] = set()
    for rule in payload.rules:
        if rule.column_name not in known:
            raise PolicyFailure("UNKNOWN_COLUMN")
        if (rule.column_name, rule.audience) in seen:
            raise PolicyFailure("DUPLICATE_RULE")
        seen.add((rule.column_name, rule.audience))

    policy = MaskingPolicy(
        connection_id=payload.connection_id,
        schema_name=payload.schema_name,
        table_name=payload.table_name,
        version=_next_version(
            db, payload.connection_id, payload.schema_name, payload.table_name
        ),
        status="DRAFT",
        schema_fingerprint=snapshot.fingerprint,
        created_by=user.id,
    )
    db.add(policy)
    db.flush()
    db.add_all(
        PolicyRule(
            policy_id=policy.id,
            column_name=rule.column_name,
            audience=rule.audience,
            action=rule.action,
            pseudonym_domain=rule.pseudonym_domain,
            classification_id=rule.classification_id,
        )
        for rule in payload.rules
    )
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise PolicyFailure("DUPLICATE_RULE") from None
    record_event(
        db,
        actor_id=user.id,
        event_type="POLICY_CREATED",
        subject_type="masking_policy",
        subject_id=policy.id,
    )
    db.commit()
    return policy


def _locked_policy(db: Session, policy_id: UUID) -> MaskingPolicy:
    policy = db.scalar(
        select(MaskingPolicy).where(MaskingPolicy.id == policy_id).with_for_update()
    )
    if policy is None:
        raise PolicyFailure("POLICY_NOT_FOUND")
    return policy


def submit_policy(db: Session, user: User, policy_id: UUID) -> MaskingPolicy:
    policy = _locked_policy(db, policy_id)
    if policy.status != "DRAFT":
        raise PolicyFailure("INVALID_TRANSITION")
    # Compile once so a broken policy cannot enter the approval queue.
    build_plan(db, policy)
    policy.status = "PENDING_APPROVAL"
    record_event(
        db,
        actor_id=user.id,
        event_type="POLICY_SUBMITTED",
        subject_type="masking_policy",
        subject_id=policy.id,
    )
    db.commit()
    return policy


def approve_policy(db: Session, user: User, policy_id: UUID) -> MaskingPolicy:
    if user.role != "ADMIN":
        raise PolicyFailure("INSUFFICIENT_PERMISSIONS")
    policy = _locked_policy(db, policy_id)
    if policy.status != "PENDING_APPROVAL":
        raise PolicyFailure("INVALID_TRANSITION")
    plan = build_plan(db, policy)
    policy.status = "APPROVED"
    policy.compiled_plan_fingerprint = plan.plan_hash
    db.add(
        PolicyApproval(
            policy_id=policy.id,
            actor_id=user.id,
            decision="APPROVED",
            approved_plan_fingerprint=plan.plan_hash,
        )
    )
    record_event(
        db,
        actor_id=user.id,
        event_type="POLICY_APPROVED",
        subject_type="masking_policy",
        subject_id=policy.id,
    )
    db.commit()
    return policy


def reject_policy(db: Session, user: User, policy_id: UUID) -> MaskingPolicy:
    if user.role != "ADMIN":
        raise PolicyFailure("INSUFFICIENT_PERMISSIONS")
    policy = _locked_policy(db, policy_id)
    if policy.status != "PENDING_APPROVAL":
        raise PolicyFailure("INVALID_TRANSITION")
    policy.status = "REJECTED"
    db.add(
        PolicyApproval(
            policy_id=policy.id,
            actor_id=user.id,
            decision="REJECTED",
            approved_plan_fingerprint=policy.compiled_plan_fingerprint or "",
        )
    )
    record_event(
        db,
        actor_id=user.id,
        event_type="POLICY_REJECTED",
        subject_type="masking_policy",
        subject_id=policy.id,
    )
    db.commit()
    return policy


def deploy_policy(
    db: Session,
    user: User,
    policy_id: UUID,
    idempotency_key: UUID | None = None,
) -> PolicyDeployment:
    """Queue a deployment for an approved (or explicitly retried) policy."""
    if user.role != "ADMIN":
        raise PolicyFailure("INSUFFICIENT_PERMISSIONS")
    policy = _locked_policy(db, policy_id)
    if policy.status not in ("APPROVED", "FAILED"):
        raise PolicyFailure("POLICY_NOT_APPROVED")
    if policy.status == "FAILED":
        # A failed deployment may return to APPROVED only for unchanged content.
        plan = build_plan(db, policy)
        if plan.plan_hash != policy.compiled_plan_fingerprint:
            raise PolicyFailure("SCHEMA_DRIFT")
        policy.status = "APPROVED"

    key = idempotency_key or uuid4()
    existing = db.scalar(
        select(PolicyDeployment).where(PolicyDeployment.idempotency_key == key)
    )
    if existing is not None:
        if existing.policy_id != policy_id:
            raise PolicyFailure("IDEMPOTENCY_CONFLICT")
        return existing

    active = db.scalar(
        select(PolicyDeployment).where(
            PolicyDeployment.policy_id == policy_id,
            PolicyDeployment.status.in_(ACTIVE_DEPLOYMENT_STATES),
        )
    )
    if active is not None:
        raise PolicyFailure("DEPLOYMENT_IN_PROGRESS")

    deployment = PolicyDeployment(
        policy_id=policy_id,
        requested_by=user.id,
        idempotency_key=key,
        status="QUEUED",
    )
    db.add(deployment)
    db.flush()
    record_event(
        db,
        actor_id=user.id,
        event_type="DEPLOYMENT_QUEUED",
        subject_type="policy_deployment",
        subject_id=deployment.id,
    )
    db.commit()
    # Best effort: a durable QUEUED row is retried by the periodic dispatcher.
    try:
        enqueue_deployment(deployment.id, force=True)
    except Exception:
        pass
    return deployment


def get_policy_preview(
    db: Session, policy_id: UUID, audience: str = READER_AUDIENCE
) -> PolicyPreview:
    """The compiled view of one audience, and which audiences the policy has views for."""
    policy = db.get(MaskingPolicy, policy_id)
    if policy is None:
        raise PolicyFailure("POLICY_NOT_FOUND")
    plan = build_plan(db, policy)
    view = audience_view(plan, audience)
    return PolicyPreview(
        policy_id=policy.id,
        schema_name=policy.schema_name,
        table_name=policy.table_name,
        view_schema=plan.view_schema,
        view_name=view.view_name,
        columns=[
            PolicyPreviewColumn(
                name=c.name,
                data_type=c.data_type,
                action=c.action,
                pseudonym_domain=c.pseudonym_domain,
                source_column=c.source_column or c.name,
            )
            for c in view.columns
        ],
        sql=view.sql,
        audience=view.audience,
        role=view.role,
        audiences=plan.audiences,
    )


def _policy_response(db: Session, policy: MaskingPolicy) -> PolicyResponse:
    rules = db.scalars(select(PolicyRule).where(PolicyRule.policy_id == policy.id)).all()
    return PolicyResponse(
        id=policy.id,
        connection_id=policy.connection_id,
        schema_name=policy.schema_name,
        table_name=policy.table_name,
        version=policy.version,
        status=policy.status,
        schema_fingerprint=policy.schema_fingerprint,
        compiled_plan_fingerprint=policy.compiled_plan_fingerprint,
        created_by=policy.created_by,
        created_at=policy.created_at,
        rules=[
            PolicyRuleResponse(
                policy_id=r.policy_id,
                column_name=r.column_name,
                action=r.action,
                pseudonym_domain=r.pseudonym_domain,
                classification_id=r.classification_id,
                audience=r.audience,
            )
            for r in rules
        ],
    )


def get_policy(db: Session, policy_id: UUID) -> PolicyResponse | None:
    policy = db.get(MaskingPolicy, policy_id)
    return _policy_response(db, policy) if policy else None


def list_policies(
    db: Session,
    *,
    connection_id: UUID | None = None,
    status: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[PolicyResponse], int]:
    filters = []
    if connection_id:
        filters.append(MaskingPolicy.connection_id == connection_id)
    if status:
        filters.append(MaskingPolicy.status == status)
    total = db.scalar(select(func.count()).select_from(MaskingPolicy).where(*filters)) or 0
    items = db.scalars(
        select(MaskingPolicy)
        .where(*filters)
        .order_by(MaskingPolicy.created_at.desc(), MaskingPolicy.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [_policy_response(db, policy) for policy in items], total


def list_deployments(
    db: Session, *, page: int = 1, page_size: int = 20
) -> tuple[list[DeploymentResponse], int]:
    total = db.scalar(select(func.count()).select_from(PolicyDeployment)) or 0
    items = db.scalars(
        select(PolicyDeployment)
        .order_by(PolicyDeployment.created_at.desc(), PolicyDeployment.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [DeploymentResponse.model_validate(item) for item in items], total


def list_audit_events(
    db: Session,
    *,
    actor_id: UUID | None = None,
    event_type: str | None = None,
    subject_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[AuditEventResponse], int]:
    filters = []
    if actor_id:
        filters.append(AuditEvent.actor_id == actor_id)
    if event_type:
        filters.append(AuditEvent.event_type == event_type)
    if subject_type:
        filters.append(AuditEvent.subject_type == subject_type)
    if since is not None:
        filters.append(AuditEvent.created_at >= since)
    if until is not None:
        filters.append(AuditEvent.created_at <= until)
    total = db.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0
    items = db.scalars(
        select(AuditEvent)
        .where(*filters)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [AuditEventResponse.model_validate(item) for item in items], total

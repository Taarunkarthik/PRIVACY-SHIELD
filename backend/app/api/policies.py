from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, require_roles
from app.core.database import get_db
from app.models import User
from app.schemas.policies import (
    AuditEventPage,
    DeploymentPage,
    DeploymentResponse,
    DeployRequest,
    PolicyCreate,
    PolicyPage,
    PolicyPreview,
    PolicyResponse,
)
from app.services.policies.service import (
    PolicyFailure,
    approve_policy,
    create_policy,
    deploy_policy,
    get_policy,
    get_policy_preview,
    list_audit_events,
    list_deployments,
    list_policies,
    reject_policy,
    submit_policy,
)

router = APIRouter(tags=["Masking policies"])


def _handle_failure(exc: PolicyFailure) -> None:
    status_map = {
        "CONNECTION_INACTIVE": 409,
        "CONNECTION_CHANGED": 409,
        "SCHEMA_DRIFT": 409,
        "TARGET_UNAVAILABLE": 502,
        "DEPLOYMENT_FAILED": 502,
        "DEPLOYMENT_TIMEOUT": 504,
        "RECONCILIATION_PENDING": 503,
        "ATTEMPT_LIMIT_EXCEEDED": 409,
        "POLICY_NOT_APPROVED": 409,
        "POLICY_NOT_FOUND": 404,
        "INVALID_TRANSITION": 409,
        "INSUFFICIENT_PERMISSIONS": 403,
        "DEPLOYMENT_IN_PROGRESS": 409,
        "DUPLICATE_RULE": 422,
        "IDEMPOTENCY_CONFLICT": 409,
        "TABLE_NOT_FOUND": 422,
        "UNKNOWN_COLUMN": 422,
        "INVALID_PLAN": 422,
        "TABLE_TOO_WIDE": 422,
        "VIEW_OWNER_UNAVAILABLE": 422,
        "RECEIPT_CONFLICT": 409,
    }
    raise HTTPException(status_map.get(exc.code, 400), exc.code) from None


@router.get("/policies", response_model=PolicyPage)
def get_policies(
    connection_id: UUID | None = None,
    status: str | None = None,
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> PolicyPage:
    items, total = list_policies(
        db, connection_id=connection_id, status=status, page=page, page_size=page_size
    )
    return PolicyPage(items=items, total=total, page=page, page_size=page_size)


@router.post("/policies", response_model=PolicyResponse, status_code=201)
def create_new_policy(
    payload: PolicyCreate,
    user: User = Depends(require_roles("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    try:
        policy = create_policy(db, user, payload)
    except PolicyFailure as exc:
        _handle_failure(exc)
    return get_policy(db, policy.id)


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
def get_policy_by_id(
    policy_id: UUID,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    policy = get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(404, "Policy not found")
    return policy


@router.post("/policies/{policy_id}/submit", response_model=PolicyResponse)
def submit_policy_endpoint(
    policy_id: UUID,
    user: User = Depends(require_roles("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    try:
        policy = submit_policy(db, user, policy_id)
    except PolicyFailure as exc:
        _handle_failure(exc)
    return get_policy(db, policy.id)


@router.post("/policies/{policy_id}/approve", response_model=PolicyResponse)
def approve_policy_endpoint(
    policy_id: UUID,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    try:
        policy = approve_policy(db, user, policy_id)
    except PolicyFailure as exc:
        _handle_failure(exc)
    return get_policy(db, policy.id)


@router.post("/policies/{policy_id}/reject", response_model=PolicyResponse)
def reject_policy_endpoint(
    policy_id: UUID,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> PolicyResponse:
    try:
        policy = reject_policy(db, user, policy_id)
    except PolicyFailure as exc:
        _handle_failure(exc)
    return get_policy(db, policy.id)


@router.post(
    "/policies/{policy_id}/deploy", response_model=DeploymentResponse, status_code=202
)
def deploy_policy_endpoint(
    policy_id: UUID,
    payload: DeployRequest | None = None,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> DeploymentResponse:
    idempotency_key = payload.idempotency_key if payload else None
    try:
        deployment = deploy_policy(db, user, policy_id, idempotency_key)
    except PolicyFailure as exc:
        _handle_failure(exc)
    return DeploymentResponse.model_validate(deployment)


@router.get("/policies/{policy_id}/preview", response_model=PolicyPreview)
def preview_policy(
    policy_id: UUID,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> PolicyPreview:
    try:
        return get_policy_preview(db, policy_id)
    except PolicyFailure as exc:
        _handle_failure(exc)


@router.get("/deployments", response_model=DeploymentPage)
def get_deployments(
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> DeploymentPage:
    items, total = list_deployments(db, page=page, page_size=page_size)
    return DeploymentPage(items=items, total=total, page=page, page_size=page_size)


@router.get("/audit-events", response_model=AuditEventPage)
def get_audit_events(
    actor_id: UUID | None = None,
    event_type: str | None = None,
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> AuditEventPage:
    items, total = list_audit_events(
        db, actor_id=actor_id, event_type=event_type, page=page, page_size=page_size
    )
    return AuditEventPage(items=items, total=total, page=page, page_size=page_size)

"""Real PostgreSQL/Redis recovery and concurrency checks for the control plane.

Covers stale approval decisions, row-lock serialization of concurrent decisions,
durable state left by an interrupted deployment worker, and uncertain-outcome
reconciliation through the existing deployment receipt mechanism.
"""

import os
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import encrypt_credential, hash_password
from app.main import app
from app.models import (
    AuditEvent,
    DatabaseConnection,
    MaskingPolicy,
    PolicyApproval,
    PolicyDeployment,
    SchemaSnapshot,
    User,
)
from app.schemas.policies import PolicyCreate, PolicyRuleCreate
from app.services.discovery.catalog import catalog_fingerprint
from app.services.policies.execution import _execute_target, run_deployment
from app.services.policies.jobs import complete_deployment, enqueue_deployment
from app.services.policies.service import (
    PolicyFailure,
    approve_policy,
    build_plan,
    create_policy,
    deploy_policy,
    reject_policy,
    submit_policy,
)
from app.services.scanning.jobs import scan_lock
from app.workers.celery_app import celery_app

pytestmark = pytest.mark.integration


def _target_available() -> bool:
    return all(
        os.environ.get(name)
        for name in (
            "TEST_TARGET_SCANNER_PASSWORD",
            "TEST_TARGET_DEPLOYER_PASSWORD",
            "TEST_TARGET_READER_PASSWORD",
        )
    )


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def admin(db):
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"recovery-{uuid.uuid4().hex}@example.com",
        role="ADMIN",
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    return user, password


def _col(name, data_type, ordinal, *, pk=False):
    return {
        "name": name,
        "data_type": data_type,
        "udt_name": data_type.split("(")[0],
        "nullable": not pk,
        "ordinal": ordinal,
        "is_primary_key": pk,
        "is_jsonb": False,
    }


def _submitted_policy(db, admin_user) -> MaskingPolicy:
    connection = DatabaseConnection(
        name=f"recovery-{uuid.uuid4().hex[:10]}",
        host="target-db",
        port=5432,
        database_name="enterprise_demo",
        ssl_mode="disable",
        scanner_username="ps_scanner",
        scanner_password_ciphertext=encrypt_credential("scanner-secret"),
        deployer_username="ps_deployer",
        deployer_password_ciphertext=encrypt_credential("deployer-secret"),
        created_by=admin_user.id,
    )
    db.add(connection)
    db.flush()
    catalog = {
        "schemas": ["enterprise"],
        "tables": [
            {
                "schema": "enterprise",
                "name": "customers",
                "oid": 1,
                "row_estimate": 100,
                "rls_enabled": False,
                "columns": [_col("id", "bigint", 1, pk=True), _col("email", "text", 2)],
                "primary_key": ["id"],
                "foreign_keys": [],
            }
        ],
    }
    snapshot = SchemaSnapshot(
        connection_id=connection.id,
        catalog=catalog,
        fingerprint=catalog_fingerprint(catalog),
    )
    db.add(snapshot)
    db.commit()
    policy = create_policy(
        db,
        admin_user,
        PolicyCreate(
            connection_id=connection.id,
            schema_name="enterprise",
            table_name="customers",
            snapshot_id=snapshot.id,
            rules=[PolicyRuleCreate(column_name="id", action="KEEP")],
        ),
    )
    submit_policy(db, admin_user, policy.id)
    return policy


def _approval_count(db, policy_id) -> int:
    return db.scalar(
        select(func.count())
        .select_from(PolicyApproval)
        .where(PolicyApproval.policy_id == policy_id)
    )


def _retire(deployment_id) -> None:
    with session_factory()() as session:
        deployment = session.get(PolicyDeployment, deployment_id)
        if deployment is not None and deployment.status in ("QUEUED", "RUNNING", "RECONCILING"):
            deployment.status = "FAILED"
            deployment.error_code = "TEST_CLEANUP"
            session.commit()


def test_stale_approval_decision_cannot_overwrite_applied_decision(db, admin):
    user, _ = admin
    policy = _submitted_policy(db, user)
    approve_policy(db, user, policy.id)
    # A decision queued against the old PENDING_APPROVAL state is stale.
    with pytest.raises(PolicyFailure) as excinfo:
        reject_policy(db, user, policy.id)
    assert excinfo.value.code == "INVALID_TRANSITION"
    db.expire_all()
    assert db.get(MaskingPolicy, policy.id).status == "APPROVED"
    assert _approval_count(db, policy.id) == 1


def test_concurrent_approval_decisions_are_serialized_by_row_lock(db, admin):
    user, _ = admin
    policy = _submitted_policy(db, user)
    policy_id = policy.id
    barrier = threading.Barrier(2)

    def decide() -> str:
        barrier.wait(timeout=15)
        with session_factory()() as session:
            actor = session.get(User, user.id)
            try:
                approve_policy(session, actor, policy_id)
                return "approved"
            except PolicyFailure as exc:
                return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [future.result() for future in (pool.submit(decide), pool.submit(decide))]

    assert sorted(outcomes) == ["INVALID_TRANSITION", "approved"]
    db.expire_all()
    assert db.get(MaskingPolicy, policy_id).status == "APPROVED"
    assert _approval_count(db, policy_id) == 1


def test_interrupted_deployment_stays_durable_and_is_redispatchable(db, admin, monkeypatch):
    user, _ = admin
    policy = _submitted_policy(db, user)
    approve_policy(db, user, policy.id)
    monkeypatch.setattr(celery_app, "send_task", lambda *args, **kwargs: None)
    deployment = deploy_policy(db, user, policy.id)
    db.expire_all()
    stored = db.get(PolicyDeployment, deployment.id)
    assert stored.status == "QUEUED"

    # Simulate a worker that started, wrote attempts, and died before finishing.
    stored.status = "RUNNING"
    stored.target_receipt = {"attempts": 1, "dispatched_at": "2000-01-01T00:00:00+00:00"}
    db.commit()

    # The per-deployment advisory lock fences a duplicate dispatcher.
    with scan_lock(stored.id, "deployment") as lease:
        assert lease.valid()
        assert enqueue_deployment(stored.id, force=True) is False

    # With the lease released, the durable row is redispatched exactly once.
    sent: list[str] = []
    monkeypatch.setattr(celery_app, "send_task", lambda name, *args, **kwargs: sent.append(name))
    assert enqueue_deployment(stored.id, force=True) is True
    assert sent == ["privacyshield.deploy"]
    _retire(stored.id)


def test_uncertain_outcome_reconciliation_is_idempotent(db, admin, monkeypatch):
    user, _ = admin
    policy = _submitted_policy(db, user)
    approve_policy(db, user, policy.id)
    monkeypatch.setattr(celery_app, "send_task", lambda *args, **kwargs: None)
    deployment = deploy_policy(db, user, policy.id)
    db.expire_all()
    stored = db.get(PolicyDeployment, deployment.id)
    stored.status = "RUNNING"
    db.commit()

    receipt = {
        "view_schema": "privacyshield_masked",
        "view_name": "v_enterprise_customers",
        "plan_hash": "a" * 64,
        "deployed_at": "2026-01-01T00:00:00+00:00",
        "reconciled": True,
    }
    assert complete_deployment(stored.id, receipt) is True
    db.expire_all()
    stored = db.get(PolicyDeployment, stored.id)
    assert stored.status == "COMPLETED"
    assert stored.target_receipt["reconciled"] is True
    assert db.get(MaskingPolicy, policy.id).status == "DEPLOYED"

    # A repeated uncertain completion is fenced and never duplicates terminal audit.
    assert complete_deployment(stored.id, receipt) is False
    assert (
        db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.subject_id == stored.id,
                AuditEvent.event_type == "DEPLOYMENT_COMPLETED",
            )
        )
        == 1
    )


@pytest.mark.skipif(not _target_available(), reason="Real target credentials are required")
def test_target_receipt_reconciles_without_reapplying_ddl(db, admin, monkeypatch):
    user, password = admin
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    client = TestClient(app, base_url="http://localhost:8080")
    login = client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )
    assert login.status_code == 200, login.text
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]

    host = os.environ.get("TEST_TARGET_HOST", "target-db")
    port = int(os.environ.get("TEST_TARGET_PORT", "5432"))
    connection = client.post(
        "/api/v1/connections",
        json={
            "name": f"reconcile-{uuid.uuid4().hex[:10]}",
            "host": host,
            "port": port,
            "database_name": "enterprise_demo",
            "ssl_mode": "disable",
            "scanner_username": "ps_scanner",
            "scanner_password": os.environ["TEST_TARGET_SCANNER_PASSWORD"],
            "deployer_username": "ps_deployer",
            "deployer_password": os.environ["TEST_TARGET_DEPLOYER_PASSWORD"],
        },
    )
    assert connection.status_code == 201, connection.text
    connection_id = connection.json()["id"]
    snapshot = client.post(
        f"/api/v1/connections/{connection_id}/discover", json={"schemas": ["enterprise"]}
    )
    assert snapshot.status_code == 200, snapshot.text
    policy = client.post(
        "/api/v1/policies",
        json={
            "connection_id": connection_id,
            "schema_name": "enterprise",
            "table_name": "customers",
            "snapshot_id": snapshot.json()["snapshot_id"],
            "rules": [
                {"column_name": "id", "action": "KEEP"},
                {"column_name": "full_name", "action": "REDACT"},
                {"column_name": "email", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
                {"column_name": "created_at", "action": "KEEP"},
            ],
        },
    )
    assert policy.status_code == 201, policy.text
    policy_id = policy.json()["id"]
    assert client.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200
    assert client.post(f"/api/v1/policies/{policy_id}/approve").status_code == 200
    deployment = client.post(f"/api/v1/policies/{policy_id}/deploy", json={})
    assert deployment.status_code == 202, deployment.text
    deployment_id = uuid.UUID(deployment.json()["id"])
    # Either this process or the isolated worker may hold the deployment lock;
    # poll for the terminal state instead of assuming which one ran it.
    run_deployment(deployment_id)
    deadline = time.monotonic() + 30
    stored = None
    while time.monotonic() < deadline:
        db.expire_all()
        stored = db.get(PolicyDeployment, deployment_id)
        if stored.status in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.5)
    assert stored.status == "COMPLETED", stored.status

    # Simulate a lost acknowledgment: the target already holds the receipt, but
    # the control plane believes the deployment is still running.
    record = db.get(DatabaseConnection, uuid.UUID(connection_id))
    plan = build_plan(db, db.get(MaskingPolicy, uuid.UUID(policy_id)))
    stored.status = "RUNNING"
    stored.finished_at = None
    db.commit()
    assert _execute_target(deployment_id, record, plan) is True  # Reconciled, no new DDL.
    _retire(deployment_id)
    client.close()

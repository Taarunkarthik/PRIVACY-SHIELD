"""Target-side deployment execution.

Runs DDL as the deployer role, assuming the view-owner role for object creation,
inside a single target transaction with an idempotent receipt.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import UUID

import psycopg
from cryptography.fernet import InvalidToken
from psycopg.rows import dict_row

from app.core.database import session_factory
from app.core.security import decrypt_credential
from app.models import DatabaseConnection, MaskingPolicy, PolicyDeployment
from app.services.discovery.catalog import DiscoveryError, validate_target_host
from app.services.policies.compiler import (
    AUDIENCE_ROLES,
    VIEW_OWNER_ROLE,
    CompiledPlan,
    quote_ident,
    view_name_for,
)
from app.services.policies.jobs import complete_deployment, fail_deployment
from app.services.policies.service import ACTIVE_DEPLOYMENT_STATES, PolicyFailure, build_plan
from app.services.scanning.jobs import scan_lock

logger = logging.getLogger("privacyshield")

MAX_DEPLOY_ATTEMPTS = 3


class DeploymentTargetError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@contextmanager
def deployer_session(record: DatabaseConnection) -> Iterator[psycopg.Connection]:
    """Connect as the deployment role with write access and no read-only default."""
    validate_target_host(record.host)
    if not record.deployer_username or not record.deployer_password_ciphertext:
        raise DiscoveryError(422, "No deployment credentials are configured for this connection")
    try:
        with psycopg.connect(
            host=record.host,
            port=record.port,
            dbname=record.database_name,
            user=record.deployer_username,
            password=decrypt_credential(record.deployer_password_ciphertext),
            sslmode=record.ssl_mode,
            connect_timeout=5,
            autocommit=True,
            application_name="privacyshield-deployer",
            row_factory=dict_row,
            options="-c statement_timeout=30000 -c search_path=pg_catalog",
        ) as connection:
            yield connection
    except InvalidToken:
        raise DiscoveryError(503, "Stored credentials could not be decrypted") from None
    except psycopg.Error:
        raise DiscoveryError(502, "Target database connection or deployment failed") from None


def read_access(target, role: str, schema: str, relation: str) -> bool | None:
    """Whether ``role`` may read any part of a relation; ``None`` if it is absent."""
    row = target.execute(
        """
        SELECT pg_catalog.has_table_privilege(%(role)s, c.oid, 'SELECT')
               OR pg_catalog.has_any_column_privilege(%(role)s, c.oid, 'SELECT') AS readable
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %(schema)s AND c.relname = %(relation)s
        """,
        {"role": role, "schema": schema, "relation": relation},
    ).fetchone()
    return None if row is None else bool(row["readable"])


def existing_audience_roles(target) -> set[str]:
    """The audience roles that exist in the target database.

    A database initialised before audiences existed has only the reader role.
    """
    rows = target.execute(
        "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY(%s)",
        (list(AUDIENCE_ROLES.values()),),
    ).fetchall()
    return {row["rolname"] for row in rows}


def run_deployment(deployment_id: UUID) -> None:
    """Execute or reconcile a policy deployment against the target database."""
    # A single worker holds the per-deployment advisory lock; duplicates exit.
    with scan_lock(deployment_id, "deployment") as lease:
        if not lease:
            return
        _run_deployment_locked(deployment_id)


def _run_deployment_locked(deployment_id: UUID) -> None:
    with session_factory()() as db:
        deployment = db.get(PolicyDeployment, deployment_id)
        if deployment is None or deployment.status not in ACTIVE_DEPLOYMENT_STATES:
            return
        policy = db.get(MaskingPolicy, deployment.policy_id)
        if policy is None:
            fail_deployment(deployment_id, "POLICY_NOT_FOUND")
            return
        connection = db.get(DatabaseConnection, policy.connection_id)
        if connection is None or not connection.is_active:
            fail_deployment(deployment_id, "CONNECTION_INACTIVE")
            return

        meta = dict(deployment.target_receipt or {})
        attempts = int(meta.get("attempts", 0)) + 1
        if attempts > MAX_DEPLOY_ATTEMPTS:
            fail_deployment(deployment_id, "ATTEMPT_LIMIT_EXCEEDED")
            return
        try:
            plan = build_plan(db, policy)
        except PolicyFailure as exc:
            fail_deployment(deployment_id, exc.code)
            return
        if policy.status != "APPROVED" or plan.plan_hash != policy.compiled_plan_fingerprint:
            fail_deployment(deployment_id, "SCHEMA_DRIFT")
            return

        meta["attempts"] = attempts
        deployment.status = "RUNNING"
        deployment.target_receipt = meta
        db.commit()

    try:
        reconciled = _execute_target(deployment_id, connection, plan)
    except DeploymentTargetError as exc:
        fail_deployment(deployment_id, exc.code)
        return
    except DiscoveryError:
        fail_deployment(deployment_id, "TARGET_UNAVAILABLE")
        return
    except Exception:
        logger.error("Deployment %s failed unexpectedly", deployment_id)
        fail_deployment(deployment_id, "DEPLOYMENT_FAILED")
        return

    complete_deployment(
        deployment_id,
        {
            "view_schema": plan.view_schema,
            "view_name": plan.view_name,
            # Every audience that has a view after this deployment. An audience
            # not listed has none: a view left by an earlier version was dropped.
            "audiences": plan.audiences,
            "audience_views": {view.audience: view.view_name for view in plan.views},
            "plan_hash": plan.plan_hash,
            "deployed_at": datetime.now(UTC).isoformat(),
            "reconciled": reconciled,
            "access_verified": True,
        },
    )


def _execute_target(
    deployment_id: UUID, connection: DatabaseConnection, plan: CompiledPlan
) -> bool:
    """Apply the compiled plan in one target transaction; return True if reconciled."""
    with deployer_session(connection) as target, target.transaction():
        target.execute(f"SET LOCAL ROLE {quote_ident(VIEW_OWNER_ROLE)}")
        allowed = target.execute(
            "SELECT pg_catalog.has_schema_privilege(current_user, %s, 'CREATE') AS allowed",
            (plan.view_schema,),
        ).fetchone()
        if not allowed or not allowed["allowed"]:
            raise DeploymentTargetError("VIEW_OWNER_UNAVAILABLE")
        existing = target.execute(
            "SELECT plan_hash FROM privacyshield_private.deployment_receipts "
            "WHERE deployment_id = %s",
            (deployment_id,),
        ).fetchone()
        if existing is not None:
            if existing["plan_hash"] != plan.plan_hash:
                raise DeploymentTargetError("RECEIPT_CONFLICT")
            return True  # Already applied: idempotent success.

        # Every audience this policy has a view for needs its role. Checked
        # before any change, so a database without the role gets nothing.
        present = existing_audience_roles(target)
        if any(view.role not in present for view in plan.views):
            raise DeploymentTargetError("AUDIENCE_ROLE_MISSING")

        # One audience at a time, always in the same order, so two deployments
        # for one table take their locks in the same sequence.
        for audience in AUDIENCE_ROLES:
            audience_view = plan.view_for(audience)
            name = (
                audience_view.view_name
                if audience_view is not None
                else view_name_for(plan.source_schema, plan.source_table, audience)
            )
            view = f"{quote_ident(plan.view_schema)}.{quote_ident(name)}"
            if audience_view is None:
                # This version has no view for the audience, so the view an
                # earlier version gave it must go: it would outlive its policy.
                try:
                    with target.transaction():
                        target.execute(f"DROP VIEW IF EXISTS {view}")
                except psycopg.errors.DependentObjectsStillExist:
                    # Something else was built on the view. Dropping that too
                    # is not ours to decide, so nothing is deployed.
                    raise DeploymentTargetError("AUDIENCE_VIEW_IN_USE") from None
                continue
            try:
                # A savepoint, so a refused replacement does not abort the deployment.
                with target.transaction():
                    target.execute(audience_view.sql)
            except psycopg.errors.InvalidTableDefinition:
                # CREATE OR REPLACE VIEW cannot change an existing column's type,
                # which happens when a newer version masks a column that an older
                # one kept. Recreate the view instead. Both steps commit together,
                # so readers never see it missing, and DROP without CASCADE still
                # refuses if anything else depends on the view.
                target.execute(f"DROP VIEW {view}")
                target.execute(audience_view.sql)
            # Each audience role sees only its own approved view. Both
            # statements are idempotent.
            others = sorted(present - {audience_view.role})
            if others:
                target.execute(
                    f"REVOKE ALL ON {view} FROM {', '.join(quote_ident(role) for role in others)}"
                )
            target.execute(f"GRANT SELECT ON {view} TO {quote_ident(audience_view.role)}")

        # Verify the resulting access before committing. Every audience role
        # that exists must have no path to the unmasked source table and must
        # read its own view of this table and no other audience's. That holds
        # for an audience without a view too: it reads nothing. A failure here
        # rolls every view back with the rest of the transaction.
        for audience, role in AUDIENCE_ROLES.items():
            if role not in present:
                continue
            if read_access(target, role, plan.source_schema, plan.source_table) is not False:
                raise DeploymentTargetError("ACCESS_VERIFICATION_FAILED")
            for audience_view in plan.views:
                expected = audience_view.audience == audience
                readable = read_access(target, role, plan.view_schema, audience_view.view_name)
                if readable is not expected:
                    raise DeploymentTargetError("ACCESS_VERIFICATION_FAILED")
        target.execute(
            "INSERT INTO privacyshield_private.deployment_receipts (deployment_id, plan_hash) "
            "VALUES (%s, %s)",
            (deployment_id, plan.plan_hash),
        )
    return False

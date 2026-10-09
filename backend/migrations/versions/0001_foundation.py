"""Create the PrivacyShield control-plane schema and least-privilege grants.

Revision ID: 0001_foundation
Revises: None

This revision is deliberately frozen: it does not import application models.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=16), server_default="ANALYST", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('ADMIN', 'ANALYST', 'AUDITOR')", name=op.f("ck_users_valid_role")
        ),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_users_normalized_email")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_table(
        "audit_events",
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("subject_type", sa.String(length=80), nullable=False),
        sa.Column("subject_id", sa.UUID(), nullable=True),
        sa.Column("correlation_id", sa.UUID(), nullable=False),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_audit_events_actor_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_actor_id"), "audit_events", ["actor_id"], unique=False)
    op.create_index(
        "ix_audit_events_actor_id_created_at",
        "audit_events",
        ["actor_id", "created_at"],
        unique=False,
    )
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_audit_events_event_type"), "audit_events", ["event_type"], unique=False
    )
    op.create_table(
        "database_connections",
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), server_default="5432", nullable=False),
        sa.Column("database_name", sa.String(length=63), nullable=False),
        sa.Column("ssl_mode", sa.String(length=16), server_default="require", nullable=False),
        sa.Column("scanner_username", sa.String(length=63), nullable=False),
        sa.Column("scanner_password_ciphertext", sa.Text(), nullable=False),
        sa.Column("deployer_username", sa.String(length=63), nullable=True),
        sa.Column("deployer_password_ciphertext", sa.Text(), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "ssl_mode IN ('disable','require','verify-ca','verify-full')",
            name=op.f("ck_database_connections_valid_ssl_mode"),
        ),
        sa.CheckConstraint(
            "port BETWEEN 1 AND 65535", name=op.f("ck_database_connections_valid_port")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_database_connections_created_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_database_connections")),
        sa.UniqueConstraint("name", name=op.f("uq_database_connections_name")),
    )
    op.create_index(
        op.f("ix_database_connections_created_by"),
        "database_connections",
        ["created_by"],
        unique=False,
    )
    op.create_table(
        "user_sessions",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_user_sessions_positive_lifetime")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_sessions_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_user_sessions_token_hash")),
    )
    op.create_index(
        op.f("ix_user_sessions_expires_at"), "user_sessions", ["expires_at"], unique=False
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False)
    op.create_table(
        "masking_policies",
        sa.Column("connection_id", sa.UUID(), nullable=False),
        sa.Column("schema_name", sa.String(length=63), nullable=False),
        sa.Column("table_name", sa.String(length=63), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="DRAFT", nullable=False),
        sa.Column("schema_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("compiled_plan_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('DRAFT','PENDING_APPROVAL','APPROVED','REJECTED','DEPLOYED','FAILED')",
            name=op.f("ck_masking_policies_valid_status"),
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_masking_policies_positive_version")),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["database_connections.id"],
            name=op.f("fk_masking_policies_connection_id_database_connections"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_masking_policies_created_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_masking_policies")),
        sa.UniqueConstraint(
            "connection_id",
            "schema_name",
            "table_name",
            "version",
            name=op.f("uq_masking_policies_connection_id"),
        ),
    )
    op.create_index(
        op.f("ix_masking_policies_connection_id"),
        "masking_policies",
        ["connection_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_masking_policies_created_by"), "masking_policies", ["created_by"], unique=False
    )
    op.create_index(
        "ix_masking_policies_status_created_at",
        "masking_policies",
        ["status", "created_at"],
        unique=False,
    )
    op.create_table(
        "schema_snapshots",
        sa.Column("connection_id", sa.UUID(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("catalog", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["database_connections.id"],
            name=op.f("fk_schema_snapshots_connection_id_database_connections"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_schema_snapshots")),
        sa.UniqueConstraint("id", "connection_id", name=op.f("uq_schema_snapshots_id")),
    )
    op.create_index(
        op.f("ix_schema_snapshots_connection_id"),
        "schema_snapshots",
        ["connection_id"],
        unique=False,
    )
    op.create_table(
        "policy_approvals",
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("approved_plan_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "decision IN ('APPROVED','REJECTED')", name=op.f("ck_policy_approvals_valid_decision")
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name=op.f("fk_policy_approvals_actor_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["masking_policies.id"],
            name=op.f("fk_policy_approvals_policy_id_masking_policies"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policy_approvals")),
        sa.UniqueConstraint("policy_id", name=op.f("uq_policy_approvals_policy_id")),
    )
    op.create_index(
        op.f("ix_policy_approvals_actor_id"), "policy_approvals", ["actor_id"], unique=False
    )
    op.create_index(
        "ix_policy_approvals_decision_created_at",
        "policy_approvals",
        ["decision", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_policy_approvals_policy_id"), "policy_approvals", ["policy_id"], unique=False
    )
    op.create_table(
        "policy_deployments",
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="QUEUED", nullable=False),
        sa.Column("target_receipt", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED','RUNNING','RECONCILING','COMPLETED','FAILED')",
            name=op.f("ck_policy_deployments_valid_status"),
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["masking_policies.id"],
            name=op.f("fk_policy_deployments_policy_id_masking_policies"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name=op.f("fk_policy_deployments_requested_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policy_deployments")),
        sa.UniqueConstraint("idempotency_key", name=op.f("uq_policy_deployments_idempotency_key")),
    )
    op.create_index(
        op.f("ix_policy_deployments_policy_id"), "policy_deployments", ["policy_id"], unique=False
    )
    op.create_index(
        op.f("ix_policy_deployments_requested_by"),
        "policy_deployments",
        ["requested_by"],
        unique=False,
    )
    op.create_index(
        "ix_policy_deployments_status_created_at",
        "policy_deployments",
        ["status", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_policy_deployments_one_active",
        "policy_deployments",
        ["policy_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('QUEUED','RUNNING','RECONCILING')"),
    )
    op.create_table(
        "scan_jobs",
        sa.Column("connection_id", sa.UUID(), nullable=False),
        sa.Column("snapshot_id", sa.UUID(), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="QUEUED", nullable=False),
        sa.Column("sample_limit", sa.Integer(), server_default="1000", nullable=False),
        sa.Column("progress", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED')",
            name=op.f("ck_scan_jobs_valid_status"),
        ),
        sa.CheckConstraint("progress BETWEEN 0 AND 100", name=op.f("ck_scan_jobs_valid_progress")),
        sa.CheckConstraint(
            "sample_limit BETWEEN 1 AND 10000", name=op.f("ck_scan_jobs_bounded_sample")
        ),
        sa.ForeignKeyConstraint(
            ["connection_id"],
            ["database_connections.id"],
            name=op.f("fk_scan_jobs_connection_id_database_connections"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name=op.f("fk_scan_jobs_requested_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id", "connection_id"],
            ["schema_snapshots.id", "schema_snapshots.connection_id"],
            name=op.f("fk_scan_jobs_snapshot_id_schema_snapshots"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_jobs")),
    )
    op.create_index(
        op.f("ix_scan_jobs_connection_id"), "scan_jobs", ["connection_id"], unique=False
    )
    op.create_index(op.f("ix_scan_jobs_requested_by"), "scan_jobs", ["requested_by"], unique=False)
    op.create_index(op.f("ix_scan_jobs_snapshot_id"), "scan_jobs", ["snapshot_id"], unique=False)
    op.create_index(
        "ix_scan_jobs_status_created_at", "scan_jobs", ["status", "created_at"], unique=False
    )
    op.create_table(
        "scan_results",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("schema_name", sa.String(length=63), nullable=False),
        sa.Column("table_name", sa.String(length=63), nullable=False),
        sa.Column("column_name", sa.String(length=63), nullable=False),
        sa.Column("json_path", sa.String(length=1024), server_default="", nullable=False),
        sa.Column("sampled_rows", sa.Integer(), nullable=False),
        sa.Column("matching_rows", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "category_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "sanitized_evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "confidence BETWEEN 0 AND 1", name=op.f("ck_scan_results_valid_confidence")
        ),
        sa.CheckConstraint(
            "matching_rows BETWEEN 0 AND sampled_rows",
            name=op.f("ck_scan_results_valid_matching_rows"),
        ),
        sa.CheckConstraint(
            "sampled_rows >= 0", name=op.f("ck_scan_results_nonnegative_sampled_rows")
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"], ["scan_jobs.id"], name=op.f("fk_scan_results_scan_job_id_scan_jobs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_results")),
        sa.UniqueConstraint(
            "scan_job_id",
            "schema_name",
            "table_name",
            "column_name",
            "json_path",
            name=op.f("uq_scan_results_scan_job_id"),
        ),
    )
    op.create_index(
        op.f("ix_scan_results_scan_job_id"), "scan_results", ["scan_job_id"], unique=False
    )
    op.create_table(
        "pii_classifications",
        sa.Column("scan_result_id", sa.UUID(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("recommendation", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "recommendation IN ('KEEP','REDACT','PARTIAL','PSEUDONYMIZE','NULLIFY','RESTRICT')",
            name=op.f("ck_pii_classifications_valid_recommendation"),
        ),
        sa.CheckConstraint(
            "risk IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name=op.f("ck_pii_classifications_valid_risk"),
        ),
        sa.CheckConstraint(
            "confidence BETWEEN 0 AND 1", name=op.f("ck_pii_classifications_valid_confidence")
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"],
            ["scan_results.id"],
            name=op.f("fk_pii_classifications_scan_result_id_scan_results"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pii_classifications")),
    )
    op.create_index(
        op.f("ix_pii_classifications_scan_result_id"),
        "pii_classifications",
        ["scan_result_id"],
        unique=False,
    )
    op.create_table(
        "policy_rules",
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("column_name", sa.String(length=63), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("pseudonym_domain", sa.String(length=120), nullable=True),
        sa.Column("classification_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('KEEP','REDACT','PARTIAL','PSEUDONYMIZE','NULLIFY','RESTRICT')",
            name=op.f("ck_policy_rules_valid_action"),
        ),
        sa.ForeignKeyConstraint(
            ["classification_id"],
            ["pii_classifications.id"],
            name=op.f("fk_policy_rules_classification_id_pii_classifications"),
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["masking_policies.id"],
            name=op.f("fk_policy_rules_policy_id_masking_policies"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policy_rules")),
        sa.UniqueConstraint("policy_id", "column_name", name=op.f("uq_policy_rules_policy_id")),
    )
    op.create_index(
        op.f("ix_policy_rules_classification_id"),
        "policy_rules",
        ["classification_id"],
        unique=False,
    )
    op.create_index(op.f("ix_policy_rules_policy_id"), "policy_rules", ["policy_id"], unique=False)
    # The migrator owns all objects; API/worker use the separately provisioned ps_app role.
    # Do not grant on ALL tables: that would allow runtime edits to alembic_version.
    op.execute("GRANT USAGE ON SCHEMA public TO ps_app")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users, user_sessions, "
        "database_connections, scan_jobs, scan_results, pii_classifications, "
        "masking_policies, policy_rules, policy_approvals, policy_deployments TO ps_app"
    )
    op.execute("GRANT SELECT, INSERT ON TABLE audit_events, schema_snapshots TO ps_app")
    op.execute(
        "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_events, schema_snapshots FROM ps_app"
    )


def downgrade() -> None:
    # Destructive downgrades must be deliberately executed by the migration owner.
    op.drop_table("policy_rules")
    op.drop_table("pii_classifications")
    op.drop_table("scan_results")
    op.drop_table("scan_jobs")
    op.drop_table("policy_deployments")
    op.drop_table("policy_approvals")
    op.drop_table("schema_snapshots")
    op.drop_table("masking_policies")
    op.drop_table("user_sessions")
    op.drop_table("database_connections")
    op.drop_table("audit_events")
    op.drop_table("users")

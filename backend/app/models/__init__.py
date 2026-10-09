"""Relational control-plane entities. Source customer values are never stored here."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Entity:
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Entity, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('ADMIN', 'ANALYST', 'AUDITOR')", name="valid_role"),
        CheckConstraint("email = lower(email)", name="normalized_email"),
    )

    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), server_default="ANALYST")
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class UserSession(Entity, Base):
    __tablename__ = "user_sessions"
    __table_args__ = (CheckConstraint("expires_at > created_at", name="positive_lifetime"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DatabaseConnection(Entity, Base):
    __tablename__ = "database_connections"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="valid_port"),
        CheckConstraint(
            "ssl_mode IN ('disable','require','verify-ca','verify-full')", name="valid_ssl_mode"
        ),
    )

    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, server_default="5432")
    database_name: Mapped[str] = mapped_column(String(63))
    ssl_mode: Mapped[str] = mapped_column(String(16), server_default="require")
    scanner_username: Mapped[str] = mapped_column(String(63))
    scanner_password_ciphertext: Mapped[str] = mapped_column(Text)
    deployer_username: Mapped[str | None] = mapped_column(String(63))
    deployer_password_ciphertext: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))


class SchemaSnapshot(Entity, Base):
    __tablename__ = "schema_snapshots"
    __table_args__ = (UniqueConstraint("id", "connection_id"),)

    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("database_connections.id"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    catalog: Mapped[dict[str, Any]] = mapped_column(JSONB)


class ScanJob(Entity, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["snapshot_id", "connection_id"],
            ["schema_snapshots.id", "schema_snapshots.connection_id"],
        ),
        CheckConstraint(
            "status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED')", name="valid_status"
        ),
        CheckConstraint("sample_limit BETWEEN 1 AND 10000", name="bounded_sample"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="valid_progress"),
        Index("ix_scan_jobs_status_created_at", "status", "created_at"),
    )

    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("database_connections.id"), index=True
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), server_default="QUEUED")
    sample_limit: Mapped[int] = mapped_column(Integer, server_default="1000")
    progress: Mapped[int] = mapped_column(Integer, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))


class ScanResult(Entity, Base):
    __tablename__ = "scan_results"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "schema_name", "table_name", "column_name", "json_path"),
        CheckConstraint("sampled_rows >= 0", name="nonnegative_sampled_rows"),
        CheckConstraint("matching_rows BETWEEN 0 AND sampled_rows", name="valid_matching_rows"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_confidence"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    schema_name: Mapped[str] = mapped_column(String(63))
    table_name: Mapped[str] = mapped_column(String(63))
    column_name: Mapped[str] = mapped_column(String(63))
    json_path: Mapped[str] = mapped_column(String(1024), server_default="")
    sampled_rows: Mapped[int] = mapped_column(Integer)
    matching_rows: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    category_counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb")
    )
    sanitized_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb")
    )


class PIIClassification(Entity, Base):
    __tablename__ = "pii_classifications"
    __table_args__ = (
        CheckConstraint("risk IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="valid_risk"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_confidence"),
        CheckConstraint(
            "recommendation IN ('KEEP','REDACT','PARTIAL','PSEUDONYMIZE','NULLIFY','RESTRICT')",
            name="valid_recommendation",
        ),
    )

    scan_result_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_results.id"), index=True)
    category: Mapped[str] = mapped_column(String(64))
    risk: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    recommendation: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(120))
    prompt_version: Mapped[str] = mapped_column(String(32))


class MaskingPolicy(Entity, Base):
    __tablename__ = "masking_policies"
    __table_args__ = (
        UniqueConstraint("connection_id", "schema_name", "table_name", "version"),
        CheckConstraint("version >= 1", name="positive_version"),
        CheckConstraint(
            "status IN ('DRAFT','PENDING_APPROVAL','APPROVED','REJECTED','DEPLOYED','FAILED')",
            name="valid_status",
        ),
        Index("ix_masking_policies_status_created_at", "status", "created_at"),
    )

    connection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("database_connections.id"), index=True
    )
    schema_name: Mapped[str] = mapped_column(String(63))
    table_name: Mapped[str] = mapped_column(String(63))
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), server_default="DRAFT")
    schema_fingerprint: Mapped[str] = mapped_column(String(64))
    compiled_plan_fingerprint: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)


class PolicyRule(Entity, Base):
    __tablename__ = "policy_rules"
    __table_args__ = (
        UniqueConstraint("policy_id", "column_name"),
        CheckConstraint(
            "action IN ('KEEP','REDACT','PARTIAL','PSEUDONYMIZE','NULLIFY','RESTRICT')",
            name="valid_action",
        ),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("masking_policies.id"), index=True)
    column_name: Mapped[str] = mapped_column(String(63))
    action: Mapped[str] = mapped_column(String(16))
    pseudonym_domain: Mapped[str | None] = mapped_column(String(120))
    classification_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pii_classifications.id"), index=True
    )


class PolicyApproval(Entity, Base):
    __tablename__ = "policy_approvals"
    __table_args__ = (
        UniqueConstraint("policy_id"),
        CheckConstraint("decision IN ('APPROVED','REJECTED')", name="valid_decision"),
        Index("ix_policy_approvals_decision_created_at", "decision", "created_at"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("masking_policies.id"), index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    decision: Mapped[str] = mapped_column(String(16))
    approved_plan_fingerprint: Mapped[str] = mapped_column(String(64))


class PolicyDeployment(Entity, Base):
    __tablename__ = "policy_deployments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('QUEUED','RUNNING','RECONCILING','COMPLETED','FAILED')", name="valid_status"
        ),
        Index(
            "uq_policy_deployments_one_active",
            "policy_id",
            unique=True,
            postgresql_where=text("status IN ('QUEUED','RUNNING','RECONCILING')"),
        ),
        Index("ix_policy_deployments_status_created_at", "status", "created_at"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("masking_policies.id"), index=True)
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    idempotency_key: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True)
    status: Mapped[str] = mapped_column(String(16), server_default="QUEUED")
    target_receipt: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))


class AuditEvent(Entity, Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_actor_id_created_at", "actor_id", "created_at"),)

    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    subject_type: Mapped[str] = mapped_column(String(80))
    subject_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    correlation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))


Index("ix_audit_events_created_at", AuditEvent.created_at)

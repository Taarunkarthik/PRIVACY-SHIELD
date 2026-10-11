"""Add the insert-only hash chain that makes audit history tamper-evident.

Revision ID: 0006_audit_chain
Revises: 0005_format_masks
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_audit_chain"
down_revision = "0005_format_masks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # op.f() marks each name as final so the naming convention is not applied a
    # second time. It needs a running migration, hence inside this function.
    op.create_table(
        "audit_chain",
        # Assigned by the sealer under an advisory lock; deliberately no sequence,
        # because a sequence leaves gaps when a transaction rolls back.
        sa.Column("chain_index", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("row_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "sealed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("chain_index >= 1", name=op.f("ck_audit_chain_positive_index")),
        sa.CheckConstraint(
            "prev_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_audit_chain_valid_prev_hash")
        ),
        sa.CheckConstraint(
            "row_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_audit_chain_valid_row_hash")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["audit_events.id"], name=op.f("fk_audit_chain_event_id_audit_events")
        ),
        sa.PrimaryKeyConstraint("chain_index", name=op.f("pk_audit_chain")),
        sa.UniqueConstraint("event_id", name=op.f("uq_audit_chain_event_id")),
    )
    # Same boundary as audit_events: the runtime role appends and reads, nothing else.
    op.execute("GRANT SELECT, INSERT ON TABLE audit_chain TO ps_app")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_chain FROM ps_app")


def downgrade() -> None:
    # Dropping the chain discards the evidence, not the audit events. After a
    # later upgrade every existing event is sealed again from the first one.
    op.drop_table("audit_chain")

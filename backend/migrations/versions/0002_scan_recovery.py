"""Add durable scan dispatch and bounded recovery state.

Revision ID: 0002_scan_recovery
Revises: 0001_foundation
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_scan_recovery"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs", sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("scan_jobs", sa.Column("dispatch_attempted_at", sa.DateTime(timezone=True)))
    op.add_column(
        "scan_jobs",
        sa.Column("connection_fingerprint", sa.String(64), nullable=False, server_default=""),
    )
    op.create_check_constraint(
        op.f("ck_scan_jobs_bounded_attempts"), "scan_jobs", "attempt_count BETWEEN 0 AND 3"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_scan_jobs_bounded_attempts"), "scan_jobs", type_="check")
    op.drop_column("scan_jobs", "connection_fingerprint")
    op.drop_column("scan_jobs", "dispatch_attempted_at")
    op.drop_column("scan_jobs", "attempt_count")

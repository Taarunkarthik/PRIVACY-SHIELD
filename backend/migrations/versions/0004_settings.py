"""Add the singleton operator settings row and bounded custom detection patterns.

Revision ID: 0004_settings
Revises: 0003_classification_jobs
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_settings"
down_revision = "0003_classification_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column(
            "workspace_name",
            sa.String(length=120),
            server_default="Privacy workspace",
            nullable=False,
        ),
        sa.Column("retention_days", sa.Integer(), server_default="365", nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.UUID(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(workspace_name) BETWEEN 1 AND 120",
            name=op.f("ck_app_settings_bounded_workspace_name"),
        ),
        sa.CheckConstraint(
            "retention_days BETWEEN 1 AND 3650",
            name=op.f("ck_app_settings_bounded_retention_days"),
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], name=op.f("fk_app_settings_updated_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_settings")),
    )
    op.create_index(
        op.f("ix_app_settings_updated_by"), "app_settings", ["updated_by"], unique=False
    )
    # A unique index over a constant expression enforces exactly one settings row.
    op.execute(
        "CREATE UNIQUE INDEX uq_app_settings_singleton ON app_settings ((true))"
    )
    op.create_table(
        "custom_patterns",
        sa.Column("name", sa.String(length=60), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("regex", sa.String(length=200), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "category IN ('PII','FINANCIAL','HEALTH','OTHER')",
            name=op.f("ck_custom_patterns_valid_category"),
        ),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 60", name=op.f("ck_custom_patterns_bounded_name")
        ),
        sa.CheckConstraint(
            "length(regex) BETWEEN 1 AND 200", name=op.f("ck_custom_patterns_bounded_regex")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_custom_patterns_created_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custom_patterns")),
        sa.UniqueConstraint("name", name=op.f("uq_custom_patterns_name")),
    )
    op.create_index(
        op.f("ix_custom_patterns_created_by"), "custom_patterns", ["created_by"], unique=False
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app_settings, custom_patterns TO ps_app"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_custom_patterns_created_by"), table_name="custom_patterns")
    op.drop_table("custom_patterns")
    op.execute("DROP INDEX IF EXISTS uq_app_settings_singleton")
    op.drop_index(op.f("ix_app_settings_updated_by"), table_name="app_settings")
    op.drop_table("app_settings")

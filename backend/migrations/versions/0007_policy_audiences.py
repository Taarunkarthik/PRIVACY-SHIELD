"""Give every policy rule an audience, so one policy can mask a table per audience.

Revision ID: 0007_policy_audiences
Revises: 0006_audit_chain
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_policy_audiences"
down_revision = "0006_audit_chain"
branch_labels = None
depends_on = None

_TABLE = "policy_rules"
# The convention names a unique constraint after its first column only, so the
# name is the same before and after: just the column list changes.
_UNIQUE = "uq_policy_rules_policy_id"
_CHECK = "ck_policy_rules_valid_audience"
_AUDIENCES = "audience IN ('reader','support','analyst')"


def _replace_unique(columns: list[str]) -> None:
    # op.f() marks the name as final, so the naming convention is not applied
    # twice. It is only usable while a migration is running, hence not at import.
    name = op.f(_UNIQUE)
    op.drop_constraint(name, _TABLE, type_="unique")
    op.create_unique_constraint(name, _TABLE, columns)


def upgrade() -> None:
    # Every existing rule was written for the only audience there was.
    op.add_column(
        _TABLE,
        sa.Column("audience", sa.Text(), server_default="reader", nullable=False),
    )
    op.create_check_constraint(op.f(_CHECK), _TABLE, _AUDIENCES)
    _replace_unique(["policy_id", "column_name", "audience"])


def downgrade() -> None:
    # A rule is part of an approved, fingerprinted policy. Dropping the rules of
    # the other audiences would leave approvals and deployed views describing
    # something else, so the downgrade stops instead when any exist.
    in_use = (
        0  # Offline (--sql) rendering has no database to ask.
        if op.get_context().as_sql
        else op.get_bind()
        .exec_driver_sql("SELECT count(*) FROM policy_rules WHERE audience <> 'reader'")
        .scalar()
    )
    if in_use:
        raise RuntimeError(
            f"{in_use} policy rules belong to an audience other than 'reader'; "
            "remove those policies before downgrading"
        )
    _replace_unique(["policy_id", "column_name"])
    op.drop_constraint(op.f(_CHECK), _TABLE, type_="check")
    op.drop_column(_TABLE, "audience")

"""Allow format-aware masking actions on policy rules.

Revision ID: 0005_format_masks
Revises: 0004_settings
"""

from alembic import op

revision = "0005_format_masks"
down_revision = "0004_settings"
branch_labels = None
depends_on = None

_NAME = "ck_policy_rules_valid_action"
_PREVIOUS = "action IN ('KEEP','REDACT','PARTIAL','PSEUDONYMIZE','NULLIFY','RESTRICT')"
_CURRENT = (
    "action IN ('KEEP','REDACT','PARTIAL','MASK_EMAIL','MASK_PHONE','MASK_ID',"
    "'PSEUDONYMIZE','NULLIFY','RESTRICT')"
)


def _replace_constraint(condition: str) -> None:
    # op.f() marks the name as final, so the naming convention is not applied
    # twice. It is only usable while a migration is running, hence not at import.
    name = op.f(_NAME)
    op.drop_constraint(name, "policy_rules", type_="check")
    op.create_check_constraint(name, "policy_rules", condition)


def upgrade() -> None:
    _replace_constraint(_CURRENT)


def downgrade() -> None:
    # A rule is part of an approved, fingerprinted policy. Rewriting it would
    # leave approvals and deployed views describing something else, so the
    # downgrade stops instead when format-aware masks are in use.
    in_use = (
        0  # Offline (--sql) rendering has no database to ask.
        if op.get_context().as_sql
        else op.get_bind()
        .exec_driver_sql(
            "SELECT count(*) FROM policy_rules "
            "WHERE action IN ('MASK_EMAIL','MASK_PHONE','MASK_ID')"
        )
        .scalar()
    )
    if in_use:
        raise RuntimeError(
            f"{in_use} policy rules use format-aware masks; "
            "remove those policies before downgrading"
        )
    _replace_constraint(_PREVIOUS)

"""Allow format-aware masking actions on policy rules.

Revision ID: 0005_format_masks
Revises: 0004_settings
"""

from alembic import op

revision = "0005_format_masks"
down_revision = "0004_settings"
branch_labels = None
depends_on = None

# op.f() marks the name as final so the naming convention is not applied twice.
_CONSTRAINT = op.f("ck_policy_rules_valid_action")
_PREVIOUS = "action IN ('KEEP','REDACT','PARTIAL','PSEUDONYMIZE','NULLIFY','RESTRICT')"
_CURRENT = (
    "action IN ('KEEP','REDACT','PARTIAL','MASK_EMAIL','MASK_PHONE','MASK_ID',"
    "'PSEUDONYMIZE','NULLIFY','RESTRICT')"
)


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "policy_rules", type_="check")
    op.create_check_constraint(_CONSTRAINT, "policy_rules", _CURRENT)


def downgrade() -> None:
    # Rules using a format-aware mask fall back to the stricter whole-value
    # redaction, so a downgrade never exposes more than the approved policy did.
    op.execute(
        "UPDATE policy_rules SET action = 'REDACT' "
        "WHERE action IN ('MASK_EMAIL','MASK_PHONE','MASK_ID')"
    )
    op.drop_constraint(_CONSTRAINT, "policy_rules", type_="check")
    op.create_check_constraint(_CONSTRAINT, "policy_rules", _PREVIOUS)

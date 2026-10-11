"""Unit tests for the masking compiler and policy state machine."""

import uuid

import pytest

from app.services.policies.compiler import (
    ColumnDecision,
    CompileError,
    build_preview,
    catalog_columns_to_decisions,
    compile_plan,
    compile_sample_query,
    view_name_for,
)
from app.services.policies.preview import SAMPLE_ROWS, sample_values
from app.services.policies.service import PolicyFailure


def _columns():
    return [
        ColumnDecision(name="id", data_type="bigint", action="KEEP", source_column="id"),
        ColumnDecision(name="email", data_type="text", action="REDACT", source_column="email"),
        ColumnDecision(name="phone", data_type="text", action="NULLIFY", source_column="phone"),
    ]


def test_compile_plan_generates_security_barrier_view():
    plan = compile_plan(source_schema="enterprise", source_table="customers", columns=_columns())
    assert plan.view_schema == "privacyshield_masked"
    assert "security_barrier = true" in plan.sql
    assert "CREATE OR REPLACE VIEW" in plan.sql
    assert plan.statements == [plan.sql]
    assert len(plan.plan_hash) == 64


def test_compile_plan_nullifies_unresolved_columns():
    columns = [
        ColumnDecision(name="id", data_type="bigint", action="KEEP", source_column="id"),
        ColumnDecision(name="secret", data_type="text", action="NULLIFY", source_column="secret"),
    ]
    plan = compile_plan(source_schema="public", source_table="test", columns=columns)
    assert 'NULL::text AS "secret"' in plan.sql


def test_compile_plan_redact_preserves_null():
    columns = [
        ColumnDecision(name="email", data_type="text", action="REDACT", source_column="email")
    ]
    plan = compile_plan(source_schema="public", source_table="test", columns=columns)
    assert "CASE WHEN" in plan.sql
    assert "'[REDACTED]'" in plan.sql


def test_compile_plan_partial_masks_text():
    columns = [
        ColumnDecision(name="phone", data_type="text", action="PARTIAL", source_column="phone")
    ]
    plan = compile_plan(source_schema="public", source_table="test", columns=columns)
    assert "right(" in plan.sql
    assert "'***'" in plan.sql


def test_compile_plan_pseudonymize_uses_keyed_hmac_and_text_output():
    columns = [
        ColumnDecision(
            name="email",
            data_type="text",
            action="PSEUDONYMIZE",
            pseudonym_domain="contact",
            source_column="email",
        ),
    ]
    plan = compile_plan(source_schema="public", source_table="test", columns=columns)
    assert "extensions.hmac" in plan.sql
    assert "convert_to" in plan.sql
    assert "pseudonym_keys" in plan.sql
    assert "contact" in plan.sql
    # Pseudonym output is text, never cast back to the source type.
    assert 'AS "email"' in plan.sql
    assert "::text AS" not in plan.sql


def test_compile_plan_rejects_empty_columns():
    with pytest.raises(CompileError, match="At least one column"):
        compile_plan(source_schema="public", source_table="test", columns=[])


def test_compile_plan_rejects_invalid_identifiers():
    columns = [
        ColumnDecision(
            name="id; DROP TABLE users", data_type="bigint", action="KEEP", source_column="id"
        ),
    ]
    with pytest.raises(CompileError, match="identifier"):
        compile_plan(source_schema="public", source_table="test", columns=columns)


def test_compile_plan_rejects_injected_domain():
    columns = [
        ColumnDecision(
            name="email",
            data_type="text",
            action="PSEUDONYMIZE",
            pseudonym_domain="x' AND 1=1 --",
            source_column="email",
        ),
    ]
    with pytest.raises(CompileError, match="domain"):
        compile_plan(source_schema="public", source_table="test", columns=columns)


def test_compile_plan_rejects_untrusted_data_type():
    columns = [
        ColumnDecision(
            name="x", data_type="text); DROP TABLE users; --", action="NULLIFY", source_column="x"
        ),
    ]
    with pytest.raises(CompileError, match="data type"):
        compile_plan(source_schema="public", source_table="test", columns=columns)


def test_view_name_is_deterministic_and_bounded():
    first = view_name_for("enterprise", "customers")
    second = view_name_for("enterprise", "customers")
    assert first == second
    assert first != view_name_for("enterprise", "accounts")
    assert len(first) <= 63
    long_name = view_name_for("enterprise", "t" * 63)
    assert len(long_name) <= 63


def test_catalog_columns_to_decisions_defaults_nullify():
    catalog = [
        {"name": "id", "data_type": "bigint"},
        {"name": "email", "data_type": "text"},
        {"name": "phone", "data_type": "text"},
    ]
    decisions = catalog_columns_to_decisions(catalog, {"email": "REDACT"})
    assert [d.action for d in decisions] == ["NULLIFY", "REDACT", "NULLIFY"]


def test_catalog_columns_to_decisions_assigns_domains():
    catalog = [
        {"name": "email", "data_type": "text"},
        {"name": "phone", "data_type": "text"},
    ]
    decisions = catalog_columns_to_decisions(
        catalog,
        {"email": "PSEUDONYMIZE", "phone": "PSEUDONYMIZE"},
        {"email": "contact", "phone": "contact"},
    )
    assert decisions[0].pseudonym_domain == "contact"
    assert decisions[1].pseudonym_domain == "contact"


def test_plan_hash_is_deterministic_for_same_rules():
    plan1 = compile_plan(source_schema="enterprise", source_table="customers", columns=_columns())
    plan2 = compile_plan(source_schema="enterprise", source_table="customers", columns=_columns())
    assert plan1.plan_hash == plan2.plan_hash


def test_plan_hash_changes_with_different_rules():
    base = [ColumnDecision(name="id", data_type="bigint", action="KEEP", source_column="id")]
    changed = [ColumnDecision(name="id", data_type="bigint", action="NULLIFY", source_column="id")]
    plan1 = compile_plan(source_schema="public", source_table="test", columns=base)
    plan2 = compile_plan(source_schema="public", source_table="test", columns=changed)
    assert plan1.plan_hash != plan2.plan_hash


def test_build_preview_reports_columns_and_sql():
    preview = build_preview(
        policy_id=uuid.uuid4(),
        source_schema="enterprise",
        source_table="customers",
        columns=_columns(),
    )
    assert len(preview.columns) == 3
    assert preview.columns[0].name == "id"
    assert preview.view_schema == "privacyshield_masked"
    assert "CREATE OR REPLACE VIEW" in preview.sql


def test_policy_failure_code():
    exc = PolicyFailure("SCHEMA_DRIFT")
    assert exc.code == "SCHEMA_DRIFT"
    assert str(exc) == "SCHEMA_DRIFT"


@pytest.mark.parametrize(
    ("action", "fragment"),
    [
        ("MASK_EMAIL", "left(\"contact\"::text, 1) || '***' || substring("),
        ("MASK_PHONE", "'[0-9](?=([^0-9]*[0-9]){4})', '*', 'g')"),
        ("MASK_ID", "'[A-Za-z0-9](?=([^A-Za-z0-9]*[A-Za-z0-9]){4})', '*', 'g')"),
    ],
)
def test_compile_plan_format_masks_preserve_null_and_fail_closed(action, fragment):
    columns = [
        ColumnDecision(name="contact", data_type="text", action=action, source_column="contact")
    ]
    plan = compile_plan(source_schema="public", source_table="test", columns=columns)
    assert fragment in plan.sql
    assert 'CASE WHEN "contact" IS NULL THEN NULL' in plan.sql
    # A value without the expected shape is replaced, never partially shown.
    assert "ELSE '***' END AS \"contact\"" in plan.sql
    # Bound parameters use %s, so compiled expressions must never contain one.
    assert "%" not in plan.sql


def test_format_masks_change_the_plan_fingerprint():
    def fingerprint(action):
        column = ColumnDecision(name="c", data_type="text", action=action, source_column="c")
        return compile_plan(source_schema="s", source_table="t", columns=[column]).plan_hash

    hashes = {fingerprint(a) for a in ("PARTIAL", "MASK_EMAIL", "MASK_PHONE", "MASK_ID")}
    assert len(hashes) == 4


def test_sample_query_reads_only_bound_values():
    columns = [
        ColumnDecision(name="id", data_type="bigint", action="KEEP", source_column="id"),
        ColumnDecision(name="email", data_type="text", action="MASK_EMAIL", source_column="email"),
    ]
    query = compile_sample_query(columns, 2)
    assert query.count("%s") == 4
    row = "(%s::bigint, %s::text)"
    assert f'(VALUES {row}, {row}) AS src("id", "email")' in query
    assert '"id"::text AS before_0' in query and "AS after_1" in query
    # The only relation in the FROM clause is the literal VALUES list.
    assert query.count(" FROM ") == 1
    with pytest.raises(CompileError):
        compile_sample_query(columns, 0)
    with pytest.raises(CompileError):
        compile_sample_query([], 1)
    with pytest.raises(CompileError):
        compile_sample_query(
            [ColumnDecision(name="x", data_type="text); DROP", action="KEEP", source_column="x")],
            1,
        )


@pytest.mark.parametrize(
    ("column", "action", "first"),
    [
        ({"name": "email", "udt_name": "text"}, "KEEP", "priya.sharma@example.com"),
        ({"name": "contact", "udt_name": "varchar"}, "MASK_EMAIL", "priya.sharma@example.com"),
        ({"name": "mobileNumber", "udt_name": "text"}, "KEEP", "+91 98765 43210"),
        ({"name": "phone", "udt_name": "int8"}, "MASK_PHONE", "919876543210"),
        ({"name": "pan", "udt_name": "text"}, "MASK_ID", "ABCPK1234F"),
        ({"name": "reference", "udt_name": "text"}, "MASK_ID", "ACC0012345678901"),
        ({"name": "full_name", "udt_name": "text"}, "REDACT", "Priya Sharma"),
        ({"name": "company", "udt_name": "text"}, "KEEP", "Sample text 1"),
        ({"name": "id", "udt_name": "int4"}, "KEEP", "1001"),
        ({"name": "email", "udt_name": "int4"}, "KEEP", "1001"),
        ({"name": "balance", "udt_name": "numeric"}, "KEEP", "2500.75"),
        ({"name": "tags", "udt_name": "_text"}, "KEEP", None),
        ({}, "NULLIFY", None),
    ],
)
def test_sample_values_are_fabricated_from_type_name_and_action(column, action, first):
    values = sample_values(column, action)
    assert len(values) == SAMPLE_ROWS
    assert values[0] == first

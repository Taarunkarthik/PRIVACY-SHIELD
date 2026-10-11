"""Unit tests for per-audience masking: compiled views, names and the fingerprint."""

import hashlib
import json
import re
import uuid

import pytest
from pydantic import ValidationError

from app.schemas.policies import PolicyCreate, PolicyRuleCreate
from app.services.policies.compiler import (
    AUDIENCE_ROLES,
    AUDIENCES,
    ColumnDecision,
    CompileError,
    compile_plan,
    view_name_for,
)

READER_SHAPE = re.compile(r".*_[0-9a-f]{12}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,62}")


def _decision(name, action, data_type="text", domain=None):
    return ColumnDecision(
        name=name,
        data_type=data_type,
        action=action,
        pseudonym_domain=domain,
        source_column=name,
    )


def _reader():
    return [
        _decision("id", "KEEP", "bigint"),
        _decision("full_name", "REDACT"),
        _decision("email", "MASK_EMAIL"),
        _decision("phone", "NULLIFY"),
        _decision("pan", "PSEUDONYMIZE", domain="demo"),
        _decision("balance", "PARTIAL", "numeric(14,2)"),
    ]


def _support():
    return [
        _decision("id", "KEEP", "bigint"),
        _decision("full_name", "NULLIFY"),
        _decision("email", "MASK_EMAIL"),
        _decision("phone", "MASK_PHONE"),
        _decision("pan", "NULLIFY"),
        _decision("balance", "NULLIFY", "numeric(14,2)"),
    ]


def _analyst():
    return [
        _decision("id", "KEEP", "bigint"),
        _decision("full_name", "NULLIFY"),
        _decision("email", "PSEUDONYMIZE", domain="demo"),
        _decision("phone", "NULLIFY"),
        _decision("pan", "NULLIFY"),
        _decision("balance", "NULLIFY", "numeric(14,2)"),
    ]


def _compile(reader=None, **audiences):
    return compile_plan(
        source_schema="enterprise",
        source_table="customers",
        columns=reader or _reader(),
        audience_columns=audiences or None,
    )


def _pre_audience_fingerprint(source_schema, source_table, view_name, columns):
    """The fingerprint exactly as the compiler computed it before audiences existed."""
    content = json.dumps(
        {
            "source_schema": source_schema,
            "source_table": source_table,
            "view_schema": "privacyshield_masked",
            "view_name": view_name,
            "columns": [
                {
                    "name": c.name,
                    "source_column": c.source_column or c.name,
                    "action": c.action,
                    "pseudonym_domain": c.pseudonym_domain,
                }
                for c in columns
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_reader_only_plan_matches_values_recorded_before_audiences_existed():
    # Recorded by running this fixture through the compiler as it was before the
    # audience change. An approved policy stored with this fingerprint must
    # still deploy, so neither value may ever move.
    plan = _compile()
    assert plan.view_name == "customers_20f808f337c9"
    assert plan.plan_hash == "2b3ff43302cd109f72d392459736eb048ac9551720e4d1509eecec9a7b76ca22"
    assert (
        hashlib.sha256(plan.sql.encode()).hexdigest()
        == "524e2d7854374e5c1b4ff69eeab0c4b586e23d04a693902da3e579ef3dd0a864"
    )
    assert plan.statements == [plan.sql]
    assert plan.audiences == ["reader"]
    assert [(v.audience, v.role, v.view_name, v.sql) for v in plan.views] == [
        ("reader", "ps_reader", plan.view_name, plan.sql)
    ]
    # An empty audience mapping is the same thing as none at all.
    empty = compile_plan(
        source_schema="enterprise",
        source_table="customers",
        columns=_reader(),
        audience_columns={},
    )
    assert (empty.sql, empty.plan_hash) == (plan.sql, plan.plan_hash)


@pytest.mark.parametrize(
    ("schema", "table", "columns"),
    [
        ("enterprise", "customers", _reader()),
        ("public", "t", [_decision("id", "KEEP", "bigint")]),
        ("enterprise", "accounts", [_decision("balance", "REDACT", "numeric(14,2)")]),
        ("s", "t" * 63, [_decision("a", "PSEUDONYMIZE", domain="contact"), _decision("b", "KEEP")]),
        ("enterprise", "customers_support", [_decision("note", "MASK_ID")]),
    ],
)
def test_reader_only_fingerprint_keeps_its_pre_audience_formula(schema, table, columns):
    plan = compile_plan(source_schema=schema, source_table=table, columns=columns)
    prefix = table[:50]
    digest = hashlib.sha256(f"{schema}\x00{table}".encode()).hexdigest()[:12]
    assert plan.view_name == f"{prefix}_{digest}"
    assert plan.plan_hash == _pre_audience_fingerprint(schema, table, plan.view_name, columns)
    assert plan.sql.startswith(
        f'CREATE OR REPLACE VIEW "privacyshield_masked"."{plan.view_name}" '
        "WITH (security_barrier = true) AS\nSELECT\n"
    )
    assert plan.sql.endswith(f'\nFROM "{schema}"."{table}"')


def test_multi_audience_plan_has_one_statement_per_audience():
    plan = _compile(support=_support(), analyst=_analyst())
    assert plan.audiences == ["reader", "support", "analyst"]
    assert [view.role for view in plan.views] == ["ps_reader", "ps_support", "ps_analyst"]
    assert plan.statements == [view.sql for view in plan.views]
    assert len(plan.statements) == 3

    names = [view.view_name for view in plan.views]
    assert names == [
        "customers_20f808f337c9",
        "customers_20f808f337c9_support",
        "customers_20f808f337c9_analyst",
    ]
    assert len(set(names)) == 3
    for view in plan.views:
        assert IDENTIFIER.fullmatch(view.view_name)
        assert len(view.view_name.encode()) <= 63
        assert view.sql.startswith(
            f'CREATE OR REPLACE VIEW "privacyshield_masked"."{view.view_name}" '
            "WITH (security_barrier = true) AS\n"
        )
        assert view.sql.endswith('\nFROM "enterprise"."customers"')
        # Each statement creates exactly one view and names no other audience's.
        assert view.sql.count("CREATE OR REPLACE VIEW") == 1
        others = [name for name in names if name != view.view_name]
        assert not [name for name in others if f'"{name}"' in view.sql]

    # Adding audiences leaves the reader's view exactly as it was.
    reader_only = _compile()
    assert (plan.view_name, plan.sql, plan.columns) == (
        reader_only.view_name,
        reader_only.sql,
        reader_only.columns,
    )
    assert plan.view_for("reader").sql == reader_only.sql

    # Each audience's statement carries that audience's decisions.
    support, analyst = plan.view_for("support"), plan.view_for("analyst")
    assert "regexp_replace(\"phone\"::text, '[0-9](?=" in support.sql
    assert "extensions.hmac" not in support.sql
    assert "extensions.hmac(convert_to(\"email\"::text, 'UTF8')" in analyst.sql
    assert 'NULL::text AS "phone"' in analyst.sql


def test_an_audience_without_decisions_gets_no_view():
    plan = _compile(analyst=_analyst())
    assert plan.audiences == ["reader", "analyst"]
    assert plan.view_for("support") is None
    assert len(plan.statements) == 2
    assert "support" not in "".join(plan.statements)


def test_audience_order_is_fixed_whatever_order_the_caller_uses():
    forward = _compile(support=_support(), analyst=_analyst())
    backward = _compile(analyst=_analyst(), support=_support())
    assert backward.audiences == ["reader", "support", "analyst"]
    assert (backward.statements, backward.plan_hash) == (forward.statements, forward.plan_hash)


def _changed(decisions, name, **fields):
    return [
        ColumnDecision(**{**vars(decision), **fields}) if decision.name == name else decision
        for decision in decisions
    ]


def test_fingerprint_covers_every_audiences_decisions():
    base = _compile(support=_support(), analyst=_analyst())
    variants = {
        "reader only": _compile(),
        "reader and support": _compile(support=_support()),
        "reader and analyst": _compile(analyst=_analyst()),
        "reader rule changed": _compile(
            _changed(_reader(), "email", action="REDACT"), support=_support(), analyst=_analyst()
        ),
        "support rule changed": _compile(
            support=_changed(_support(), "phone", action="KEEP"), analyst=_analyst()
        ),
        "support rule added": _compile(
            support=_changed(_support(), "full_name", action="REDACT"), analyst=_analyst()
        ),
        "analyst rule changed": _compile(
            support=_support(), analyst=_changed(_analyst(), "email", action="MASK_EMAIL")
        ),
        "analyst domain changed": _compile(
            support=_support(), analyst=_changed(_analyst(), "email", pseudonym_domain="other")
        ),
        # The same decisions given to the other audience are a different policy.
        "audiences swapped": _compile(support=_analyst(), analyst=_support()),
    }
    hashes = {name: plan.plan_hash for name, plan in variants.items()}
    assert base.plan_hash not in hashes.values()
    assert len(set(hashes.values())) == len(hashes), hashes
    assert _compile(support=_support(), analyst=_analyst()).plan_hash == base.plan_hash


@pytest.mark.parametrize(
    "audience",
    [
        "admin",
        "",
        "READER",
        "Support",
        "support ",
        'support"; DROP VIEW privacyshield_masked.x; --',
        "ps_support",
        # The reader's decisions are the plan's own columns, never a second entry.
        "reader",
    ],
)
def test_unknown_audience_never_reaches_sql(audience):
    with pytest.raises(CompileError, match="Unknown audience"):
        compile_plan(
            source_schema="enterprise",
            source_table="customers",
            columns=_reader(),
            audience_columns={audience: _support()},
        )


@pytest.mark.parametrize("audience", ["admin", "", "READER", 'x"; DROP ROLE ps_reader; --'])
def test_view_name_rejects_unknown_audience(audience):
    with pytest.raises(CompileError, match="Unknown audience"):
        view_name_for("enterprise", "customers", audience)


def test_audience_decisions_are_validated_like_reader_decisions():
    def with_support(decisions):
        return compile_plan(
            source_schema="enterprise",
            source_table="customers",
            columns=_reader(),
            audience_columns={"support": decisions},
        )

    with pytest.raises(CompileError, match="identifier"):
        with_support([_decision("id; DROP TABLE users", "KEEP")])
    with pytest.raises(CompileError, match="data type"):
        with_support([_decision("x", "NULLIFY", "text); DROP TABLE users; --")])
    with pytest.raises(CompileError, match="domain"):
        with_support([_decision("email", "PSEUDONYMIZE", domain="x' OR 1=1 --")])
    with pytest.raises(CompileError, match="At least one column"):
        with_support([])


def test_reader_view_name_cannot_take_an_audience_views_name():
    taken = view_name_for("enterprise", "customers", "support")
    with pytest.raises(CompileError, match="distinct"):
        compile_plan(
            source_schema="enterprise",
            source_table="customers",
            columns=_reader(),
            view_name=taken,
            audience_columns={"support": _support()},
        )


@pytest.mark.parametrize(
    "table",
    [
        "customers",
        "t",
        "t" * 63,
        "customers_support",
        "customers_analyst",
        # Table names shaped like view names of either kind.
        "customers_20f808f337c9",
        "customers_20f808f337c9_support",
        "x_0123456789ab",
        "a" * 40 + "_0123456789ab_support",
    ],
)
def test_view_names_are_bounded_deterministic_and_never_shaped_like_a_reader_view(table):
    reader = view_name_for("enterprise", table)
    assert reader == view_name_for("enterprise", table, "reader")
    assert READER_SHAPE.fullmatch(reader) and len(reader) <= 63
    names = {reader}
    for audience in AUDIENCES[1:]:
        name = view_name_for("enterprise", table, audience)
        assert name == view_name_for("enterprise", table, audience)
        assert len(name.encode()) <= 63 and IDENTIFIER.fullmatch(name)
        assert name.endswith(f"_{audience}")
        # Every reader view name, of any table, ends in twelve hex digits. No
        # audience view name does, so the two can never be the same name.
        assert not READER_SHAPE.fullmatch(name)
        # Same table digest as the reader view, so the pair is recognisable.
        assert reader[-12:] in name
        assert name != view_name_for("other_schema", table, audience)
        names.add(name)
    assert len(names) == len(AUDIENCES)


def test_audience_roles_are_a_fixed_mapping():
    assert AUDIENCE_ROLES == {
        "reader": "ps_reader",
        "support": "ps_support",
        "analyst": "ps_analyst",
    }
    assert AUDIENCES == ("reader", "support", "analyst")


def _policy(rules):
    return PolicyCreate(
        connection_id=uuid.uuid4(),
        schema_name="enterprise",
        table_name="customers",
        snapshot_id=uuid.uuid4(),
        rules=rules,
    )


def test_rule_audience_defaults_to_reader_and_is_restricted():
    assert PolicyRuleCreate(column_name="email", action="KEEP").audience == "reader"
    assert PolicyRuleCreate.model_validate(
        {"column_name": "email", "action": "MASK_EMAIL", "audience": "support"}
    ).audience == "support"
    for audience in ("admin", "", "READER", None, "support; DROP"):
        with pytest.raises(ValidationError):
            PolicyRuleCreate.model_validate(
                {"column_name": "email", "action": "KEEP", "audience": audience}
            )


def test_rule_count_is_bounded_per_audience():
    def rules(audience, count):
        return [
            {"column_name": f"c{index}", "action": "KEEP", "audience": audience}
            for index in range(count)
        ]

    full = _policy(rules("reader", 200) + rules("support", 200) + rules("analyst", 200))
    assert len(full.rules) == 600
    # The limit that applied before audiences still applies to each of them.
    for audience in ("reader", "support"):
        with pytest.raises(ValidationError):
            _policy(rules(audience, 201))

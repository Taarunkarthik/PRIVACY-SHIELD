"""Compile policy rules into PostgreSQL security-barrier view definitions.

Pure functions only: no database access and no source-row reads. Every exposed
column receives an explicit decision; columns without a rule become typed NULL.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field

from app.schemas.policies import PolicyAction, PolicyPreview, PolicyPreviewColumn

VIEW_SCHEMA = "privacyshield_masked"
PRIVATE_SCHEMA = "privacyshield_private"
VIEW_OWNER_ROLE = "ps_view_owner"
VIEW_READER_ROLE = "ps_reader"
MAX_IDENTIFIER = 63
_DOMAIN_PATTERN = re.compile(r"^[a-z0-9_]{1,60}$")
_DATA_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9_ .,()\[\]]{1,96}$")
# Shown when a value does not have the shape its mask expects. Nothing from the
# source value is revealed in that case (fail closed).
MASK_FALLBACK = "***"


class CompileError(ValueError):
    """A policy could not be compiled into safe SQL."""


@dataclass
class ColumnDecision:
    name: str
    data_type: str
    action: PolicyAction
    pseudonym_domain: str | None = None
    source_column: str = ""


@dataclass
class CompiledPlan:
    view_schema: str
    view_name: str
    source_schema: str
    source_table: str
    columns: list[ColumnDecision] = field(default_factory=list)
    statements: list[str] = field(default_factory=list)
    sql: str = ""
    plan_hash: str = ""


def quote_ident(name: str) -> str:
    """Quote a PostgreSQL identifier, doubling embedded quotes."""
    return '"' + name.replace('"', '""') + '"'


def _qualified(schema: str, name: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(name)}"


def view_name_for(source_schema: str, source_table: str) -> str:
    """Deterministically derive a view name from schema and table.

    Stable across versions so a newer policy replaces the same view, and stable
    across processes (unlike Python's randomized hash()).
    """
    digest = hashlib.sha256(f"{source_schema}\x00{source_table}".encode()).hexdigest()
    prefix = source_table[: MAX_IDENTIFIER - 1 - 12]
    return f"{prefix}_{digest[:12]}"


def _pseudonym_expr(domain: str, source_column: str) -> str:
    """Deterministic keyed pseudonym over the text form of the source value.

    Equal source values with the same domain produce equal pseudonyms. A missing
    domain key yields NULL (fail closed). Output is text per the written design.
    """
    if not _DOMAIN_PATTERN.fullmatch(domain):
        raise CompileError("Pseudonym domain must be lowercase letters, digits, or underscores")
    source = f"convert_to({quote_ident(source_column)}::text, 'UTF8')"
    key = (
        f"(SELECT key FROM {PRIVATE_SCHEMA}.pseudonym_keys "
        f"WHERE domain = '{domain}' AND key_version = 1)"
    )
    return f"encode(extensions.hmac({source}, {key}, 'sha256'), 'hex')"


def _mask_email_expr(source: str) -> str:
    """Keep the first character and the domain: ``c***@example.com``.

    Only a value with exactly one ``@`` and no whitespace is treated as an
    address. Anything else is replaced entirely, so free text stored in an
    email column is never partially exposed.
    """
    text = f"{source}::text"
    return (
        f"CASE WHEN {source} IS NULL THEN NULL "
        f"WHEN {text} ~ '^[^@[:space:]]+@[^@[:space:]]+$' "
        f"THEN left({text}, 1) || '***' || substring({text} from '@.*$') "
        f"ELSE '{MASK_FALLBACK}' END"
    )


def _mask_phone_expr(source: str) -> str:
    """Mask every digit except the last four, keeping the punctuation.

    ``+91 90000 00001`` becomes ``+** ***** *0001``. A value containing letters,
    or fewer than eight digits, is replaced entirely.
    """
    text = f"{source}::text"
    return (
        f"CASE WHEN {source} IS NULL THEN NULL "
        f"WHEN {text} ~ '^[0-9+(). -]{{8,32}}$' "
        f"AND length(regexp_replace({text}, '[^0-9]', '', 'g')) >= 8 "
        f"THEN regexp_replace({text}, '[0-9](?=([^0-9]*[0-9]){{4}})', '*', 'g') "
        f"ELSE '{MASK_FALLBACK}' END"
    )


def _mask_id_expr(source: str) -> str:
    """Mask letters and digits except the last four, keeping separators.

    Suits PAN, Aadhaar, card and account numbers: ``2345 6789 0001`` becomes
    ``**** **** 0001`` and ``ABCDE1234F`` becomes ``******234F``. A value without
    a digit, with other characters, or with fewer than eight letters and digits
    is replaced entirely.
    """
    text = f"{source}::text"
    return (
        f"CASE WHEN {source} IS NULL THEN NULL "
        f"WHEN {text} ~ '^[A-Za-z0-9 ./-]{{8,64}}$' AND {text} ~ '[0-9]' "
        f"AND length(regexp_replace({text}, '[^A-Za-z0-9]', '', 'g')) >= 8 "
        f"THEN regexp_replace("
        f"{text}, '[A-Za-z0-9](?=([^A-Za-z0-9]*[A-Za-z0-9]){{4}})', '*', 'g') "
        f"ELSE '{MASK_FALLBACK}' END"
    )


_FORMAT_MASKS = {
    "MASK_EMAIL": _mask_email_expr,
    "MASK_PHONE": _mask_phone_expr,
    "MASK_ID": _mask_id_expr,
}


def column_expression(decision: ColumnDecision) -> str:
    """Generate the bare projection expression for one column (no alias)."""
    source = quote_ident(decision.source_column or decision.name)
    if decision.action == "KEEP":
        return source
    if decision.action in ("NULLIFY", "RESTRICT"):
        # No value is exposed; keep the declared type so consumers see NULL.
        return f"NULL::{decision.data_type}"
    if decision.action == "REDACT":
        return f"CASE WHEN {source} IS NULL THEN NULL ELSE '[REDACTED]' END"
    if decision.action == "PARTIAL":
        return (
            f"CASE WHEN {source} IS NULL THEN NULL "
            f"ELSE '***' || right({source}::text, 4) END"
        )
    if decision.action in _FORMAT_MASKS:
        return _FORMAT_MASKS[decision.action](source)
    if decision.action == "PSEUDONYMIZE":
        domain = decision.pseudonym_domain or "default"
        return _pseudonym_expr(domain, decision.source_column or decision.name)
    raise CompileError(f"Unsupported action: {decision.action}")


def _compile_column_expr(decision: ColumnDecision) -> str:
    """Generate the explicit, aliased projection for one column."""
    return f"  {column_expression(decision)} AS {quote_ident(decision.name)}"


def _validate(decision: ColumnDecision) -> None:
    for identifier in (decision.name, decision.source_column or decision.name):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]{0,62}", identifier):
            raise CompileError("Column names must be simple PostgreSQL identifiers")
    if not _DATA_TYPE_PATTERN.fullmatch(decision.data_type):
        raise CompileError("Column data type is not permitted in compiled SQL")
    if decision.action == "PSEUDONYMIZE":
        domain = decision.pseudonym_domain or "default"
        _pseudonym_expr(domain, decision.source_column or decision.name)


def compile_plan(
    *,
    source_schema: str,
    source_table: str,
    columns: list[ColumnDecision],
    view_name: str | None = None,
) -> CompiledPlan:
    """Compile column decisions into a complete security-barrier view statement."""
    if not columns:
        raise CompileError("At least one column decision is required")
    for decision in columns:
        _validate(decision)

    vname = view_name or view_name_for(source_schema, source_table)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]{0,62}", vname):
        raise CompileError("View name must be a simple PostgreSQL identifier")
    target = _qualified(VIEW_SCHEMA, vname)
    source = _qualified(source_schema, source_table)
    select_list = ",\n".join(_compile_column_expr(decision) for decision in columns)

    statement = (
        f"CREATE OR REPLACE VIEW {target} WITH (security_barrier = true) AS\n"
        f"SELECT\n{select_list}\nFROM {source}"
    )

    plan_content = json.dumps(
        {
            "source_schema": source_schema,
            "source_table": source_table,
            "view_schema": VIEW_SCHEMA,
            "view_name": vname,
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
    plan_hash = hashlib.sha256(plan_content.encode("utf-8")).hexdigest()

    return CompiledPlan(
        view_schema=VIEW_SCHEMA,
        view_name=vname,
        source_schema=source_schema,
        source_table=source_table,
        columns=list(columns),
        statements=[statement],
        sql=statement,
        plan_hash=plan_hash,
    )


def compile_sample_query(columns: list[ColumnDecision], row_count: int) -> str:
    """Build a query that runs the plan's expressions over supplied literal rows.

    The source is a ``VALUES`` list of bound parameters, never a table, so the
    result shows exactly what the deployed view would produce for those inputs
    without reading a single source row. Each output row holds the text form of
    every input followed by the text form of every masked expression.
    """
    if not columns or not 1 <= row_count <= 10:
        raise CompileError("A sample query needs columns and between 1 and 10 rows")
    for decision in columns:
        _validate(decision)
    names = ", ".join(quote_ident(c.source_column or c.name) for c in columns)
    row = "(" + ", ".join(f"%s::{c.data_type}" for c in columns) + ")"
    values = ", ".join([row] * row_count)
    # Positional aliases keep every output column distinct for dict-style rows.
    before = [
        f"{quote_ident(c.source_column or c.name)}::text AS before_{index}"
        for index, c in enumerate(columns)
    ]
    after = [
        f"({column_expression(c)})::text AS after_{index}" for index, c in enumerate(columns)
    ]
    return f"SELECT {', '.join(before + after)} FROM (VALUES {values}) AS src({names})"


def build_preview(
    *,
    policy_id,
    source_schema: str,
    source_table: str,
    columns: list[ColumnDecision],
    view_name: str | None = None,
) -> PolicyPreview:
    """Build a preview response from a compiled plan."""
    plan = compile_plan(
        source_schema=source_schema,
        source_table=source_table,
        columns=columns,
        view_name=view_name,
    )
    return PolicyPreview(
        policy_id=policy_id,
        schema_name=source_schema,
        table_name=source_table,
        view_schema=plan.view_schema,
        view_name=plan.view_name,
        columns=[
            PolicyPreviewColumn(
                name=c.name,
                data_type=c.data_type,
                action=c.action,
                pseudonym_domain=c.pseudonym_domain,
                source_column=c.source_column or c.name,
            )
            for c in plan.columns
        ],
        sql=plan.sql,
    )


def catalog_columns_to_decisions(
    catalog_columns: list[dict],
    rules: dict[str, PolicyAction],
    pseudonym_domains: dict[str, str] | None = None,
) -> list[ColumnDecision]:
    """Convert catalog columns to decisions, defaulting unresolved columns to NULL."""
    pseudonym_domains = pseudonym_domains or {}
    decisions = []
    for col in catalog_columns:
        name = col["name"]
        action = rules.get(name, "NULLIFY")
        decisions.append(
            ColumnDecision(
                name=name,
                data_type=col["data_type"],
                action=action,
                pseudonym_domain=pseudonym_domains.get(name),
                source_column=name,
            )
        )
    return decisions

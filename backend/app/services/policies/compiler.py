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


def _compile_column_expr(decision: ColumnDecision) -> str:
    """Generate the explicit projection expression for one column."""
    source = quote_ident(decision.source_column or decision.name)
    target = quote_ident(decision.name)
    if decision.action == "KEEP":
        return f"  {source} AS {target}"
    if decision.action in ("NULLIFY", "RESTRICT"):
        # No value is exposed; keep the declared type so consumers see NULL.
        return f"  NULL::{decision.data_type} AS {target}"
    if decision.action == "REDACT":
        return f"  CASE WHEN {source} IS NULL THEN NULL ELSE '[REDACTED]' END AS {target}"
    if decision.action == "PARTIAL":
        return (
            f"  CASE WHEN {source} IS NULL THEN NULL "
            f"ELSE '***' || right({source}::text, 4) END AS {target}"
        )
    if decision.action == "PSEUDONYMIZE":
        domain = decision.pseudonym_domain or "default"
        expr = _pseudonym_expr(domain, decision.source_column or decision.name)
        return f"  {expr} AS {target}"
    raise CompileError(f"Unsupported action: {decision.action}")


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

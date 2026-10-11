"""Compile policy rules into PostgreSQL security-barrier view definitions.

Pure functions only: no database access and no source-row reads. Every exposed
column receives an explicit decision; columns without a rule become typed NULL.

A policy holds decisions for up to three fixed audiences. Each audience that has
a view gets its own statement, view name and target role. The general "reader"
audience always has a view; another audience has one only when the policy holds
at least one rule for it.
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
READER_AUDIENCE = "reader"
# Audience -> the target role that may read that audience's view. A fixed
# mapping: an audience value from a request or a stored rule only ever selects
# an entry here, and nothing else about it reaches compiled SQL.
AUDIENCE_ROLES = {
    READER_AUDIENCE: VIEW_READER_ROLE,
    "support": "ps_support",
    "analyst": "ps_analyst",
}
AUDIENCES = tuple(AUDIENCE_ROLES)
MAX_IDENTIFIER = 63
_DIGEST_CHARS = 12
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,62}")
# A reader view name always ends in an underscore and twelve hex digits.
_READER_VIEW_SHAPE = re.compile(r".*_[0-9a-f]{12}")
_DOMAIN_PATTERN = re.compile(r"^[a-z0-9_]{1,60}$")
_DATA_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9_ .,()\[\]]{1,96}$")
# Shown when a value does not have the shape its mask expects. Nothing from the
# source value is revealed in that case (fail closed).
MASK_FALLBACK = "***"
# One address: up to 64 characters with no "@" or whitespace, an "@", then a host
# name of dot-separated labels ending in a purely alphabetic one. A bare word or
# a run of digits after the "@" is not a host. POSIX classes, no backslashes.
EMAIL_SHAPE = (
    r"^[^@[:space:]]{1,64}@"
    r"([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?[.]){1,8}[A-Za-z]{2,24}$"
)


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
class AudienceView:
    """One audience's masked view: who reads it, its name, columns and statement."""

    audience: str
    role: str
    view_name: str
    columns: list[ColumnDecision] = field(default_factory=list)
    sql: str = ""


@dataclass
class CompiledPlan:
    """A compiled policy.

    ``view_name``, ``columns`` and ``sql`` describe the reader view, as they did
    before audiences existed. ``views`` holds every audience that has a view,
    reader first, and ``statements`` holds their statements in the same order.
    """

    view_schema: str
    view_name: str
    source_schema: str
    source_table: str
    columns: list[ColumnDecision] = field(default_factory=list)
    statements: list[str] = field(default_factory=list)
    sql: str = ""
    plan_hash: str = ""
    views: list[AudienceView] = field(default_factory=list)

    @property
    def audiences(self) -> list[str]:
        return [view.audience for view in self.views]

    def view_for(self, audience: str) -> AudienceView | None:
        """The view of one audience, or ``None`` when the policy gives it none."""
        return next((view for view in self.views if view.audience == audience), None)


def quote_ident(name: str) -> str:
    """Quote a PostgreSQL identifier, doubling embedded quotes."""
    return '"' + name.replace('"', '""') + '"'


def _qualified(schema: str, name: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(name)}"


def view_name_for(
    source_schema: str, source_table: str, audience: str = READER_AUDIENCE
) -> str:
    """Deterministically derive a view name from schema, table and audience.

    Stable across versions so a newer policy replaces the same view, and stable
    across processes (unlike Python's randomized hash()).

    The reader view is ``<table>_<digest>``. Another audience's view is
    ``<table>_<digest>_<audience>`` with the same digest and a shorter table
    prefix, so it also fits in 63 characters. A reader name ends in an
    underscore and twelve hex digits. The last twelve characters of the other
    names include the underscore before the audience, so they never have that
    shape and the two cannot be equal, for this table or any other.
    """
    if audience not in AUDIENCE_ROLES:
        raise CompileError("Unknown audience")
    digest = hashlib.sha256(f"{source_schema}\x00{source_table}".encode()).hexdigest()
    digest = digest[:_DIGEST_CHARS]
    if audience == READER_AUDIENCE:
        prefix = source_table[: MAX_IDENTIFIER - 1 - _DIGEST_CHARS]
        return f"{prefix}_{digest}"
    suffix = f"_{digest}_{audience}"
    return f"{source_table[: MAX_IDENTIFIER - len(suffix)]}{suffix}"


for _audience in AUDIENCES[1:]:
    # Guards the claim above against a future audience with a long hex name.
    assert not _READER_VIEW_SHAPE.fullmatch(f"t_{'0' * _DIGEST_CHARS}_{_audience}"), _audience


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

    The value must be a single address and nothing else: a local part, one
    ``@``, then a dotted host name of letters, digits and hyphens that ends in
    letters. Anything else is replaced entirely. Without the host-name rule,
    whatever followed the ``@`` would be shown, so ``a@b.com;9876543210`` or a
    JSON string holding an address would leak the rest of the value.
    """
    text = f"{source}::text"
    return (
        f"CASE WHEN {source} IS NULL THEN NULL "
        f"WHEN {text} ~ '{EMAIL_SHAPE}' "
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
        if not _IDENTIFIER_PATTERN.fullmatch(identifier):
            raise CompileError("Column names must be simple PostgreSQL identifiers")
    if not _DATA_TYPE_PATTERN.fullmatch(decision.data_type):
        raise CompileError("Column data type is not permitted in compiled SQL")
    if decision.action == "PSEUDONYMIZE":
        domain = decision.pseudonym_domain or "default"
        _pseudonym_expr(domain, decision.source_column or decision.name)


def _view_statement(
    view_name: str, source_schema: str, source_table: str, columns: list[ColumnDecision]
) -> str:
    target = _qualified(VIEW_SCHEMA, view_name)
    source = _qualified(source_schema, source_table)
    select_list = ",\n".join(_compile_column_expr(decision) for decision in columns)
    return (
        f"CREATE OR REPLACE VIEW {target} WITH (security_barrier = true) AS\n"
        f"SELECT\n{select_list}\nFROM {source}"
    )


def _hashed_columns(columns: list[ColumnDecision]) -> list[dict]:
    return [
        {
            "name": c.name,
            "source_column": c.source_column or c.name,
            "action": c.action,
            "pseudonym_domain": c.pseudonym_domain,
        }
        for c in columns
    ]


def compile_plan(
    *,
    source_schema: str,
    source_table: str,
    columns: list[ColumnDecision],
    view_name: str | None = None,
    audience_columns: dict[str, list[ColumnDecision]] | None = None,
) -> CompiledPlan:
    """Compile column decisions into security-barrier view statements.

    ``columns`` are the reader's decisions and always produce the reader view.
    ``audience_columns`` maps each other audience that has rules to its full
    list of decisions; an audience left out gets no view. Without it the result
    is exactly the single-audience plan compiled before audiences existed, with
    the same SQL and the same fingerprint.
    """
    if not columns:
        raise CompileError("At least one column decision is required")
    audience_columns = audience_columns or {}
    for audience, decisions in audience_columns.items():
        # Checked before anything is generated: an unknown audience never
        # reaches a view name, a role name, or any other SQL.
        if audience not in AUDIENCE_ROLES or audience == READER_AUDIENCE:
            raise CompileError("Unknown audience")
        if not decisions:
            raise CompileError("At least one column decision is required")
    for decision in columns:
        _validate(decision)
    for decisions in audience_columns.values():
        for decision in decisions:
            _validate(decision)

    vname = view_name or view_name_for(source_schema, source_table)
    if not _IDENTIFIER_PATTERN.fullmatch(vname):
        raise CompileError("View name must be a simple PostgreSQL identifier")
    statement = _view_statement(vname, source_schema, source_table, columns)
    views = [
        AudienceView(
            audience=READER_AUDIENCE,
            role=VIEW_READER_ROLE,
            view_name=vname,
            columns=list(columns),
            sql=statement,
        )
    ]
    # Fixed audience order, whatever order the caller's mapping has.
    for audience in AUDIENCES:
        if audience not in audience_columns:
            continue
        name = view_name_for(source_schema, source_table, audience)
        if not _IDENTIFIER_PATTERN.fullmatch(name):
            raise CompileError("View name must be a simple PostgreSQL identifier")
        decisions = list(audience_columns[audience])
        views.append(
            AudienceView(
                audience=audience,
                role=AUDIENCE_ROLES[audience],
                view_name=name,
                columns=decisions,
                sql=_view_statement(name, source_schema, source_table, decisions),
            )
        )
    if len({view.view_name for view in views}) != len(views):
        raise CompileError("Audience view names must be distinct")

    content: dict = {
        "source_schema": source_schema,
        "source_table": source_table,
        "view_schema": VIEW_SCHEMA,
        "view_name": vname,
        "columns": _hashed_columns(columns),
    }
    if len(views) > 1:
        # Added only when another audience has a view, so a reader-only policy
        # keeps the fingerprint it was approved with before audiences existed.
        content["audiences"] = {
            view.audience: {
                "role": view.role,
                "view_name": view.view_name,
                "columns": _hashed_columns(view.columns),
            }
            for view in views[1:]
        }
    plan_content = json.dumps(content, sort_keys=True, separators=(",", ":"))
    plan_hash = hashlib.sha256(plan_content.encode("utf-8")).hexdigest()

    return CompiledPlan(
        view_schema=VIEW_SCHEMA,
        view_name=vname,
        source_schema=source_schema,
        source_table=source_table,
        columns=list(columns),
        statements=[view.sql for view in views],
        sql=statement,
        plan_hash=plan_hash,
        views=views,
    )


def _sample_expression(decision: ColumnDecision) -> str:
    """The expression a sample preview runs for one column.

    Identical to the deployed expression, except for pseudonyms. A real
    pseudonym is an HMAC under a secret key held on the target. Returning it for
    known example inputs would hand out real tokens, which could be matched
    against masked output, so the preview shows an unkeyed digest of the same
    shape instead. That also keeps the preview free of any table access.
    """
    if decision.action != "PSEUDONYMIZE":
        return column_expression(decision)
    source = quote_ident(decision.source_column or decision.name)
    return (
        f"CASE WHEN {source} IS NULL THEN NULL "
        f"ELSE encode(sha256(convert_to({source}::text, 'UTF8')), 'hex') END"
    )


def compile_sample_query(columns: list[ColumnDecision], row_count: int) -> str:
    """Build a query that runs the plan's expressions over supplied literal rows.

    The source is a ``VALUES`` list of bound parameters and nothing else: no
    table, no key, no source row. For every action but ``PSEUDONYMIZE`` the
    result is exactly what the deployed view would produce for those inputs.
    Each output row holds the text form of every input followed by the text
    form of every masked expression.
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
        f"({_sample_expression(c)})::text AS after_{index}" for index, c in enumerate(columns)
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

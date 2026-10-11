"""Before/after illustration and post-deployment evidence for a masking policy.

Two read-only views of a policy, both evaluated by PostgreSQL itself:

* ``illustrative_samples`` runs the policy's compiled expressions over fabricated
  input values. No source row is read, so it is safe for any policy state.
* ``protected_output`` reads a few rows from the *deployed* view and reports what
  the reader role can and cannot access. It returns only what the approved policy
  already exposes to that role.
"""

import json
import re
from uuid import UUID

import psycopg
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_event
from app.models import DatabaseConnection, MaskingPolicy, PolicyDeployment, User
from app.schemas.policies import (
    AccessCheck,
    PolicySamples,
    ProtectedOutput,
    SampleColumn,
)
from app.services.discovery.catalog import DiscoveryError
from app.services.policies.compiler import (
    VIEW_OWNER_ROLE,
    VIEW_READER_ROLE,
    ColumnDecision,
    CompileError,
    compile_sample_query,
    quote_ident,
)
from app.services.policies.execution import deployer_session, read_access
from app.services.policies.service import (
    PolicyFailure,
    build_plan,
    policy_catalog_columns,
)

SAMPLE_ROWS = 3
OUTPUT_ROW_LIMIT = 5
MAX_CELL_CHARS = 120
_PREVIEW_TIMEOUT_MS = 5000

_EMAILS = ("priya.sharma@example.com", "arjun.mehta@example.org", "f.khan@example.net")
_PHONES = ("+91 98765 43210", "+91 91234 56789", "(022) 2345-6789")
_NAMES = ("Priya Sharma", "Arjun Mehta", "Fatima Khan")
_ADDRESSES = ("14 MG Road, Bengaluru", "7 Park Street, Kolkata", "221 Marine Drive, Mumbai")
_PANS = ("ABCPK1234F", "BNZPM4321K", "CQRPS9876L")
_AADHAARS = ("2345 6789 0124", "3456 7890 1235", "4567 8901 2346")
_CARDS = ("4111 1111 1111 1111", "5500 0000 0000 0004", "4000 1234 5678 9010")
_ACCOUNTS = ("ACC0012345678901", "ACC0098765432109", "ACC0055501234567")
_NOTES = (
    "Customer asked for a call back on 98765 43210.",
    "Refund sent to priya.sharma@example.com.",
    "Address change requested by phone.",
)
_JSON = tuple(
    json.dumps({"contact": {"email": email}, "preferences": {"newsletter": index % 2 == 0}})
    for index, email in enumerate(_EMAILS)
)

_TEXT_TYPES = {"text", "varchar", "bpchar", "char", "citext"}
_INTEGER_DIGITS = {"int2": 4, "int4": 9, "int8": 18}
_INTEGER_TYPES = set(_INTEGER_DIGITS)
_TYPE_SAMPLES = {
    "numeric": ("2500.75", "18400.00", "912.40"),
    "float4": ("2500.75", "18400.5", "912.4"),
    "float8": ("2500.75", "18400.5", "912.4"),
    "bool": ("true", "false", "true"),
    "date": ("1990-04-12", "1985-11-03", "1998-07-21"),
    "timestamp": ("2026-01-15 10:30:00", "2026-02-02 16:05:00", "2026-03-20 09:45:00"),
    "timestamptz": (
        "2026-01-15 10:30:00+05:30",
        "2026-02-02 16:05:00+05:30",
        "2026-03-20 09:45:00+05:30",
    ),
    "uuid": (
        "3f2b6c1e-8a4d-4c9e-9b1a-5d7e2f0a1c34",
        "9a7d5e3c-1b2f-4a6c-8e0d-2c4b6a8e0f12",
        "c1e3a5b7-9d0f-4b2a-a4c6-e8f0b2d4c6a8",
    ),
    "json": _JSON,
    "jsonb": _JSON,
}
# Column-name hints, checked in order. Each maps name tokens to fabricated values.
_NAME_HINTS = (
    ({"email", "mail"}, _EMAILS),
    ({"phone", "mobile", "tel", "telephone"}, _PHONES),
    ({"aadhaar", "aadhar", "uid"}, _AADHAARS),
    ({"pan"}, _PANS),
    ({"card"}, _CARDS),
    ({"account", "acct", "iban"}, _ACCOUNTS),
    ({"name"}, _NAMES),
    ({"address", "street", "city"}, _ADDRESSES),
    ({"note", "notes", "body", "comment", "message", "description"}, _NOTES),
)
_ACTION_SAMPLES = {"MASK_EMAIL": _EMAILS, "MASK_PHONE": _PHONES}


def _tokens(name: str) -> set[str]:
    separated = re.sub(r"([a-z])([A-Z])", r"\1 \2", name[:128])
    return set(re.findall(r"[a-z]+", separated.lower()))


def sample_values(column: dict, action: str) -> tuple[str | None, ...]:
    """Fabricate plausible inputs for one column from its type, name, and action.

    These are invented examples. They are never derived from the source database.
    """
    udt = column.get("udt_name", "")
    tokens = _tokens(column.get("name", ""))
    hinted = _ACTION_SAMPLES.get(action)
    if hinted is None:
        hinted = next((values for words, values in _NAME_HINTS if tokens & words), None)
    if hinted is None and action == "MASK_ID":
        hinted = _ACCOUNTS
    if udt in _TEXT_TYPES:
        return hinted or ("Sample text 1", "Sample text 2", "Sample text 3")
    if udt in _INTEGER_TYPES:
        # Keep only the digits, and only when they fit the integer type.
        digits = tuple(re.sub(r"[^0-9]", "", value) for value in hinted or ())
        fits = digits and all(0 < len(value) <= _INTEGER_DIGITS[udt] for value in digits)
        return digits if fits else ("1001", "1002", "1003")
    return _TYPE_SAMPLES.get(udt, (None,) * SAMPLE_ROWS)


def _cell(value) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= MAX_CELL_CHARS else text[: MAX_CELL_CHARS - 1] + "…"


def _policy_context(db: Session, policy_id: UUID):
    policy = db.get(MaskingPolicy, policy_id)
    if policy is None:
        raise PolicyFailure("POLICY_NOT_FOUND")
    connection = db.get(DatabaseConnection, policy.connection_id)
    if connection is None or not connection.is_active:
        raise PolicyFailure("CONNECTION_INACTIVE")
    return policy, connection, build_plan(db, policy)


def _sample_columns(decisions: list[ColumnDecision]) -> list[SampleColumn]:
    return [SampleColumn(name=c.name, data_type=c.data_type, action=c.action) for c in decisions]


def illustrative_samples(db: Session, policy_id: UUID) -> PolicySamples:
    """Run the compiled expressions over fabricated values on the target server.

    The query reads no table. It runs as the view owner only so that column
    types defined in the source schema (an enum, a domain) resolve as they will
    for the deployed view. Pseudonym columns show an unkeyed digest, never a
    token made with the target's secret key.
    """
    policy, connection, plan = _policy_context(db, policy_id)
    catalog = policy_catalog_columns(db, policy)
    decisions = plan.columns
    inputs = [sample_values(catalog.get(c.name, {}), c.action) for c in decisions]
    # If a fabricated value cannot be cast to its column type (a number too wide
    # for numeric(4,2), say), fall back to examples for text columns only.
    text_only = [
        values if catalog.get(c.name, {}).get("udt_name") in _TEXT_TYPES else (None,) * SAMPLE_ROWS
        for c, values in zip(decisions, inputs, strict=True)
    ]
    response = PolicySamples(
        policy_id=policy.id, status="UNAVAILABLE", columns=_sample_columns(decisions)
    )
    rows = None
    try:
        query = compile_sample_query(decisions, SAMPLE_ROWS)
        with deployer_session(connection) as target, target.transaction():
            target.execute("SET TRANSACTION READ ONLY")
            target.execute(f"SET LOCAL statement_timeout = {_PREVIEW_TIMEOUT_MS}")
            target.execute(f"SET LOCAL ROLE {quote_ident(VIEW_OWNER_ROLE)}")
            for attempt in (inputs, text_only):
                params = [values[row] for row in range(SAMPLE_ROWS) for values in attempt]
                try:
                    # A savepoint, so a failed cast leaves the session usable.
                    with target.transaction():
                        rows = target.execute(query, params, prepare=False).fetchall()
                    break
                except psycopg.DataError:
                    continue
    except (CompileError, DiscoveryError, psycopg.Error):
        # The preview is a convenience: a missing deployer or an unreachable
        # target leaves it unavailable and the compiled plan still works.
        return response
    if rows is None:
        return response
    width = len(decisions)
    response.status = "OK"
    for row in rows:
        cells = list(row.values())
        response.before.append([_cell(value) for value in cells[:width]])
        response.after.append([_cell(value) for value in cells[width:]])
    return response


def _latest_completed_policy(db: Session, policy: MaskingPolicy) -> UUID | None:
    """The policy whose deployment most recently replaced this table's view.

    A view belongs to a table in a target database, not to a connection record,
    so deployments made through any connection to the same database count.
    """
    connection = db.get(DatabaseConnection, policy.connection_id)
    return db.scalar(
        select(PolicyDeployment.policy_id)
        .join(MaskingPolicy, MaskingPolicy.id == PolicyDeployment.policy_id)
        .join(DatabaseConnection, DatabaseConnection.id == MaskingPolicy.connection_id)
        .where(
            DatabaseConnection.host == connection.host,
            DatabaseConnection.port == connection.port,
            DatabaseConnection.database_name == connection.database_name,
            MaskingPolicy.schema_name == policy.schema_name,
            MaskingPolicy.table_name == policy.table_name,
            PolicyDeployment.status == "COMPLETED",
        )
        .order_by(PolicyDeployment.finished_at.desc(), PolicyDeployment.id.desc())
        .limit(1)
    )


def protected_output(db: Session, user: User, policy_id: UUID) -> ProtectedOutput:
    """Return what the reader role sees through the deployed view, plus access facts."""
    if user.role != "ADMIN":
        raise PolicyFailure("INSUFFICIENT_PERMISSIONS")
    policy, connection, plan = _policy_context(db, policy_id)
    if policy.status != "DEPLOYED" or _latest_completed_policy(db, policy) != policy.id:
        raise PolicyFailure("POLICY_NOT_DEPLOYED")
    view = f"{quote_ident(plan.view_schema)}.{quote_ident(plan.view_name)}"
    select_list = ", ".join(f"{quote_ident(c.name)}::text" for c in plan.columns)
    try:
        with deployer_session(connection) as target, target.transaction():
            target.execute("SET TRANSACTION READ ONLY")
            target.execute(f"SET LOCAL statement_timeout = {_PREVIEW_TIMEOUT_MS}")
            target.execute(f"SET LOCAL ROLE {quote_ident(VIEW_OWNER_ROLE)}")
            view_access = read_access(target, VIEW_READER_ROLE, plan.view_schema, plan.view_name)
            source_access = read_access(
                target, VIEW_READER_ROLE, plan.source_schema, plan.source_table
            )
            if view_access is None or source_access is None:
                raise PolicyFailure("POLICY_NOT_DEPLOYED")
            rows = target.execute(
                f"SELECT {select_list} FROM {view} LIMIT {OUTPUT_ROW_LIMIT}"
            ).fetchall()
    except DiscoveryError:
        raise PolicyFailure("TARGET_UNAVAILABLE") from None
    record_event(
        db,
        actor_id=user.id,
        event_type="PROTECTED_OUTPUT_VIEWED",
        subject_type="masking_policy",
        subject_id=policy.id,
    )
    db.commit()
    return ProtectedOutput(
        policy_id=policy.id,
        view_schema=plan.view_schema,
        view_name=plan.view_name,
        source_schema=plan.source_schema,
        source_table=plan.source_table,
        columns=_sample_columns(plan.columns),
        rows=[[_cell(value) for value in row.values()] for row in rows],
        row_limit=OUTPUT_ROW_LIMIT,
        access=AccessCheck(
            reader_role=VIEW_READER_ROLE,
            reader_can_read_view=view_access,
            reader_can_read_source=source_access,
        ),
    )

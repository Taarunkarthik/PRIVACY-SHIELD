"""Bounded PostgreSQL catalog discovery. No source-row queries are executed."""

import copy
import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from cryptography.fernet import InvalidToken
from psycopg.rows import dict_row

from app.core.config import get_settings
from app.core.security import decrypt_credential
from app.models import DatabaseConnection
from app.schemas.connections import Catalog, normalize_host

MAX_TABLES = 500
MAX_COLUMNS = 10000
MAX_CONSTRAINTS = 5000
DEFAULT_SCHEMAS = ["enterprise", "public"]


class DiscoveryError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def validate_target_host(host: str) -> None:
    if normalize_host(host) not in get_settings().target_allowed_hosts:
        raise DiscoveryError(422, "Target host is not enabled by the operator")


@contextmanager
def target_session(record: DatabaseConnection) -> Iterator[psycopg.Connection]:
    validate_target_host(record.host)
    try:
        # Keyword arguments are escaped by psycopg; do not interpolate a DSN or SQL string.
        with (
            psycopg.connect(
                host=record.host,
                port=record.port,
                dbname=record.database_name,
                user=record.scanner_username,
                password=decrypt_credential(record.scanner_password_ciphertext),
                sslmode=record.ssl_mode,
                connect_timeout=5,
                autocommit=True,
                application_name="privacyshield-catalog",
                row_factory=dict_row,
                options=(
                    "-c statement_timeout=10000 -c default_transaction_read_only=on "
                    "-c search_path=pg_catalog"
                ),
            ) as connection,
            connection.transaction(),
        ):
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            yield connection
    except InvalidToken:
        raise DiscoveryError(503, "Stored credentials could not be decrypted") from None
    except psycopg.Error:
        raise DiscoveryError(502, "Target database connection or metadata query failed") from None


def catalog_fingerprint(catalog: dict) -> str:
    semantic = copy.deepcopy(catalog)
    semantic["schemas"] = sorted(semantic["schemas"])
    semantic["tables"] = sorted(semantic["tables"], key=lambda t: (t["schema"], t["name"]))
    for table in semantic["tables"]:
        table.pop("oid", None)
        table.pop("row_estimate", None)
        table["columns"] = sorted(table["columns"], key=lambda column: column["ordinal"])
        table["foreign_keys"] = sorted(table["foreign_keys"], key=lambda key: key["name"])
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def discover_catalog(record: DatabaseConnection, requested_schemas: list[str] | None) -> dict:
    with target_session(record) as connection:
        role = connection.execute("""
            SELECT bool_or(rolsuper OR rolbypassrls OR rolcreaterole
                           OR rolcreatedb OR rolreplication)
                   AS unsafe
            FROM pg_catalog.pg_roles
            WHERE rolname = current_user OR pg_catalog.pg_has_role(current_user, oid, 'MEMBER')
        """).fetchone()
        if role["unsafe"]:
            raise DiscoveryError(422, "Scanner must use a role without administrative privileges")

        schemas = [
            row["nspname"]
            for row in connection.execute(
                """
            SELECT nspname FROM pg_catalog.pg_namespace
            WHERE nspname = ANY(%s) AND pg_catalog.has_schema_privilege(oid, 'USAGE')
            ORDER BY nspname
        """,
                (requested_schemas if requested_schemas is not None else DEFAULT_SCHEMAS,),
            )
        ]
        if requested_schemas is not None and set(schemas) != set(requested_schemas):
            raise DiscoveryError(422, "Requested source schemas are unavailable to the scanner")
        if not schemas:
            raise DiscoveryError(422, "No allowed source schemas are accessible to the scanner")

        tables = connection.execute(
            """
            WITH accessible_roles AS (
                SELECT oid FROM pg_catalog.pg_roles
                WHERE rolname = current_user OR pg_catalog.pg_has_role(current_user, oid, 'MEMBER')
            )
            SELECT c.oid, n.nspname AS schema, c.relname AS name,
                   c.reltuples::bigint AS row_estimate,
                   c.relrowsecurity AS rls_enabled,
                   pg_catalog.has_table_privilege(c.oid, 'SELECT') AS can_select,
                   EXISTS (
                       SELECT 1 FROM accessible_roles r
                       WHERE c.relowner = r.oid
                          OR pg_catalog.has_table_privilege(r.oid, c.oid,
                              'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                          OR pg_catalog.has_any_column_privilege(r.oid, c.oid,
                              'INSERT,UPDATE,REFERENCES')
                   ) AS unsafe
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY(%s) AND c.relkind IN ('r','p')
            ORDER BY n.nspname, c.relname LIMIT %s
        """,
            (schemas, MAX_TABLES + 1),
        ).fetchall()
        if len(tables) > MAX_TABLES:
            raise DiscoveryError(422, "Source scope exceeds the table limit; select fewer schemas")
        if any(table["unsafe"] for table in tables):
            raise DiscoveryError(
                422, "Scanner must not own or modify tables in the selected schemas"
            )
        if any(not table["can_select"] for table in tables):
            raise DiscoveryError(
                422, "Scanner requires SELECT on every table in the selected schemas"
            )
        by_oid = {}
        for table in tables:
            table.pop("can_select")
            table.pop("unsafe")
            table.update(columns=[], primary_key=[], foreign_keys=[])
            by_oid[table["oid"]] = table
        if not by_oid:
            return {"schemas": schemas, "tables": []}
        oids = list(by_oid)
        columns = connection.execute(
            """
            SELECT a.attrelid AS table_oid, a.attname AS name,
                   pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
                   t.typname AS udt_name, NOT (a.attnotnull OR t.typnotnull) AS nullable,
                   a.attnum AS ordinal, (t.typname = 'jsonb') AS is_jsonb
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
            WHERE a.attrelid = ANY(%s::oid[]) AND a.attnum > 0 AND NOT a.attisdropped
            ORDER BY a.attrelid, a.attnum LIMIT %s
        """,
            (oids, MAX_COLUMNS + 1),
        ).fetchall()
        if len(columns) > MAX_COLUMNS:
            raise DiscoveryError(422, "Source scope exceeds the column limit; select fewer schemas")
        for column in columns:
            table_oid = column.pop("table_oid")
            column["is_primary_key"] = False
            by_oid[table_oid]["columns"].append(column)
        constraints = connection.execute(
            """
            SELECT con.conrelid AS table_oid, con.contype, con.conname AS name,
                   ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY k(num, ord)
                         JOIN pg_catalog.pg_attribute a
                           ON a.attrelid=con.conrelid AND a.attnum=k.num
                         ORDER BY k.ord) AS columns,
                   rn.nspname AS referenced_schema, rc.relname AS referenced_table,
                   ARRAY(SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY k(num, ord)
                         JOIN pg_catalog.pg_attribute a
                           ON a.attrelid=con.confrelid AND a.attnum=k.num
                         ORDER BY k.ord) AS referenced_columns
            FROM pg_catalog.pg_constraint con
            LEFT JOIN pg_catalog.pg_class rc ON rc.oid = con.confrelid
            LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
            WHERE con.conrelid = ANY(%s::oid[]) AND con.contype IN ('p','f')
            ORDER BY con.conrelid, con.conname LIMIT %s
        """,
            (oids, MAX_CONSTRAINTS + 1),
        ).fetchall()
        if len(constraints) > MAX_CONSTRAINTS:
            raise DiscoveryError(
                422, "Source scope exceeds the constraint limit; select fewer schemas"
            )
        for constraint in constraints:
            table = by_oid[constraint.pop("table_oid")]
            if constraint.pop("contype") == "p":
                table["primary_key"] = constraint["columns"]
                for column in table["columns"]:
                    column["is_primary_key"] = column["name"] in table["primary_key"]
            else:
                table["foreign_keys"].append(constraint)
        catalog = {"schemas": schemas, "tables": tables}
        Catalog.model_validate(catalog)
        return catalog

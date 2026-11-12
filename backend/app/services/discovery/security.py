"""Read-only checks for source-table exposure and basic integrity risks."""

from app.models import DatabaseConnection
from app.services.discovery.catalog import target_session

MAX_FINDINGS = 50


def assess_catalog_security(record: DatabaseConnection, catalog: dict) -> list[dict]:
    """Report privilege and key risks using PostgreSQL metadata only.

    No source rows or column values are read. Role names and SQL identifiers are
    fixed constants or supplied as bound parameters.
    """
    tables = catalog.get("tables", [])
    if not tables:
        return []
    table_oids = [table["oid"] for table in tables]
    schema_names = sorted({table["schema"] for table in tables})
    findings: list[dict] = []
    with target_session(record) as connection:
        reader_exists = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='ps_reader')"
            " AS reader_exists"
        ).fetchone()["reader_exists"]
        exposed = connection.execute(
            """
            SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name,
                   EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(
                       COALESCE(c.relacl, pg_catalog.acldefault('r',c.relowner))) acl
                     WHERE acl.grantee=0 AND acl.privilege_type='SELECT'
                   ) AND EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(
                       COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
                     WHERE acl.grantee=0 AND acl.privilege_type='USAGE'
                   ) AS public_select,
                   CASE WHEN %s THEN
                     pg_catalog.has_table_privilege('ps_reader', c.oid, 'SELECT')
                     AND pg_catalog.has_schema_privilege('ps_reader', n.oid, 'USAGE')
                     ELSE false END AS reader_select
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE c.oid=ANY(%s::oid[])
            ORDER BY n.nspname,c.relname
            """,
            (reader_exists, table_oids),
        ).fetchall()
        public_create = connection.execute(
            """
            SELECT n.nspname
            FROM pg_catalog.pg_namespace n
            CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
            WHERE n.nspname=ANY(%s)
              AND acl.grantee=0 AND acl.privilege_type='CREATE'
            ORDER BY n.nspname
            """,
            (schema_names,),
        ).fetchall()

    for row in exposed:
        if row["public_select"]:
            findings.append(
                {
                    "code": "PUBLIC_TABLE_READ",
                    "severity": "CRITICAL",
                    "title": "PUBLIC can read source rows",
                    "description": "The PostgreSQL PUBLIC role has SELECT on this source table.",
                    "schema_name": row["schema_name"],
                    "table_name": row["table_name"],
                }
            )
        if row["reader_select"]:
            findings.append(
                {
                    "code": "READER_SOURCE_ACCESS",
                    "severity": "CRITICAL",
                    "title": "Restricted reader can read a source table",
                    "description": (
                        "The ps_reader role can bypass the approved masked view for this table."
                    ),
                    "schema_name": row["schema_name"],
                    "table_name": row["table_name"],
                }
            )
    for row in public_create:
        findings.append(
            {
                "code": "PUBLIC_SCHEMA_CREATE",
                "severity": "HIGH",
                "title": "PUBLIC can create objects in a source schema",
                "description": (
                    "The PostgreSQL PUBLIC role can create objects in this discovered schema."
                ),
                "schema_name": row["nspname"],
                "table_name": None,
            }
        )
    for table in tables:
        if not table.get("primary_key"):
            findings.append(
                {
                    "code": "TABLE_WITHOUT_PRIMARY_KEY",
                    "severity": "MEDIUM",
                    "title": "Source table has no primary key",
                    "description": "Rows cannot be uniquely identified by a declared primary key.",
                    "schema_name": table["schema"],
                    "table_name": table["name"],
                }
            )
    return findings[:MAX_FINDINGS]

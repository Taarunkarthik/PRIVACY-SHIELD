from contextlib import contextmanager

from app.services.discovery import security


class Result:
    def __init__(self, *, one=None, rows=None):
        self.one = one
        self.rows = rows or []

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.rows


class CatalogConnection:
    def execute(self, statement, _params=None):
        if "pg_roles" in statement:
            return Result(one={"reader_exists": True})
        if "pg_class" in statement:
            return Result(
                rows=[
                    {
                        "public_select": True,
                        "reader_select": True,
                        "schema_name": "exposed",
                        "table_name": "customers",
                    }
                ]
            )
        return Result(rows=[{"nspname": "exposed"}])


def test_security_report_translates_catalog_risks_without_source_values(monkeypatch):
    connection = CatalogConnection()

    @contextmanager
    def target_session(_record):
        yield connection

    monkeypatch.setattr(security, "target_session", target_session)
    findings = security.assess_catalog_security(
        object(),
        {
            "tables": [
                {
                    "oid": 42,
                    "schema": "exposed",
                    "name": "customers",
                    "primary_key": [],
                }
            ]
        },
    )

    assert {item["code"] for item in findings} == {
        "PUBLIC_TABLE_READ",
        "READER_SOURCE_ACCESS",
        "PUBLIC_SCHEMA_CREATE",
        "TABLE_WITHOUT_PRIMARY_KEY",
    }
    assert all(
        set(item)
        == {"code", "severity", "title", "description", "schema_name", "table_name"}
        for item in findings
    )


def test_empty_catalog_needs_no_target_privilege_query(monkeypatch):
    def should_not_open(_record):
        raise AssertionError("empty catalogs require no connection")

    monkeypatch.setattr(security, "target_session", should_not_open)
    assert security.assess_catalog_security(object(), {"tables": []}) == []

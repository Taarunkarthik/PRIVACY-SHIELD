"""Row selection against real PostgreSQL: the sample must span the whole table."""

import os
import uuid

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import dict_row

from app.services.scanning import sampling
from app.services.scanning.sampling import sample_seed, sample_table

pytestmark = pytest.mark.integration

ROWS = 2000
SAMPLE = 100


def _connect(user, password):
    return psycopg.connect(
        host=os.environ.get("TEST_TARGET_HOST", "target-db"),
        port=int(os.environ.get("TEST_TARGET_PORT", "5432")),
        dbname="enterprise_demo",
        user=user,
        password=password,
        autocommit=True,
        row_factory=dict_row,
        options="-c search_path=pg_catalog",
    )


@pytest.fixture
def late_pii_table():
    """A table whose newer half holds emails and whose older half holds none."""
    superuser = os.environ.get("TEST_TARGET_SUPERUSER_PASSWORD")
    scanner = os.environ.get("TEST_TARGET_SCANNER_PASSWORD")
    assert superuser and scanner, "Real target credentials are required"
    schema = "ps_sample_" + uuid.uuid4().hex[:16]
    table = sql.Identifier(schema, "events")
    with _connect("postgres", superuser) as admin:
        try:
            admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            admin.execute(
                sql.SQL("CREATE TABLE {} (id int PRIMARY KEY, contact text, filler text)").format(
                    table
                )
            )
            admin.execute(
                sql.SQL(
                    "INSERT INTO {} SELECT n, CASE WHEN n > %s THEN 'user' || n || '@example.com' "
                    "ELSE 'none' END, repeat('x', 200) FROM generate_series(1, %s) AS n"
                ).format(table),
                (ROWS // 2, ROWS),
            )
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO ps_scanner").format(sql.Identifier(schema))
            )
            admin.execute(sql.SQL("GRANT SELECT ON {} TO ps_scanner").format(table))
            oid = admin.execute(
                "SELECT %s::regclass::oid AS oid", (f'{schema}."events"',)
            ).fetchone()["oid"]
            yield {
                "schema": schema,
                "name": "events",
                "oid": oid,
                "primary_key": ["id"],
                "columns": [
                    {"name": "id", "udt_name": "int4", "is_jsonb": False},
                    {"name": "contact", "udt_name": "text", "is_jsonb": False},
                    {"name": "filler", "udt_name": "text", "is_jsonb": False},
                ],
            }
        finally:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def _email_detector(value, context, **_):
    return {"EMAIL_ADDRESS": 1.0} if "@" in value else {}


def _contact_result(table, seed):
    with (
        _connect("ps_scanner", os.environ["TEST_TARGET_SCANNER_PASSWORD"]) as scanner,
        scanner.transaction(),
    ):
        scanner.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        results = list(sample_table(scanner, table, SAMPLE, detector=_email_detector, seed=seed))
    # Every column of one table describes the same sampled rows.
    assert len({result["sampled_rows"] for result in results}) == 1
    return next(result for result in results if result["column_name"] == "contact")


def test_sample_reaches_rows_beyond_the_start_of_the_table(late_pii_table):
    # Reading the first 100 rows by primary key would find no email at all,
    # because every email is in rows 1001-2000. A random sample finds about half.
    seed = sample_seed("scan-a")
    first = _contact_result(late_pii_table, seed)
    assert first["sampled_rows"] == SAMPLE
    assert 20 <= first["matching_rows"] <= 80
    assert first["category_counts"] == {"EMAIL_ADDRESS": first["matching_rows"]}

    # The same seed reads the same rows; that keeps a retried scan consistent.
    assert _contact_result(late_pii_table, seed)["matching_rows"] == first["matching_rows"]


def test_large_tables_are_page_sampled_before_rows_are_chosen(late_pii_table, monkeypatch):
    # Treat the fixture as a large table so the TABLESAMPLE path runs for real.
    monkeypatch.setattr(sampling, "LARGE_TABLE_BYTES", 0)
    monkeypatch.setattr(sampling, "MIN_CANDIDATE_PAGES", 1)
    size = None
    with _connect("ps_scanner", os.environ["TEST_TARGET_SCANNER_PASSWORD"]) as scanner:
        size = sampling.table_bytes(scanner, late_pii_table)
    percent = sampling.page_sample_percent(size, SAMPLE)
    assert size > 0 and percent is None  # 100 pages requested from a smaller table

    # Pretend pages are small so only a few percent of the real pages are read.
    monkeypatch.setattr(sampling, "PAGE_BYTES", 1024)
    percent = sampling.page_sample_percent(size, SAMPLE)
    assert percent is not None and 0 < percent < 100
    result = _contact_result(late_pii_table, sample_seed("scan-b"))
    # A page sample reads a subset of the table, never more than the limit, and
    # the pages it picks are spread across both halves of the table.
    assert 0 < result["sampled_rows"] <= SAMPLE
    assert 0 < result["matching_rows"] < result["sampled_rows"]


def test_a_thin_page_sample_falls_back_to_considering_every_row(late_pii_table, monkeypatch):
    # One pre-selected page cannot supply 100 rows, as with a bloated table or
    # one where row-level security hides most rows. The sample must still be full.
    monkeypatch.setattr(sampling, "LARGE_TABLE_BYTES", 0)
    monkeypatch.setattr(sampling, "MIN_CANDIDATE_PAGES", 1)
    monkeypatch.setattr(sampling, "PAGE_BYTES", 64)
    with _connect("ps_scanner", os.environ["TEST_TARGET_SCANNER_PASSWORD"]) as scanner:
        size = sampling.table_bytes(scanner, late_pii_table)
        percent = sampling.page_sample_percent(size, SAMPLE)
        tablesample, _ = sampling.row_selection(size, SAMPLE, 1)
        assert percent is not None and percent < 2
        assert sampling.page_sample_is_thin(scanner, late_pii_table, tablesample, SAMPLE)
    result = _contact_result(late_pii_table, sample_seed("scan-c"))
    assert result["sampled_rows"] == SAMPLE
    assert 20 <= result["matching_rows"] <= 80

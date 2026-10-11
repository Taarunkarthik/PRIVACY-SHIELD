import json
from types import SimpleNamespace

from app.services.scanning.sampling import (
    LARGE_TABLE_BYTES,
    MAX_CELL_CHARS,
    MAX_JSON_DEPTH,
    MAX_JSON_LEAVES,
    MIN_CANDIDATE_PAGES,
    PAGE_BYTES,
    Findings,
    json_leaves,
    page_sample_percent,
    row_selection,
    safe_key,
    sample_seed,
    sample_table,
)


def test_json_keys_containing_pii_are_hashed_before_paths_are_retained():
    private_key = "customer@example.com"
    leaves, truncated = json_leaves({private_key: {"contact": {"email": "nested@example.com"}}})
    assert not truncated
    assert all(private_key not in path for path, _, _ in leaves)
    assert any(value == private_key for _, value, _ in leaves)  # Key is still checked for PII.
    assert safe_key(private_key).startswith("key_")
    assert safe_key("email") == "email"
    assert safe_key(private_key) == safe_key(private_key)


def test_json_depth_and_leaf_bounds_report_partial_coverage():
    nested = "sample"
    for _ in range(MAX_JSON_DEPTH + 2):
        nested = {"contact": nested}
    assert json_leaves(nested)[1] is True
    leaves, bounded = json_leaves([str(number) for number in range(MAX_JSON_LEAVES + 10)])
    assert bounded and len(leaves) == MAX_JSON_LEAVES
    assert all(path == "$[*]" for path, _, _ in leaves)


def test_json_scalar_truncation_is_reported_even_when_cell_fits_byte_limit():
    value = {"message": "x" * (MAX_CELL_CHARS + 1)}
    assert len(json.dumps(value).encode()) < 16384
    leaves, bounded = json_leaves(value)
    assert bounded is True
    assert len(leaves[0][1]) == MAX_CELL_CHARS


def test_findings_count_matching_rows_and_categories_independently():
    aggregate = Findings()
    aggregate.add_row({"EMAIL_ADDRESS": 0.9, "PHONE_NUMBER": 0.7})
    aggregate.add_row({"EMAIL_ADDRESS": 0.8})
    aggregate.add_row({})
    assert aggregate.matching_rows == 2
    assert aggregate.category_counts == {"EMAIL_ADDRESS": 2, "PHONE_NUMBER": 1}
    assert aggregate.confidence == 0.9


def test_small_tables_consider_every_row_and_large_ones_a_bounded_share_of_pages():
    assert page_sample_percent(0, 1000) is None
    assert page_sample_percent(LARGE_TABLE_BYTES, 1000) is None
    # 1 GiB is 131,072 pages; 1,000 of them is about 0.76%.
    assert page_sample_percent(1024**3, 1000) == round(100 * 1000 / (1024**3 // PAGE_BYTES), 6)
    # A tiny sample still reads enough pages to choose from.
    assert page_sample_percent(1024**3, 1) == round(
        100 * MIN_CANDIDATE_PAGES / (1024**3 // PAGE_BYTES), 6
    )
    # Asking for more pages than exist falls back to considering every row.
    assert page_sample_percent(LARGE_TABLE_BYTES + PAGE_BYTES, 10000) is None


def test_row_selection_orders_by_a_seeded_hash_not_by_key():
    seed = sample_seed("job-1")
    assert seed == sample_seed("job-1") != sample_seed("job-2")
    assert 0 <= seed < 2**31
    tablesample, ordering = row_selection(1024, 100, seed)
    assert tablesample.as_string(None) == ""
    assert ordering.as_string(None) == (
        "pg_catalog.hashtextextended("
        f"tableoid::pg_catalog.text || ctid::pg_catalog.text, {seed}), tableoid, ctid"
    )
    tablesample, _ = row_selection(1024**3, 1000, seed)
    assert tablesample.as_string(None) == f" TABLESAMPLE SYSTEM (0.762939) REPEATABLE ({seed})"


class _SampledRows:
    """Stands in for a server-side cursor over rows the query already chose."""

    def __init__(self, rows):
        self.rows = list(rows)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, parameters):
        self.limit = parameters[0]

    def fetchmany(self, size):
        batch, self.rows = self.rows[:size], self.rows[size:]
        return batch


class _Target:
    def __init__(self, rows):
        self.rows = rows

    def execute(self, query, parameters=None):
        return SimpleNamespace(fetchone=lambda: {"bytes": 0})

    def cursor(self, name, row_factory):
        return _SampledRows(self.rows)


def test_shapes_are_stored_for_character_columns_only_and_hold_no_value():
    emails = [f"person{n}.surname@example.com" for n in range(1, 10)]
    table = {
        "schema": "enterprise",
        "name": "people",
        "oid": 1,
        "columns": [
            {"name": "contact", "is_jsonb": False, "udt_name": "text"},
            {"name": "joined", "is_jsonb": False, "udt_name": "date"},
            {"name": "profile", "is_jsonb": True, "udt_name": "jsonb"},
            {"name": "photo", "is_jsonb": False, "udt_name": "bytea"},
            {"name": "nickname", "is_jsonb": False, "udt_name": "text"},
        ],
    }
    # Three cells per column: value, truncated, skipped.
    rows = [
        (email, False, False)
        + ("2026-10-11", False, False)
        + (json.dumps({"email": email}), False, False)
        + (None, False, True)
        + (None if index else "--", False, False)
        for index, email in enumerate(emails)
    ]
    seen = []

    def detector(value, context):
        seen.append(value)
        return {}

    results = list(sample_table(_Target(rows), table, 100, detector=detector))
    evidence = {
        (item["column_name"], item["json_path"]): item["sanitized_evidence"] for item in results
    }
    assert evidence[("contact", "")]["shapes"] == [{"shape": "a+9.a+@a+.a+", "rows": 9}]
    # A date (its type already says its form), a JSON document, a path inside it
    # and an unread type carry no shapes key.
    for key in [("joined", ""), ("profile", ""), ("profile", "$.email"), ("photo", "")]:
        assert "shapes" not in evidence[key]
    # Punctuation-only and NULL values leave the list empty, not absent.
    assert evidence[("nickname", "")]["shapes"] == []
    assert evidence[("nickname", "")]["values_read"] == 1
    coverage_keys = {
        "mode",
        "sample_limit",
        "max_cell_chars",
        "max_cell_bytes",
        "values_truncated",
        "values_skipped",
        "json_truncated",
        "path_limit_reached",
        "unsupported_type",
    }
    for item in evidence.values():
        # The adapter's strict coverage model rejects any additional key.
        assert set(item["coverage"]) == coverage_keys
        assert set(item) <= {"labels", "coverage", "values_read", "shapes"}
    assert emails[0] in seen  # The detector still receives the value itself.
    stored = json.dumps(results)
    for fragment in ["person", "surname", "example", "2026", "--"]:
        assert fragment not in stored

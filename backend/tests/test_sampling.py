import json

from app.services.scanning.sampling import (
    MAX_CELL_CHARS,
    MAX_JSON_DEPTH,
    MAX_JSON_LEAVES,
    Findings,
    json_leaves,
    safe_key,
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

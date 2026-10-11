"""The rule that decides which columns are worth the model's time."""

import uuid
from types import SimpleNamespace

import pytest

from app.services.classification.triage import detector_verdict, triage_results

CLEAN = {
    "mode": "bounded_sample",
    "sample_limit": 100,
    "max_cell_chars": 4096,
    "max_cell_bytes": 16384,
    "values_truncated": 0,
    "values_skipped": 0,
    "json_truncated": 0,
    "path_limit_reached": 0,
    "unsupported_type": False,
}


def verdict(sampled=100, matching=100, confidence=1.0, coverage=CLEAN, **evidence):
    return detector_verdict(
        sampled_rows=sampled,
        matching_rows=matching,
        confidence=confidence,
        evidence={"coverage": coverage, "values_read": sampled} | evidence,
    )


def test_a_fully_read_column_matching_on_most_rows_is_decided():
    assert verdict() == "DECIDED"
    assert verdict(matching=80, confidence=0.6) == "DECIDED"
    assert verdict(sampled=3, matching=3, confidence=0.92) == "DECIDED"
    # Named-entity matches score 0.65 and can settle a column on their own.
    assert verdict(matching=95, confidence=0.65) == "DECIDED"


@pytest.mark.parametrize(
    "arguments",
    [
        {"matching": 0, "confidence": 0.0},  # Nothing found: the model's main use.
        {"matching": 79},  # Just under 80% of sampled rows.
        {"sampled": 3, "matching": 2, "confidence": 0.92},
        {"confidence": 0.59},
        {"confidence": 0.45},  # A column-name hint alone.
        {"coverage": CLEAN | {"values_truncated": 1}},
        {"coverage": CLEAN | {"values_skipped": 1}},
        {"coverage": CLEAN | {"json_truncated": 1}},
        {"coverage": CLEAN | {"path_limit_reached": 1}},
        {"values_read": 40, "matching": 40},  # Sparse: 40% of sampled rows.
    ],
)
def test_anything_else_that_was_scanned_is_uncertain(arguments):
    assert verdict(**arguments) == "UNCERTAIN"


@pytest.mark.parametrize(
    "arguments",
    [
        {"coverage": CLEAN | {"unsupported_type": True}, "matching": 0, "confidence": 0.0},
        {"sampled": 0, "matching": 0, "confidence": 0.0},
        {"values_read": 0, "matching": 0, "confidence": 0.0},
        {"coverage": {}},
        {"coverage": None},
        {"coverage": "corrupt"},
        {"values_read": "many"},
    ],
)
def test_unread_columns_are_neither_decided_nor_uncertain(arguments):
    assert verdict(**arguments) == "NOT_CLASSIFIABLE"


def test_scans_stored_before_values_read_and_shapes_are_judged_on_coverage():
    old = {"labels": ["EMAIL_ADDRESS"], "coverage": CLEAN}
    assert (
        detector_verdict(sampled_rows=3, matching_rows=3, confidence=0.92, evidence=old)
        == "DECIDED"
    )
    assert (
        detector_verdict(sampled_rows=3, matching_rows=0, confidence=0.0, evidence=old)
        == "UNCERTAIN"
    )
    for missing in (None, {}, []):
        assert (
            detector_verdict(sampled_rows=3, matching_rows=3, confidence=1.0, evidence=missing)
            == "NOT_CLASSIFIABLE"
        )


def test_triage_counts_every_row_once_and_keeps_uncertain_ids_in_order():
    def row(matching, confidence, coverage=CLEAN):
        return SimpleNamespace(
            id=uuid.uuid4(),
            sampled_rows=10,
            matching_rows=matching,
            confidence=confidence,
            sanitized_evidence={"coverage": coverage, "values_read": 10},
        )

    rows = [
        row(10, 1.0),
        row(0, 0.0),
        row(0, 0.0, CLEAN | {"unsupported_type": True}),
        row(5, 0.85),
        row(10, 0.45),
        row(9, 0.85),
    ]
    triage = triage_results(rows)
    assert (triage.decided, triage.uncertain, triage.not_classifiable) == (2, 3, 1)
    assert triage.uncertain_ids == [rows[1].id, rows[3].id, rows[4].id]
    assert triage_results([]) == (0, 0, 0, [])

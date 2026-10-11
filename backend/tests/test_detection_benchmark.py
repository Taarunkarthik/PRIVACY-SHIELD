"""Accuracy of the real detectors on the labelled synthetic benchmark.

The thresholds sit just under the measured results recorded in
docs/detection-accuracy.md, so a change that makes detection worse fails here.
"""

import pytest

from app.services.scanning.detection import detect_pii
from tests.support.pii_benchmark import NONE, build_columns, evaluate, report


@pytest.fixture(scope="module")
def result():
    return evaluate(build_columns(), detect_pii)


def test_benchmark_is_deterministic_and_balanced():
    columns = build_columns()
    assert [c.values for c in columns] == [c.values for c in build_columns()]
    assert len({c.name for c in columns}) == len(columns)
    labelled = [c for c in columns if c.label != NONE]
    assert len(labelled) >= 20 and len(columns) - len(labelled) >= 15


def test_no_column_with_personal_data_is_missed(result):
    # Missing personal data is the costly error for a privacy tool.
    assert result["sensitive"]["recall"] == 1.0
    assert all(score["recall"] == 1.0 for score in result["per_category"].values())


def test_false_positive_rate_does_not_regress(result):
    assert result["sensitive"]["precision"] >= 0.75
    assert result["exact"] >= 0.80
    for category in ("EMAIL_ADDRESS", "CREDIT_CARD", "IBAN_CODE", "BANK_ACCOUNT"):
        assert result["per_category"][category]["precision"] == 1.0


def test_report_lists_every_disagreement_without_values(result):
    text = report(result)
    wrong = [r for r in result["rows"] if r["predicted"] != r["column"].label]
    assert all(f"`{r['column'].name}`" in text for r in wrong)
    # The report names columns and categories; it never prints a cell value.
    assert "@example" not in text

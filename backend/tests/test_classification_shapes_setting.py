"""AI_SEND_SHAPES decides whether stored value shapes are part of the model request."""

import uuid
from types import SimpleNamespace

import pytest

from app.core.config import get_settings
from app.models import ScanJob, ScanResult, SchemaSnapshot
from app.services.classification.jobs import evidence_for_result

SHAPES = [{"shape": "a+.a+@a+.a+", "rows": 9}]
COVERAGE = {
    "mode": "bounded_sample",
    "sample_limit": 10,
    "max_cell_chars": 4096,
    "max_cell_bytes": 16384,
    "values_truncated": 0,
    "values_skipped": 0,
    "json_truncated": 0,
    "path_limit_reached": 0,
    "unsupported_type": False,
}


@pytest.fixture(autouse=True)
def fresh_settings():
    # Settings are read once per process; each test here changes the environment.
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _Rows:
    def __init__(self, *rows):
        self._rows = {(type_, row.id): row for type_, row in rows}

    def get(self, model, key):
        return self._rows.get((model, key))


def _fixture(json_path=""):
    scan = SimpleNamespace(id=uuid.uuid4(), status="COMPLETED", snapshot_id=uuid.uuid4())
    snapshot = SimpleNamespace(
        id=scan.snapshot_id,
        catalog={
            "tables": [
                {
                    "schema": "enterprise",
                    "name": "people",
                    "foreign_keys": [],
                    "columns": [
                        {
                            "name": "contact",
                            "data_type": "text",
                            "is_primary_key": False,
                            "nullable": True,
                        }
                    ],
                }
            ]
        },
    )
    result = SimpleNamespace(
        id=uuid.uuid4(),
        scan_job_id=scan.id,
        schema_name="enterprise",
        table_name="people",
        column_name="contact",
        json_path=json_path,
        sampled_rows=10,
        matching_rows=0,
        category_counts={},
        confidence=0,
        sanitized_evidence={"coverage": {}, "values_read": 10, "shapes": SHAPES},
    )
    db = _Rows((ScanJob, scan), (SchemaSnapshot, snapshot), (ScanResult, result))
    return db, SimpleNamespace(scan_job_id=scan.id), result.id


def test_shapes_are_sent_by_default(monkeypatch):
    monkeypatch.delenv("AI_SEND_SHAPES", raising=False)
    db, job, result_id = _fixture()
    assert evidence_for_result(db, job, result_id)["shapes"] == SHAPES


@pytest.mark.parametrize("value", ["false", "0"])
def test_switching_shapes_off_sends_the_earlier_request(monkeypatch, value):
    monkeypatch.setenv("AI_SEND_SHAPES", value)
    db, job, result_id = _fixture()
    assert "shapes" not in evidence_for_result(db, job, result_id)


def test_shapes_stored_by_an_earlier_build_are_filtered_not_sent(monkeypatch):
    """Otherwise the adapter rejects the whole column, or the model sees a sign."""
    monkeypatch.setenv("AI_SEND_SHAPES", "true")
    db, job, result_id = _fixture()
    result = db.get(ScanResult, result_id)
    result.sanitized_evidence["shapes"] = [
        {"shape": "+9+ 9+ 9+", "rows": 90},  # A sign at the start: no longer a shape.
        {"shape": "a+.a+@a+.a+", "rows": 9},
        {"shape": "A+9+A", "rows": 1},  # Too few rows to describe the column.
        {"shape": "customer1@example.com", "rows": 50},  # Not a shape at all.
        "not-a-dict",
    ]
    assert evidence_for_result(db, job, result_id)["shapes"] == SHAPES
    result.sanitized_evidence["shapes"] = [{"shape": "-9+.9+", "rows": 40}]
    assert "shapes" not in evidence_for_result(db, job, result_id)
    # The adapter accepts what is left.
    from app.services.classification.adapter import _validate_inputs

    result.sanitized_evidence["shapes"] = [{"shape": "+9+ 9+ 9+", "rows": 9}, *SHAPES]
    evidence = evidence_for_result(db, job, result_id)
    evidence["coverage"] = COVERAGE
    assert _validate_inputs([evidence])[0].shapes is not None


def test_a_json_path_never_carries_shapes(monkeypatch):
    monkeypatch.setenv("AI_SEND_SHAPES", "true")
    db, job, result_id = _fixture(json_path="$.email")
    assert "shapes" not in evidence_for_result(db, job, result_id)

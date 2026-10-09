"""Real PostgreSQL/Redis/separate worker with a controlled HTTP model double.

These tests verify orchestration, not real model quality. Real Ollama is a separate gate.
"""

import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import encrypt_credential, hash_password
from app.main import app
from app.models import (
    ClassificationJob,
    ClassificationJobItem,
    DatabaseConnection,
    PIIClassification,
    ScanJob,
    ScanResult,
    SchemaSnapshot,
    User,
)
from app.services.classification.adapter import ClassificationDecision
from app.services.classification.jobs import (
    enqueue_classification,
    finish_job,
    persist_decision,
    persist_failure,
)
from app.services.scanning.jobs import scan_lock
from app.workers.celery_app import celery_app

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as session:
        yield session


@pytest.fixture
def login(db, monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    clients = []

    def create(role="ADMIN"):
        password = secrets.token_urlsafe(24)
        user = User(
            email=f"ai-{uuid.uuid4().hex}@example.com",
            role=role,
            password_hash=hash_password(password),
        )
        db.add(user)
        db.commit()
        client = TestClient(app, base_url="http://localhost:8080")
        clients.append(client)
        response = client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": password}
        )
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        return client, user

    yield create
    for client in clients:
        client.close()


@pytest.fixture
def fake_model():
    url = os.environ.get("TEST_OLLAMA_BASE_URL")
    assert url, "Controlled HTTP Ollama double required; real model is a separate smoke test"
    with httpx.Client(base_url=url, timeout=10, trust_env=False) as client:
        assert client.get("/health").json()["implementation"] == "controlled-http-test-double"
        assert client.post("/control", json={"mode": "valid"}).status_code == 200
        yield client
        assert client.post("/control", json={"mode": "valid"}).status_code == 200


@pytest.fixture
def evidence_scan(db, login):
    """Seed synthetic aggregate evidence; worker must never connect to this source."""
    client, user = login()
    connection = DatabaseConnection(
        name="classification-" + uuid.uuid4().hex,
        host="unreachable.example.invalid",
        database_name="synthetic_metadata_only",
        scanner_username="no_source_access",
        scanner_password_ciphertext=encrypt_credential("must-never-reach-model"),
        created_by=user.id,
    )
    db.add(connection)
    db.flush()
    names = [("id", "integer", True), ("email", "text", False), ("profile", "jsonb", False)]
    snapshot = SchemaSnapshot(
        connection_id=connection.id,
        fingerprint="a" * 64,
        catalog={
            "schemas": ["enterprise"],
            "tables": [
                {
                    "schema": "enterprise",
                    "name": "people",
                    "primary_key": ["id"],
                    "foreign_keys": [],
                    "columns": [
                        {
                            "name": name,
                            "data_type": dtype,
                            "nullable": not primary,
                            "is_primary_key": primary,
                        }
                        for name, dtype, primary in names
                    ],
                }
            ],
        },
    )
    db.add(snapshot)
    db.flush()
    scan = ScanJob(
        connection_id=connection.id,
        snapshot_id=snapshot.id,
        requested_by=user.id,
        status="COMPLETED",
        sample_limit=3,
        progress=100,
    )
    db.add(scan)
    db.flush()
    coverage = {
        "mode": "bounded_sample",
        "sample_limit": 3,
        "max_cell_chars": 4096,
        "max_cell_bytes": 16384,
        "values_truncated": 0,
        "values_skipped": 0,
        "json_truncated": 0,
        "path_limit_reached": 0,
        "unsupported_type": False,
    }
    rows = []
    for name, path, counts in [
        ("id", "", {}),
        ("email", "", {"EMAIL_ADDRESS": 3}),
        ("profile", "", {"EMAIL_ADDRESS": 2}),
        ("profile", "$.email", {"EMAIL_ADDRESS": 2}),
    ]:
        row = ScanResult(
            scan_job_id=scan.id,
            schema_name="enterprise",
            table_name="people",
            column_name=name,
            json_path=path,
            sampled_rows=3,
            matching_rows=max(counts.values(), default=0),
            confidence=0.92 if counts else 0,
            category_counts=counts,
            sanitized_evidence={"labels": list(counts), "coverage": coverage},
        )
        db.add(row)
        rows.append(row)
    db.commit()
    return client, scan, rows


def submit(client, scan, result_ids=None):
    response = client.post(
        f"/api/v1/scans/{scan.id}/classify",
        json={} if result_ids is None else {"result_ids": [str(i) for i in result_ids]},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def completed(client, job_id, expected="COMPLETED"):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/classification-jobs/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] in {"COMPLETED", "PARTIAL", "FAILED"}:
            assert job["status"] == expected, job
            return job
        time.sleep(0.25)
    pytest.fail("Separate classification worker did not finish within 90 seconds")


def decisions(client, job_id):
    response = client.get(f"/api/v1/classifications?job_id={job_id}&page_size=100")
    assert response.status_code == 200
    return response.json()


def barrier():
    result = celery_app.send_task("privacyshield.smoke", args=["classification-barrier"])
    try:
        assert result.get(timeout=60)["status"] == "ok"
    finally:
        result.forget()


def test_classification_metadata_only_real_worker_and_duplicate_delivery(
    evidence_scan, fake_model, db
):
    client, scan, rows = evidence_scan
    job_id = submit(client, scan)
    job = completed(client, job_id)
    assert (
        job["total_results"],
        job["completed_results"],
        job["failed_results"],
        job["progress"],
    ) == (3, 3, 0, 100)
    items = decisions(client, job_id)["items"]
    assert len(items) == 3 and all(item["requires_approval"] is True for item in items)
    assert {item["scan_result_id"] for item in items} == {
        str(row.id) for row in rows if not row.json_path
    }
    assert all(item["confidence"] == 0.87 for item in items)
    assert next(item for item in items if item["column_name"] == "id")["category"] == "NONE"
    requests = fake_model.get("/requests").json()["requests"]
    assert len(requests) == 3
    assert all(len(request["columns"]) == 1 for request in requests)
    allowed = {
        "result_id",
        "schema_name",
        "table_name",
        "column_name",
        "json_path",
        "data_type",
        "is_primary_key",
        "is_foreign_key",
        "nullable",
        "sampled_rows",
        "matching_rows",
        "category_counts",
        "detector_confidence",
        "coverage",
    }
    assert all(set(request["columns"][0]) == allowed for request in requests)
    assert "must-never-reach-model" not in json.dumps(requests)
    old_ids = {item["id"] for item in items}
    celery_app.send_task("privacyshield.classify", args=[job_id], ignore_result=True)
    barrier()
    assert {item["id"] for item in decisions(client, job_id)["items"]} == old_ids
    db.expire_all()
    assert db.get(ClassificationJob, uuid.UUID(job_id)).attempt_count == 1
    assert db.get(ScanJob, scan.id).status == "COMPLETED"
    assert client.get(f"/api/v1/classification-jobs?scan_id={scan.id}").json()["total"] == 1


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "AUDITOR"])
def test_classification_roles_csrf_and_selected_path(evidence_scan, fake_model, login, role):
    _, scan, rows = evidence_scan
    client, _ = login(role)
    payload = {"result_ids": [str(rows[-1].id)]}
    assert client.get("/api/v1/classifications").status_code == 200
    assert client.get("/api/v1/classification-jobs").status_code == 200
    assert (
        client.post(
            f"/api/v1/scans/{scan.id}/classify", json=payload, headers={"X-CSRF-Token": "invalid"}
        ).status_code
        == 403
    )
    response = client.post(f"/api/v1/scans/{scan.id}/classify", json=payload)
    assert response.status_code == (403 if role == "AUDITOR" else 202)
    if role != "AUDITOR":
        job_id = response.json()["id"]
        completed(client, job_id)
        assert decisions(client, job_id)["items"][0]["json_path"] == "$.email"


def test_selection_limits_incomplete_scans_and_cross_scan_lineage(evidence_scan, db):
    client, scan, rows = evidence_scan
    for selected in [
        [],
        [str(rows[0].id)] * 2,
        [str(uuid.uuid4()) for _ in range(51)],
        [str(uuid.uuid4())],
    ]:
        assert (
            client.post(
                f"/api/v1/scans/{scan.id}/classify", json={"result_ids": selected}
            ).status_code
            == 422
        )
    other = ScanJob(
        connection_id=scan.connection_id,
        snapshot_id=scan.snapshot_id,
        requested_by=scan.requested_by,
        status="FAILED",
    )
    db.add(other)
    db.commit()
    assert client.post(f"/api/v1/scans/{other.id}/classify", json={}).status_code == 409
    other.status = "COMPLETED"
    db.commit()
    assert (
        client.post(
            f"/api/v1/scans/{other.id}/classify", json={"result_ids": [str(rows[0].id)]}
        ).status_code
        == 422
    )
    job = ClassificationJob(
        scan_job_id=other.id,
        requested_by=scan.requested_by,
        total_results=1,
        model="test",
        prompt_version="test",
    )
    db.add(job)
    db.flush()
    db.add(ClassificationJobItem(job_id=job.id, scan_job_id=other.id, scan_result_id=rows[0].id))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


@pytest.mark.parametrize(
    "mode,code",
    [
        ("unavailable", "OLLAMA_UNAVAILABLE"),
        ("malformed", "AI_INVALID_RESPONSE"),
        ("identity_mismatch", "AI_INVALID_RESPONSE"),
    ],
)
def test_model_failures_preserve_scan_without_fabricating_advice(
    evidence_scan, fake_model, db, mode, code
):
    client, scan, rows = evidence_scan
    assert fake_model.post("/control", json={"mode": mode}).status_code == 200
    job_id = submit(client, scan, [rows[1].id])
    job = completed(client, job_id, "FAILED")
    assert job["error_code"] == code
    assert (job["completed_results"], job["failed_results"]) == (0, 1)
    assert decisions(client, job_id)["total"] == 0
    db.expire_all()
    assert db.get(ScanJob, scan.id).status == "COMPLETED"
    assert (
        db.scalar(
            select(func.count()).select_from(ScanResult).where(ScanResult.scan_job_id == scan.id)
        )
        == 4
    )


def test_partial_classification_retains_only_valid_advice(evidence_scan, fake_model):
    client, scan, _ = evidence_scan
    assert fake_model.post("/control", json={"mode": "partial"}).status_code == 200
    job_id = submit(client, scan)
    job = completed(client, job_id, "PARTIAL")
    assert (job["completed_results"], job["failed_results"], job["progress"]) == (1, 2, 100)
    assert job["error_code"] == "AI_INVALID_RESPONSE"
    assert decisions(client, job_id)["total"] == 1


def test_durable_queue_recovers_interrupted_job(evidence_scan, fake_model, db, monkeypatch):
    client, scan, rows = evidence_scan
    original = celery_app.send_task
    messages = []

    def outage(name, *args, **kwargs):
        messages.append((name, kwargs))
        raise ConnectionError("Controlled unavailable broker")

    monkeypatch.setattr(celery_app, "send_task", outage)
    job_id = submit(client, scan, [rows[1].id])
    job = db.get(ClassificationJob, uuid.UUID(job_id))
    assert job.status == "QUEUED" and job.started_at is None
    assert messages[0][0] == "privacyshield.classify"
    assert messages[0][1]["args"] == [job_id]
    assert "must-never-reach-model" not in repr(messages)
    job.status = "RUNNING"
    job.attempt_count = 1
    job.dispatch_attempted_at = datetime.now(UTC) - timedelta(minutes=5)
    db.commit()
    with scan_lock(job.id, "classification") as lease:
        assert lease.valid()
        assert enqueue_classification(job.id, force=True) is False
    monkeypatch.setattr(celery_app, "send_task", original)
    original("privacyshield.dispatch_classifications", ignore_result=True)
    completed(client, job_id)
    db.expire_all()
    assert db.get(ClassificationJob, uuid.UUID(job_id)).attempt_count == 2


def test_stale_attempt_cannot_publish_or_fail_newer_attempt(evidence_scan, db, monkeypatch):
    client, scan, rows = evidence_scan
    monkeypatch.setattr(celery_app, "send_task", lambda *args, **kwargs: None)
    job_id = uuid.UUID(submit(client, scan, [rows[1].id]))
    job = db.get(ClassificationJob, job_id)
    job.status = "RUNNING"
    job.attempt_count = 2
    db.commit()
    decision = ClassificationDecision(
        result_id=str(rows[1].id),
        schema_name="enterprise",
        table_name="people",
        column_name="email",
        json_path="",
        category="EMAIL_ADDRESS",
        risk="HIGH",
        recommendation="NULLIFY",
        confidence=0.8,
        reason="Synthetic valid advisory decision",
        requires_human_approval=True,
    )
    assert persist_decision(job_id, 1, rows[1].id, decision) is False
    assert persist_failure(job_id, 1, "CLASSIFICATION_FAILED") is False
    assert finish_job(job_id, 1) is False
    db.expire_all()
    job = db.get(ClassificationJob, job_id)
    assert (job.status, job.attempt_count, job.completed_results, job.failed_results) == (
        "RUNNING",
        2,
        0,
        0,
    )
    assert (
        db.scalar(
            select(func.count())
            .select_from(PIIClassification)
            .where(PIIClassification.job_id == job_id)
        )
        == 0
    )
    # Retire this isolated test job before the periodic dispatcher revisits it.
    assert persist_failure(job_id, 2, "CLASSIFICATION_FAILED") is True
    assert finish_job(job_id, 2) is True

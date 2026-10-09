"""Scan APIs exercised against a separate Linux worker and real PostgreSQL/Redis."""

import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import hash_password
from app.main import app
from app.models import AuditEvent, ScanJob, ScanResult, User
from app.services.scanning.jobs import (
    complete_scan,
    enqueue_scan,
    mark_failed,
    persist_progress,
    scan_lock,
)
from app.workers.celery_app import celery_app

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as db:
        yield db


@pytest.fixture
def scan_client(db, monkeypatch):
    monkeypatch.setattr("app.api.auth.login_throttle", LoginThrottle())
    clients = []

    def login(role="ADMIN"):
        password = secrets.token_urlsafe(24)
        user = User(
            email=f"scan-{uuid.uuid4().hex}@example.com",
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
        return client

    yield login
    for client in clients:
        client.close()


@pytest.fixture
def scan_config():
    password = os.environ.get("TEST_TARGET_SCANNER_PASSWORD")
    assert password, "Real target scanner credential is required"
    return {
        "name": "scan-" + uuid.uuid4().hex,
        "host": os.environ.get("TEST_TARGET_HOST", "target-db"),
        "port": int(os.environ.get("TEST_TARGET_PORT", "5432")),
        "database_name": "enterprise_demo",
        "ssl_mode": "disable",
        "scanner_username": "ps_scanner",
        "scanner_password": password,
    }


def source(client, config, schemas=None):
    response = client.post("/api/v1/connections", json=config)
    assert response.status_code == 201, response.text
    connection_id = response.json()["id"]
    response = client.post(
        f"/api/v1/connections/{connection_id}/discover", json={"schemas": schemas or ["enterprise"]}
    )
    assert response.status_code == 200, response.text
    return {
        "connection_id": connection_id,
        "snapshot_id": response.json()["snapshot_id"],
        "sample_limit": 3,
    }


def submit(client, payload):
    response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 202, response.text
    return response.json()["id"]


def wait_for_scan(client, job_id, expected="COMPLETED"):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            assert job["status"] == expected, job
            return job
        time.sleep(0.5)
    pytest.fail("Separate scan worker did not finish within 180 seconds")


def results(client, job_id):
    response = client.get(f"/api/v1/scans/{job_id}/results?page_size=100")
    assert response.status_code == 200
    return response.json()


def worker_barrier():
    result = celery_app.send_task("privacyshield.smoke", args=["scan-integration-barrier"])
    try:
        assert result.get(timeout=60)["status"] == "ok"
    finally:
        result.forget()


def test_real_api_scan_detects_scalar_json_and_free_text_without_retaining_samples(
    scan_client, scan_config, db
):
    client = scan_client()
    payload = source(client, scan_config)
    job_id = submit(client, payload)
    completed = wait_for_scan(client, job_id)
    assert completed["progress"] == 100 and completed["error_code"] is None
    report = results(client, job_id)
    items = report["items"]
    assert report["total"] == len(items) and items
    categories = set().union(*(set(item["category_counts"]) for item in items))
    assert {"EMAIL_ADDRESS", "PAN_CANDIDATE", "AADHAAR_CANDIDATE"} <= categories
    assert any(item["json_path"] and "EMAIL_ADDRESS" in item["category_counts"] for item in items)
    assert any(
        item["column_name"] == "body" and "EMAIL_ADDRESS" in item["category_counts"]
        for item in items
    )
    assert all(0 <= item["matching_rows"] <= item["sampled_rows"] <= 3 for item in items)
    raw = json.dumps(report)
    for forbidden in [
        "customer1@example.com",
        "alternate1@example.org",
        "ABCDE0001F",
        "2345 6789 0001",
        scan_config["scanner_password"],
    ]:
        assert forbidden not in raw
    stored = db.scalars(select(ScanResult).where(ScanResult.scan_job_id == uuid.UUID(job_id))).all()
    assert len(stored) == len(items)
    assert "customer1@example.com" not in json.dumps([row.sanitized_evidence for row in stored])
    old_ids = {item["id"] for item in items}
    celery_app.send_task("privacyshield.scan", args=[job_id], ignore_result=True)
    worker_barrier()
    assert {item["id"] for item in results(client, job_id)["items"]} == old_ids
    db.expire_all()
    assert db.get(ScanJob, uuid.UUID(job_id)).attempt_count == 1
    assert (
        db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.subject_id == uuid.UUID(job_id),
                AuditEvent.event_type == "SCAN_COMPLETED",
            )
        )
        == 1
    )


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "AUDITOR"])
def test_scan_api_role_boundaries(scan_client, scan_config, role):
    admin = scan_client()
    payload = source(admin, scan_config)
    client = scan_client(role)
    assert client.get("/api/v1/scans").status_code == 200
    response = client.post("/api/v1/scans", json=payload | {"sample_limit": 1})
    assert response.status_code == (403 if role == "AUDITOR" else 202)
    if role != "AUDITOR":
        job_id = response.json()["id"]
        wait_for_scan(client, job_id)
        auditor = scan_client("AUDITOR")
        assert auditor.get(f"/api/v1/scans/{job_id}").status_code == 200
        assert auditor.get(f"/api/v1/scans/{job_id}/results").status_code == 200


def test_scan_limits_snapshot_ownership_and_csrf(scan_client, scan_config):
    client = scan_client()
    payload = source(client, scan_config)
    for limit in [0, 10001]:
        assert (
            client.post("/api/v1/scans", json=payload | {"sample_limit": limit}).status_code == 422
        )
    other = source(client, scan_config | {"name": "scan-other-" + uuid.uuid4().hex})
    assert (
        client.post(
            "/api/v1/scans", json=payload | {"snapshot_id": other["snapshot_id"]}
        ).status_code
        == 422
    )
    assert (
        client.post("/api/v1/scans", json=payload, headers={"X-CSRF-Token": "invalid"}).status_code
        == 403
    )


def test_durable_dispatch_survives_broker_failure_and_interrupted_execution(
    scan_client, scan_config, db, monkeypatch
):
    client = scan_client()
    payload = source(client, scan_config)
    original = celery_app.send_task
    attempts = []

    def unavailable(name, *args, **kwargs):
        attempts.append((name, args, kwargs))
        raise ConnectionError("simulated broker outage")

    monkeypatch.setattr(celery_app, "send_task", unavailable)
    job_id = submit(client, payload)
    job = db.get(ScanJob, uuid.UUID(job_id))
    assert job.status == "QUEUED" and job.started_at is None
    assert attempts[0][0] == "privacyshield.scan"
    assert attempts[0][2]["args"] == [job_id]
    assert scan_config["scanner_password"] not in repr(attempts)
    # Simulate durable state left by a terminated process; the real separate worker recovers it.
    job.status = "RUNNING"
    job.attempt_count = 1
    job.started_at = datetime.now(UTC) - timedelta(minutes=5)
    job.dispatch_attempted_at = datetime.now(UTC) - timedelta(minutes=5)
    db.commit()
    with scan_lock(job.id) as locked:
        assert locked
        assert enqueue_scan(job.id, force=True) is False
    monkeypatch.setattr(celery_app, "send_task", original)
    original("privacyshield.dispatch_scans", ignore_result=True)
    wait_for_scan(client, job_id)
    db.expire_all()
    assert db.get(ScanJob, uuid.UUID(job_id)).attempt_count == 2
    assert results(client, job_id)["items"]


def test_stale_attempt_cannot_change_newer_progress_results_or_failure(
    scan_client,
    scan_config,
    db,
    monkeypatch,
):
    client = scan_client()
    payload = source(client, scan_config)
    monkeypatch.setattr(celery_app, "send_task", lambda *args, **kwargs: None)
    job_id = uuid.UUID(submit(client, payload))
    job = db.get(ScanJob, job_id)
    job.status = "RUNNING"
    job.attempt_count = 2
    job.progress = 60
    db.commit()
    assert persist_progress(job_id, 1, 90) is False
    assert complete_scan(job_id, 1, []) is False
    assert mark_failed(job_id, "SCAN_FAILED", 1) is False
    db.expire_all()
    job = db.get(ScanJob, job_id)
    assert (job.status, job.attempt_count, job.progress, job.error_code) == ("RUNNING", 2, 60, None)
    assert (
        db.scalar(
            select(func.count()).select_from(ScanResult).where(ScanResult.scan_job_id == job_id)
        )
        == 0
    )
    assert (
        db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.subject_id == job_id,
                AuditEvent.event_type.in_(["SCAN_COMPLETED", "SCAN_FAILED"]),
            )
        )
        == 0
    )
    with scan_lock(job_id) as lease:
        assert lease.valid()
    assert lease.valid() is False  # A released/closed lock session cannot authorize publication.
    job.status = (
        "CANCELLED"  # Retire this isolated synthetic job before the dispatcher revisits it.
    )
    db.commit()


@pytest.fixture
def bounded_source(scan_config):
    password = os.environ.get("TEST_TARGET_SUPERUSER_PASSWORD")
    assert password, "Real target admin credential is required for isolated scan fixtures"
    schema = "ps_scan_" + uuid.uuid4().hex[:16]
    table = sql.Identifier(schema, 'PII "records"')
    with psycopg.connect(
        host=scan_config["host"],
        port=scan_config["port"],
        dbname="enterprise_demo",
        user="postgres",
        password=password,
        autocommit=True,
    ) as admin:
        try:
            admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            admin.execute(
                sql.SQL(
                    "CREATE TABLE {} (id int PRIMARY KEY, profile jsonb, "
                    "oversized jsonb, note text, binary_data bytea)"
                ).format(table)
            )
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO ps_scanner").format(sql.Identifier(schema))
            )
            admin.execute(sql.SQL("GRANT SELECT ON {} TO ps_scanner").format(table))
            admin.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(table))
            admin.execute(
                sql.SQL(
                    "CREATE POLICY scan_visible_rows ON {} FOR SELECT TO ps_scanner USING (id <= 2)"
                ).format(table)
            )
            for identifier in [1, 2, 3]:
                admin.execute(
                    sql.SQL("INSERT INTO {} VALUES (%s,%s::jsonb,%s::jsonb,%s,%s)").format(table),
                    (
                        identifier,
                        json.dumps(
                            {
                                "contact": {"email": f"visible{identifier}@example.com"},
                                "private-key@example.com": "candidate",
                            }
                        ),
                        json.dumps({"message": "x" * 20000}),
                        "visible@example.com " + "x" * 5000,
                        b"fixture",
                    ),
                )
            yield schema, table, admin
        finally:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_real_scan_respects_rls_cell_bounds_and_private_json_keys(
    scan_client, scan_config, bounded_source
):
    schema, _, _ = bounded_source
    client = scan_client()
    payload = source(client, scan_config, [schema]) | {"sample_limit": 5}
    job_id = submit(client, payload)
    wait_for_scan(client, job_id)
    report = results(client, job_id)
    assert all(item["sampled_rows"] == 2 for item in report["items"])
    assert "private-key@example.com" not in json.dumps(report)
    assert any("key_" in item["json_path"] for item in report["items"])
    oversized = next(item for item in report["items"] if item["column_name"] == "oversized")
    assert oversized["sanitized_evidence"]["coverage"]["values_skipped"] == 2
    note = next(item for item in report["items"] if item["column_name"] == "note")
    assert note["sanitized_evidence"]["coverage"]["values_truncated"] == 2
    assert note["category_counts"]["EMAIL_ADDRESS"] == 2
    binary = next(item for item in report["items"] if item["column_name"] == "binary_data")
    assert binary["sanitized_evidence"]["coverage"]["unsupported_type"] is True


def test_schema_drift_fails_without_publishing_partial_results(
    scan_client, scan_config, bounded_source
):
    schema, table, admin = bounded_source
    client = scan_client()
    payload = source(client, scan_config, [schema])
    admin.execute(sql.SQL("ALTER TABLE {} ADD COLUMN extra text").format(table))
    job_id = submit(client, payload)
    failed = wait_for_scan(client, job_id, "FAILED")
    assert failed["error_code"] == "SCHEMA_DRIFT"
    assert results(client, job_id)["items"] == []
    assert admin.execute(sql.SQL("SELECT count(*) FROM {}").format(table)).fetchone()[0] == 3

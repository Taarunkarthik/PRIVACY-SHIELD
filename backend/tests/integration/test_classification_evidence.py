"""Value shapes and detector triage, from a real scan to the model request.

A real worker scans the synthetic target database, and a controlled HTTP double
stands in for the model. Nothing here measures what the real model does with
shapes; that needs the separate smoke test on a machine with Ollama.
"""

import json
import os
import re
import secrets
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.auth import LoginThrottle
from app.core.database import session_factory
from app.core.security import encrypt_credential, hash_password
from app.main import app
from app.models import (
    ClassificationJob,
    DatabaseConnection,
    ScanJob,
    ScanResult,
    SchemaSnapshot,
    User,
)
from app.services.classification.adapter import system_prompt
from app.services.classification.triage import detector_verdict
from app.services.scanning.shapes import is_valid_shape

pytestmark = pytest.mark.integration

# Written out here on purpose, independent of the constants in the application.
SHAPE_PATTERN = re.compile(r"[aA9+?@.\-_()/:, ]{1,48}")
DEMO_TABLES = {"customers", "accounts", "transactions", "support_records"}
# Each demo table holds 100 rows; a quarter keeps this real scan short.
SAMPLE_ROWS = 25
RAW_FRAGMENTS = [
    "@example",
    "customer1",
    "alternate",
    "Synthetic",
    "ABCDE",
    "2345 6789",
    "+91 90000",
    "DEMO0",
    "Example Street",
    "Please contact",
]


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
            email=f"evidence-{uuid.uuid4().hex}@example.com",
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


def wait_for(client, path, done):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        response = client.get(path)
        assert response.status_code == 200
        job = response.json()
        if job["status"] in done:
            return job
        time.sleep(0.25)
    pytest.fail("The separate worker did not finish within 180 seconds")


def classify(client, scan_id, body):
    response = client.post(f"/api/v1/scans/{scan_id}/classify", json=body)
    assert response.status_code == 202, response.text
    job = wait_for(
        client,
        f"/api/v1/classification-jobs/{response.json()['id']}",
        {"COMPLETED", "PARTIAL", "FAILED"},
    )
    assert job["status"] == "COMPLETED", job
    return job


@pytest.fixture
def demo_scan(login):
    """Scan 25 random rows of each bundled demo table through the API and worker."""
    password = os.environ.get("TEST_TARGET_SCANNER_PASSWORD")
    assert password, "Real target scanner credential is required"
    client, _ = login()
    response = client.post(
        "/api/v1/connections",
        json={
            "name": "evidence-" + uuid.uuid4().hex,
            "host": os.environ.get("TEST_TARGET_HOST", "target-db"),
            "port": int(os.environ.get("TEST_TARGET_PORT", "5432")),
            "database_name": "enterprise_demo",
            "ssl_mode": "disable",
            "scanner_username": "ps_scanner",
            "scanner_password": password,
        },
    )
    assert response.status_code == 201, response.text
    connection_id = response.json()["id"]
    response = client.post(
        f"/api/v1/connections/{connection_id}/discover", json={"schemas": ["enterprise"]}
    )
    assert response.status_code == 200, response.text
    response = client.post(
        "/api/v1/scans",
        json={
            "connection_id": connection_id,
            "snapshot_id": response.json()["snapshot_id"],
            "sample_limit": SAMPLE_ROWS,
        },
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    scan = wait_for(client, f"/api/v1/scans/{scan_id}", {"COMPLETED", "FAILED", "CANCELLED"})
    assert scan["status"] == "COMPLETED", scan
    response = client.get(f"/api/v1/scans/{scan_id}/results?page_size=100")
    assert response.status_code == 200
    report = response.json()
    assert report["total"] == len(report["items"])
    return client, scan_id, report["items"]


def verdict(item):
    return detector_verdict(
        sampled_rows=item["sampled_rows"],
        matching_rows=item["matching_rows"],
        confidence=item["confidence"],
        evidence=item["sanitized_evidence"],
    )


def test_real_scan_stores_shapes_and_only_uncertain_columns_reach_the_model(
    demo_scan, fake_model, login, db
):
    client, scan_id, items = demo_scan
    whole = [item for item in items if not item["json_path"]]
    column = {(item["table_name"], item["column_name"]): item for item in whole}
    assert DEMO_TABLES <= {item["table_name"] for item in whole}

    # Every scalar column that was read has shapes, and each one is only a form.
    shaped = 0
    for item in items:
        evidence = item["sanitized_evidence"]
        if item["json_path"] or item["column_name"] == "profile":
            assert "shapes" not in evidence  # JSON documents and paths have none.
            continue
        if evidence["coverage"]["unsupported_type"]:
            assert "shapes" not in evidence
            continue
        shapes = evidence["shapes"]
        assert len(shapes) <= 3 and evidence["values_read"] <= item["sampled_rows"]
        assert sum(entry["rows"] for entry in shapes) <= evidence["values_read"]
        assert [entry["rows"] for entry in shapes] == sorted(
            (entry["rows"] for entry in shapes), reverse=True
        )
        for entry in shapes:
            assert set(entry) == {"shape", "rows"} and entry["rows"] >= 1
            assert SHAPE_PATTERN.fullmatch(entry["shape"]) and is_valid_shape(entry["shape"])
            # No letter other than a and A, and no digit other than 9.
            assert not re.search(r"[b-zB-Z0-8]", entry["shape"])
            assert "@example" not in entry["shape"]
        shaped += bool(shapes)
    assert shaped >= 10

    # The demo addresses are customer1 to customer100 at one domain. Only nine
    # have a single digit, so in any 25 rows the two-or-more-digit form leads.
    email = column[("customers", "email")]
    assert email["sampled_rows"] == SAMPLE_ROWS
    top = email["sanitized_evidence"]["shapes"][0]
    assert top["shape"] == "a+9+@a+.a+" and top["rows"] >= SAMPLE_ROWS - 9
    assert column[("customers", "phone")]["sanitized_evidence"]["shapes"] == [
        {"shape": "+9+ 9+ 9+", "rows": SAMPLE_ROWS}
    ]
    assert column[("customers", "pan")]["sanitized_evidence"]["shapes"] == [
        {"shape": "A+9+A", "rows": SAMPLE_ROWS}
    ]
    stored = db.scalars(
        select(ScanResult.sanitized_evidence).where(ScanResult.scan_job_id == uuid.UUID(scan_id))
    ).all()
    for text in (json.dumps(items), json.dumps(stored)):
        assert not any(fragment in text for fragment in RAW_FRAGMENTS)

    # The counts endpoint agrees with the documented rule applied to each result.
    verdicts = {item["id"]: verdict(item) for item in whole}
    uncertain = {key for key, value in verdicts.items() if value == "UNCERTAIN"}
    decided = {key for key, value in verdicts.items() if value == "DECIDED"}
    summary = client.get(f"/api/v1/scans/{scan_id}/classification-summary")
    assert summary.status_code == 200
    assert summary.json() == {
        "scan_id": scan_id,
        "whole_columns": len(whole),
        "decided": len(decided),
        "uncertain": len(uncertain),
        "not_classifiable": len(whole) - len(decided) - len(uncertain),
        "selection_limit": 50,
        "will_classify": min(len(uncertain), 50),
    }
    assert verdicts[email["id"]] == "DECIDED"
    assert verdicts[column[("transactions", "sequence_number")]["id"]] == "UNCERTAIN"
    assert decided and 0 < len(uncertain) <= 50
    auditor, _ = login("AUDITOR")
    assert auditor.get(f"/api/v1/scans/{scan_id}/classification-summary").json() == summary.json()

    # A request without a selection asks the model about the uncertain columns only.
    job = classify(client, scan_id, {})
    assert job["total_results"] == job["completed_results"] == len(uncertain)
    requests = fake_model.get("/requests").json()["requests"]
    sent = [request["columns"][0] for request in requests]
    assert {entry["result_id"] for entry in sent} == uncertain
    assert not {entry["result_id"] for entry in sent} & decided
    by_id = {item["id"]: item for item in whole}
    with_shapes = 0
    for request, entry in zip(requests, sent, strict=True):
        stored_shapes = by_id[entry["result_id"]]["sanitized_evidence"].get("shapes")
        if stored_shapes:
            with_shapes += 1
            assert entry["shapes"] == stored_shapes
            assert request["system"] == system_prompt(with_shapes=True)
        else:
            assert "shapes" not in entry
            assert request["system"] == system_prompt(with_shapes=False)
    assert with_shapes >= 5
    assert not any(fragment in json.dumps(sent) for fragment in RAW_FRAGMENTS)

    # A decided column can still be chosen explicitly, and its shapes are sent.
    assert fake_model.post("/control", json={"mode": "valid"}).status_code == 200
    job = classify(client, scan_id, {"result_ids": [email["id"]]})
    assert job["total_results"] == 1
    chosen = fake_model.get("/requests").json()["requests"]
    assert [request["columns"][0]["result_id"] for request in chosen] == [email["id"]]
    assert chosen[0]["columns"][0]["shapes"] == email["sanitized_evidence"]["shapes"]


@pytest.fixture
def decided_scan(db, login):
    """Seed a completed scan in which no whole column is left for the model."""
    client, user = login()
    connection = DatabaseConnection(
        name="evidence-" + uuid.uuid4().hex,
        host="unreachable.example.invalid",
        database_name="synthetic_metadata_only",
        scanner_username="no_source_access",
        scanner_password_ciphertext=encrypt_credential("must-never-reach-model"),
        created_by=user.id,
    )
    db.add(connection)
    db.flush()
    names = [("email", "text"), ("phone", "text"), ("photo", "bytea"), ("profile", "jsonb")]
    columns = [
        {"name": name, "data_type": dtype, "nullable": True, "is_primary_key": False}
        for name, dtype in names
    ]
    snapshot = SchemaSnapshot(
        connection_id=connection.id,
        fingerprint="b" * 64,
        catalog={
            "schemas": ["enterprise"],
            "tables": [
                {
                    "schema": "enterprise",
                    "name": "people",
                    "primary_key": [],
                    "foreign_keys": [],
                    "columns": columns,
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
        sample_limit=10,
        progress=100,
    )
    db.add(scan)
    db.flush()
    coverage = {
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
    rows = {}
    for name, path, matching, counts, evidence in [
        ("email", "", 10, {"EMAIL_ADDRESS": 10}, {"shapes": [{"shape": "a+@a+.a+", "rows": 10}]}),
        ("phone", "", 9, {"PHONE_NUMBER": 9}, {"shapes": [{"shape": "+9+ 9+ 9+", "rows": 9}]}),
        ("photo", "", 0, {}, {"coverage": coverage | {"unsupported_type": True}, "values_read": 0}),
        ("profile", "", 0, {}, {"values_read": 0}),
        # A JSON path with no match: paths are never part of the default selection.
        ("profile", "$.note", 0, {}, {}),
    ]:
        row = ScanResult(
            scan_job_id=scan.id,
            schema_name="enterprise",
            table_name="people",
            column_name=name,
            json_path=path,
            sampled_rows=10,
            matching_rows=matching,
            confidence=0.85 if counts else 0,
            category_counts=counts,
            sanitized_evidence={"labels": list(counts), "coverage": coverage, "values_read": 10}
            | evidence,
        )
        db.add(row)
        rows[(name, path)] = row
    db.commit()
    return client, scan, rows


def test_nothing_uncertain_is_a_bounded_error_and_starts_no_job(decided_scan, fake_model, db):
    client, scan, rows = decided_scan
    summary = client.get(f"/api/v1/scans/{scan.id}/classification-summary")
    assert summary.status_code == 200
    assert summary.json() == {
        "scan_id": str(scan.id),
        "whole_columns": 4,
        "decided": 2,
        "uncertain": 0,
        "not_classifiable": 2,
        "selection_limit": 50,
        "will_classify": 0,
    }
    for body in ({}, None):
        response = client.post(f"/api/v1/scans/{scan.id}/classify", json=body)
        assert response.status_code == 409
        assert response.json() == {"detail": "NOTHING_UNCERTAIN"}
    jobs = select(func.count()).select_from(ClassificationJob)
    assert db.scalar(jobs.where(ClassificationJob.scan_job_id == scan.id)) == 0
    assert fake_model.get("/requests").json()["requests"] == []

    # The person can still ask about a decided column by choosing it.
    job = classify(client, scan.id, {"result_ids": [str(rows[("phone", "")].id)]})
    assert job["total_results"] == 1
    requests = fake_model.get("/requests").json()["requests"]
    assert len(requests) == 1
    assert requests[0]["columns"][0]["shapes"] == [{"shape": "+9+ 9+ 9+", "rows": 9}]
    assert "must-never-reach-model" not in json.dumps(requests)


def test_summary_needs_a_session_and_a_completed_scan(decided_scan, db):
    client, scan, _ = decided_scan
    path = f"/api/v1/scans/{scan.id}/classification-summary"
    with TestClient(app, base_url="http://localhost:8080") as anonymous:
        assert anonymous.get(path).status_code == 401
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/classification-summary").status_code == 404
    # The scans router's own routes still answer, and none of them shadows this one.
    assert client.get(f"/api/v1/scans/{scan.id}").json()["id"] == str(scan.id)
    assert client.get(f"/api/v1/scans/{scan.id}/results").json()["total"] == 5
    running = ScanJob(
        connection_id=scan.connection_id,
        snapshot_id=scan.snapshot_id,
        requested_by=scan.requested_by,
        status="FAILED",
    )
    db.add(running)
    db.commit()
    assert client.get(f"/api/v1/scans/{running.id}/classification-summary").status_code == 409

"""JOB_RUNNER=inline: a real API subprocess runs every job kind without Celery or Redis.

The server is started the way a single-service deployment starts it, with
``REDIS_URL`` pointing at a port nothing listens on and a Celery queue name no
worker consumes. The test then drives scan, AI classification (against the
controlled HTTP model double) and policy deployment over HTTP only.

It shares the control and target databases with the other integration tests and
their Celery worker, so "which process ran the job" is proven rather than
assumed: the subprocess logs each job it starts and ends, and every job
finished on its first attempt (a second executor would have raised the count).
"""

import os
import secrets
import sys
import uuid

import httpx
import psycopg
import pytest
from psycopg.rows import dict_row

from app.core.database import session_factory
from app.core.security import hash_password
from app.models import ClassificationJob, PolicyDeployment, ScanJob, User
from tests.support import hosted

pytestmark = pytest.mark.integration


@pytest.fixture
def db():
    with session_factory()() as session:
        yield session


@pytest.fixture
def fake_model():
    url = os.environ.get("TEST_OLLAMA_BASE_URL")
    assert url, "Controlled HTTP Ollama double required; real model is a separate smoke test"
    with httpx.Client(base_url=url, timeout=10, trust_env=False) as client:
        assert client.get("/health").json()["implementation"] == "controlled-http-test-double"
        assert client.post("/control", json={"mode": "valid"}).status_code == 200
        yield url
        assert client.post("/control", json={"mode": "valid"}).status_code == 200


@pytest.fixture
def inline_api(tmp_path, fake_model):
    """The API as its own process, in inline mode, with no reachable broker."""
    port = hosted.free_port()
    env = hosted.child_environment(
        {
            "JOB_RUNNER": "inline",
            # Nothing listens here. Any attempt to use Redis would fail the jobs.
            "REDIS_URL": f"redis://127.0.0.1:{hosted.closed_port()}/0",
            # And no worker consumes this queue, should anything be published.
            "CELERY_QUEUE": "inline-unconsumed-" + uuid.uuid4().hex[:8],
            "OLLAMA_BASE_URL": fake_model,
            "COOKIE_SECURE": "false",
        }
    )
    env.pop("STATIC_DIR", None)
    server = hosted.ServerProcess(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
        ],
        env,
        tmp_path / "inline-api.log",
        port,
    )
    server.start()
    yield server
    server.kill()


@pytest.fixture
def admin(db):
    password = secrets.token_urlsafe(24)
    user = User(
        email=f"inline-{uuid.uuid4().hex}@example.com",
        role="ADMIN",
        password_hash=hash_password(password),
    )
    db.add(user)
    db.commit()
    return user.email, password


def _target():
    values = {
        name: os.environ.get(f"TEST_TARGET_{name}_PASSWORD")
        for name in ("SCANNER", "DEPLOYER", "READER")
    }
    assert all(values.values()), "Target scanner, deployer and reader passwords are required"
    host = os.environ.get("TEST_TARGET_HOST", "target-db")
    port = int(os.environ.get("TEST_TARGET_PORT", "5432"))
    return host, port, values


def test_inline_mode_runs_scan_classification_and_deployment_without_a_broker(
    inline_api, admin, db
):
    host, port, passwords = _target()
    email, password = admin
    # The Origin a browser on the default local frontend would send.
    session = hosted.ApiSession(inline_api.base_url, "http://localhost:8080")
    try:
        assert session.login(email, password).status_code == 200

        # Readiness does not need Redis in this mode, and says so.
        ready = session.get("/api/v1/health/ready")
        assert ready.status_code == 200, ready.text
        assert ready.json() == {
            "status": "ok",
            "checks": {"database": "ok", "redis": "not_used", "jobs": "ok"},
        }

        connection = session.post(
            "/api/v1/connections",
            json={
                "name": "inline-" + uuid.uuid4().hex[:12],
                "host": host,
                "port": port,
                "database_name": "enterprise_demo",
                "ssl_mode": "disable",
                "scanner_username": "ps_scanner",
                "scanner_password": passwords["SCANNER"],
                "deployer_username": "ps_deployer",
                "deployer_password": passwords["DEPLOYER"],
            },
        )
        assert connection.status_code == 201, connection.text
        connection_id = connection.json()["id"]
        snapshot_id = hosted.discover(session, connection_id)

        # Scan: real target rows, real Presidio, inside the API process.
        scan_id = hosted.queue_scan(session, connection_id, snapshot_id)
        scan = hosted.wait_scan(session, scan_id)
        assert scan["status"] == "COMPLETED", scan
        findings = session.get(f"/api/v1/scans/{scan_id}/results?page=1&page_size=50").json()
        assert findings["total"] > 0

        # AI classification: the in-process job calls the HTTP model double.
        classification = hosted.classify(session, scan_id)
        assert classification["status"] == "COMPLETED", classification
        assert classification["completed_results"] == classification["total_results"] > 0

        # Policy: submit, approve, deploy; the deployment job creates the view.
        policy, deployment, preview = hosted.deploy_policy(session, connection_id, snapshot_id)
        assert policy["status"] == "DEPLOYED", policy
        assert deployment["status"] == "COMPLETED", deployment
    finally:
        session.close()

    # The view exists on the target and hides what the policy says it hides.
    view = f'{preview["view_schema"]}."{preview["view_name"]}"'
    with psycopg.connect(
        host=host,
        port=port,
        dbname="enterprise_demo",
        user="ps_reader",
        password=passwords["READER"],
        connect_timeout=5,
        autocommit=True,
        row_factory=dict_row,
    ) as reader:
        rows = reader.execute(
            f"SELECT id, account_number, balance, currency FROM {view} ORDER BY id LIMIT 5"
        ).fetchall()
        assert rows and all(row["account_number"] == "[REDACTED]" for row in rows)
        assert all(row["balance"] is None for row in rows)  # no rule: typed NULL
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("SELECT * FROM enterprise.accounts LIMIT 1")

    # Each job ran exactly once, and it was this subprocess that ran it.
    db.expire_all()
    assert db.get(ScanJob, uuid.UUID(scan_id)).attempt_count == 1
    assert db.get(ClassificationJob, uuid.UUID(classification["id"])).attempt_count == 1
    assert db.get(PolicyDeployment, uuid.UUID(deployment["id"])).target_receipt["attempts"] == 1
    log = inline_api.log()
    for kind, job_id in (
        ("scan", scan_id),
        ("classify", classification["id"]),
        ("deploy", deployment["id"]),
    ):
        assert f"Job started: {kind} {job_id}" in log, log
        assert f"Job ended: {kind} {job_id}" in log, log
    assert "Jobs run in-process" in log
    # No source value, credential or key reached the server's log.
    for secret in (*passwords.values(), password, "customer1@example.com", "Synthetic Customer"):
        assert secret not in log

    # A clean stop: on SIGTERM the server drains, stops the job threads through
    # the lifespan hook, and exits. uvicorn re-raises the signal once it is done.
    assert inline_api.terminate(timeout=30) in (0, -15)
    assert "Application shutdown complete." in inline_api.log()

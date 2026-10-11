"""The in-process job runner in isolation: delivery, ordering, sweep, limits, shutdown.

These tests use stand-in job functions. The real jobs, against real PostgreSQL
and a real server process, are in tests/integration/test_inline_runner.py.
"""

import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from billiard.exceptions import SoftTimeLimitExceeded

from app.workers import inline
from app.workers.inline import InlineJobRunner

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return False


@pytest.fixture
def make_runner():
    runners = []

    def build(**kwargs):
        kwargs.setdefault("sweepers", ())
        kwargs.setdefault("poll_interval", 0.01)
        runner = InlineJobRunner(**kwargs)
        runners.append(runner)
        return runner

    yield build
    for runner in runners:
        runner.stop(timeout=2)


@pytest.fixture
def job_log(caplog):
    """The runner's log lines, captured on its own logger.

    Attached directly rather than through the root logger: the single-service
    app stops ``privacyshield`` records from propagating once it has run.
    """
    job_logger = logging.getLogger("privacyshield.jobs")
    job_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level("INFO", logger="privacyshield.jobs"):
            yield caplog
    finally:
        job_logger.removeHandler(caplog.handler)


def test_time_limits_match_the_celery_tasks():
    from app.workers.celery_app import celery_app

    tasks = {"scan": "privacyshield.scan", "classify": "privacyshield.classify"}
    tasks["deploy"] = "privacyshield.deploy"
    for kind, name in tasks.items():
        task = celery_app.tasks[name]
        assert inline.TIME_LIMITS[kind] == (task.soft_time_limit, task.time_limit)
    schedule = {entry["schedule"] for entry in celery_app.conf.beat_schedule.values()}
    assert schedule == {inline.SWEEP_INTERVAL_SECONDS}
    assert set(inline.RUNNERS) == set(inline.TIME_LIMITS) == set(tasks)


def test_a_submitted_job_starts_promptly(make_runner):
    ran = threading.Event()
    seen = []

    def job(job_id):
        seen.append(job_id)
        ran.set()

    runner = make_runner(runners={"scan": job}, sweep_interval=3600)
    job_id = uuid.uuid4()
    assert runner.submit("scan", job_id) is False  # not started: left to the sweep
    runner.start()
    started = time.monotonic()
    assert runner.submit("scan", job_id) is True
    # There are no sweepers in this runner, so only the queue can have delivered it.
    assert ran.wait(5)
    assert time.monotonic() - started < 2
    assert seen == [job_id]
    with pytest.raises(ValueError):
        runner.submit("unknown", job_id)


def test_jobs_run_one_at_a_time_in_order_and_duplicates_are_collapsed(make_runner):
    active = 0
    peak = 0
    order = []
    gate = threading.Event()
    guard = threading.Lock()

    def job(job_id):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        if not order:
            gate.wait(5)  # hold the worker so the rest pile up behind it
        order.append(job_id)
        with guard:
            active -= 1

    runner = make_runner(runners={"scan": job, "classify": job, "deploy": job})
    runner.start()
    ids = [uuid.uuid4() for _ in range(6)]
    assert runner.submit("scan", ids[0])
    assert wait_until(lambda: runner.current() == ("scan", ids[0]))
    for index, kind in enumerate(("classify", "deploy", "scan", "scan", "classify"), start=1):
        assert runner.submit(kind, ids[index])
    # Already waiting: accepted, but not queued a second time.
    assert runner.submit("scan", ids[3]) and runner.submit("deploy", ids[2])
    gate.set()
    assert wait_until(lambda: len(order) == 6)
    time.sleep(0.05)
    assert order == ids
    assert peak == 1
    assert runner.current() is None


def test_the_sweep_runs_at_startup_and_then_periodically(make_runner):
    calls = []
    job_id = uuid.uuid4()
    ran = threading.Event()

    def recover():
        # What dispatch_scan_jobs does after a restart: hand an eligible row back.
        calls.append(time.monotonic())
        if len(calls) == 1:
            runner.submit("scan", job_id)
        return 0

    def broken():
        raise RuntimeError("database unavailable")

    runner = make_runner(
        runners={"scan": lambda _: ran.set()},
        sweepers=(broken, recover),  # one failing sweeper must not stop the others
        sweep_interval=0.05,
    )
    runner.start()
    assert ran.wait(2), "the startup sweep did not deliver the abandoned job"
    assert wait_until(lambda: len(calls) >= 4)
    gaps = [later - earlier for earlier, later in zip(calls, calls[1:], strict=False)]
    assert all(gap >= 0.04 for gap in gaps)
    assert runner.alive


def test_a_failing_job_does_not_stop_the_worker(make_runner, job_log):
    done = threading.Event()

    def job(job_id):
        if not done.is_set() and job_id == first:
            raise RuntimeError("secret source value 4111-1111")
        done.set()

    first, second = uuid.uuid4(), uuid.uuid4()
    runner = make_runner(runners={"scan": job})
    runner.start()
    runner.submit("scan", first)
    runner.submit("scan", second)
    assert done.wait(2)
    assert wait_until(lambda: f"Job ended: scan {second}" in job_log.text)
    assert f"Job started: scan {first}" in job_log.text
    assert "interrupted (RuntimeError); reconciliation pending" in job_log.text
    assert "4111" not in job_log.text  # exception text is never logged
    assert runner.alive


def test_soft_limit_interrupts_the_job_and_the_worker_carries_on(make_runner):
    outcome = {}
    after = threading.Event()

    def slow(job_id):
        try:
            while True:  # pure Python work, as detection is
                time.sleep(0.005)
        except SoftTimeLimitExceeded:
            # The real jobs mark the row FAILED with a *_TIMEOUT code here.
            outcome["interrupted"] = True

    runner = make_runner(
        runners={"scan": slow, "deploy": lambda _: after.set()},
        time_limits={"scan": (0.1, 30), "deploy": (30, 60)},
        on_hard_timeout=lambda *_: outcome.setdefault("hard", True),
    )
    runner.start()
    runner.submit("scan", uuid.uuid4())
    runner.submit("deploy", uuid.uuid4())
    assert after.wait(5), "the worker did not survive a soft time limit"
    assert outcome == {"interrupted": True}
    # A cancelled or late limit must not leak into the idle worker.
    time.sleep(0.1)
    assert runner.alive and runner.current() is None


def test_soft_limit_that_escapes_the_job_is_contained(make_runner):
    after = threading.Event()

    def unprotected(job_id):
        while True:
            time.sleep(0.005)

    runner = make_runner(
        runners={"scan": unprotected, "deploy": lambda _: after.set()},
        time_limits={"scan": (0.05, 30), "deploy": (30, 60)},
    )
    runner.start()
    runner.submit("scan", uuid.uuid4())
    runner.submit("deploy", uuid.uuid4())
    assert after.wait(5)
    assert runner.alive


def test_hard_limit_reports_a_job_that_cannot_be_interrupted(make_runner):
    reported = []
    release = threading.Event()

    def stuck(job_id):
        # Ignores the soft limit, like a call blocked outside the interpreter.
        while not release.is_set():
            try:
                release.wait(0.01)
            except SoftTimeLimitExceeded:
                pass

    job_id = uuid.uuid4()
    runner = make_runner(
        runners={"scan": stuck},
        time_limits={"scan": (0.05, 0.15)},
        on_hard_timeout=lambda kind, identifier: reported.append((kind, identifier)),
    )
    runner.start()
    runner.submit("scan", job_id)
    assert wait_until(lambda: reported, timeout=3)
    time.sleep(0.1)
    assert reported == [("scan", job_id)]  # exactly once
    release.set()


def test_default_hard_limit_action_ends_the_process():
    # Run in a child: the default action is os._exit, which would end pytest.
    script = (
        "import time, uuid, logging\n"
        "logging.basicConfig(level=logging.INFO)\n"
        "from app.workers.inline import InlineJobRunner\n"
        "def stuck(_):\n"
        "    while True:\n"
        "        try:\n"
        "            time.sleep(0.01)\n"
        "        except Exception:\n"
        "            pass\n"
        "r = InlineJobRunner(runners={'scan': stuck}, sweepers=(), poll_interval=0.01,\n"
        "                    time_limits={'scan': (0.05, 0.2)})\n"
        "r.start(); r.submit('scan', uuid.uuid4()); time.sleep(20); print('still alive')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=BACKEND_ROOT, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 70
    assert "still alive" not in result.stdout
    assert "exiting so the service restarts and recovers it" in result.stderr


def test_stop_waits_for_the_running_job_and_leaves_the_rest_in_the_database(make_runner):
    finished = []
    release = threading.Event()

    def job(job_id):
        release.wait(5)
        finished.append(job_id)

    running, waiting = uuid.uuid4(), uuid.uuid4()
    runner = make_runner(runners={"scan": job})
    runner.start()
    runner.submit("scan", running)
    assert wait_until(lambda: runner.current() is not None)
    runner.submit("scan", waiting)
    threading.Timer(0.1, release.set).start()
    assert runner.stop(timeout=5) is True
    # The running job completed; the waiting one was not started. Its row is
    # still QUEUED in PostgreSQL, which is what the next start's sweep picks up.
    assert finished == [running]
    assert runner.submit("scan", uuid.uuid4()) is False
    assert not runner.alive


def test_stop_gives_up_on_a_job_that_outlasts_the_grace_period(make_runner, job_log):
    release = threading.Event()
    runner = make_runner(runners={"scan": lambda _: release.wait(10)})
    runner.start()
    job_id = uuid.uuid4()
    runner.submit("scan", job_id)
    assert wait_until(lambda: runner.current() is not None)
    assert runner.stop(timeout=0.1) is False
    assert f"scan {job_id} is still running" in job_log.text
    release.set()


def test_module_level_runner_reports_status():
    assert inline.status() == "unavailable"
    assert inline.submit("scan", uuid.uuid4()) is False
    runner = inline.start()
    try:
        assert inline.start() is runner  # idempotent
        assert inline.status() == "ok"
    finally:
        assert inline.stop(timeout=5) is True
    assert inline.status() == "unavailable"


def test_inline_mode_loads_no_broker_code_and_is_ready_without_redis():
    # A fresh interpreter, because this process has already imported Celery.
    script = (
        "import sys\n"
        "from fastapi.testclient import TestClient\n"
        "import app.api.scans, app.api.classifications, app.services.policies.execution\n"
        "from app.main import app as application\n"
        "with TestClient(application) as client:\n"
        "    body = client.get('/api/v1/health/ready').json()\n"
        "    assert body['checks']['redis'] == 'not_used', body\n"
        "    assert body['checks']['jobs'] == 'ok', body\n"
        "    assert set(body['checks']) == {'database', 'redis', 'jobs'}, body\n"
        "after = client.get('/api/v1/health/ready').json()\n"
        "assert after['checks']['jobs'] == 'unavailable', after\n"
        "brokers = ('celery', 'kombu', 'redis')\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in brokers)\n"
        "assert not loaded, loaded\n"
        "print('clean')\n"
    )
    env = os.environ | {
        "JOB_RUNNER": "inline",
        "REDIS_URL": "redis://127.0.0.1:1/0",
    }
    env.pop("STATIC_DIR", None)
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=BACKEND_ROOT, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip().endswith("clean")


def test_celery_mode_readiness_keeps_its_shape():
    from fastapi.testclient import TestClient

    from app.core.config import get_settings
    from app.main import app

    assert get_settings().job_runner == "celery"
    with TestClient(app) as client:
        body = client.get("/api/v1/health/ready").json()
    assert set(body) == {"status", "checks"}
    assert set(body["checks"]) == {"database", "redis"}
    assert set(body["checks"].values()) <= {"ok", "unavailable"}


def test_the_sweep_also_seals_the_audit_chain():
    # Celery beat seals the audit chain in the worker deployment. Without a
    # worker, the sweep is the only thing that can.
    from app.workers import celery_app, inline

    assert inline._seal_audit_chain in inline.SWEEPERS
    assert "seal-audit-chain" in celery_app.celery_app.conf.beat_schedule

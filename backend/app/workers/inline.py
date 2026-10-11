"""In-process job runner for single-service hosting: PostgreSQL is the queue.

Selected with ``JOB_RUNNER=inline``. The API process runs scan, classification
and deployment jobs itself, so the deployment needs no Celery worker and no
Redis. Nothing here imports Celery, Kombu or Redis.

Durability does not come from this module. A job is a row in PostgreSQL before
it is ever handed over, the ``run_*`` functions take a per-job advisory lock and
fence their writes by attempt number, and the ``dispatch_*`` functions find rows
that still need work. This module only supplies what the Celery worker and beat
supplied:

* delivery: ``submit`` wakes one worker thread, so a job starts as soon as the
  request that queued it has committed;
* the periodic sweep: every 15 seconds the same ``dispatch_*`` functions Celery
  beat calls re-enqueue eligible rows, which is also how a job left ``RUNNING``
  by a killed process is picked up after a restart;
* time limits: a soft limit raises ``SoftTimeLimitExceeded`` inside the job (the
  job modules already turn that into a ``*_TIMEOUT`` failure), and a hard limit
  ends the process so the platform restarts it and the row is recovered.

Exactly one job runs at a time. Detection loads Presidio and a spaCy model in
this process; a single worker thread keeps that to one copy and one job's
working set.
"""

import ctypes
import logging
import os
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

# The exception type the job modules already handle. billiard is Celery's
# multiprocessing library; importing this class starts no broker or pool.
from billiard.exceptions import SoftTimeLimitExceeded

logger = logging.getLogger("privacyshield.jobs")

# The cadence of the Celery beat schedule in app/workers/celery_app.py.
SWEEP_INTERVAL_SECONDS = 15.0
# (soft, hard) seconds per job kind: the limits of the matching Celery tasks.
# tests/test_inline_runner.py asserts the two stay equal.
TIME_LIMITS: dict[str, tuple[float, float]] = {
    "scan": (600, 660),
    "classify": (900, 960),
    "deploy": (120, 150),
}
# How long a clean shutdown waits for the running job before leaving it to be
# recovered. Kept under the 30 seconds hosting platforms allow before SIGKILL.
SHUTDOWN_GRACE_SECONDS = 20.0

_STOP = object()


def _run_scan(job_id: UUID) -> None:
    from app.services.scanning.jobs import run_scan

    run_scan(job_id)


def _run_classification(job_id: UUID) -> None:
    from app.services.classification.jobs import run_classification

    run_classification(job_id)


def _run_deployment(job_id: UUID) -> None:
    from app.services.policies.execution import run_deployment

    run_deployment(job_id)


def _sweep_scans() -> int:
    from app.services.scanning.jobs import dispatch_scan_jobs

    return dispatch_scan_jobs()


def _sweep_classifications() -> int:
    from app.services.classification.jobs import dispatch_classification_jobs

    return dispatch_classification_jobs()


def _sweep_deployments() -> int:
    from app.services.policies.jobs import dispatch_deployments

    return dispatch_deployments()


RUNNERS: dict[str, Callable[[UUID], None]] = {
    "scan": _run_scan,
    "classify": _run_classification,
    "deploy": _run_deployment,
}
SWEEPERS: tuple[Callable[[], int], ...] = (
    _sweep_scans,
    _sweep_classifications,
    _sweep_deployments,
)


def _raise_in_thread(thread_id: int, exception: type[BaseException] | None) -> None:
    """Schedule ``exception`` in another thread, or cancel a pending one with None.

    The interpreter delivers it between bytecodes, so it interrupts Python code
    (detection, JSON handling, loops) but not a call blocked inside C, such as a
    database read. Those are bounded by statement and connect timeouts instead.
    """
    # py_object() with no value is a NULL pointer, which clears a pending exception.
    target = ctypes.py_object(exception) if exception is not None else ctypes.py_object()
    ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), target)


def _exit_process(kind: str, job_id: UUID) -> None:
    # The equivalent of Celery killing a worker process at its hard time limit.
    # A thread cannot be killed, so the whole process ends: the platform
    # restarts it, the dead session releases the job's advisory lock, and the
    # sweep re-runs the row as a new attempt (at most MAX_ATTEMPTS in total).
    logger.critical(
        "Job %s %s ignored its time limit; exiting so the service restarts and recovers it",
        kind,
        job_id,
    )
    logging.shutdown()
    os._exit(70)


@dataclass(eq=False)
class _Running:
    kind: str
    job_id: UUID
    thread_id: int
    soft_deadline: float
    hard_deadline: float
    soft_fired: bool = False
    hard_fired: bool = False


class InlineJobRunner:
    """One worker thread plus a supervisor thread for the sweep and time limits."""

    def __init__(
        self,
        *,
        runners: dict[str, Callable[[UUID], None]] | None = None,
        sweepers: tuple[Callable[[], int], ...] | None = None,
        time_limits: dict[str, tuple[float, float]] | None = None,
        sweep_interval: float = SWEEP_INTERVAL_SECONDS,
        poll_interval: float = 1.0,
        on_hard_timeout: Callable[[str, UUID], None] = _exit_process,
    ) -> None:
        self._runners = RUNNERS if runners is None else runners
        self._sweepers = SWEEPERS if sweepers is None else sweepers
        self._time_limits = TIME_LIMITS if time_limits is None else time_limits
        self._sweep_interval = sweep_interval
        self._poll_interval = poll_interval
        self._on_hard_timeout = on_hard_timeout
        self._queue: queue.Queue = queue.Queue()
        self._pending: set[tuple[str, UUID]] = set()
        self._lock = threading.Lock()
        self._current: _Running | None = None
        self._started = False
        self._stopping = False
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._work, name="ps-job-worker", daemon=True)
        self._supervisor = threading.Thread(
            target=self._supervise, name="ps-job-supervisor", daemon=True
        )

    # ------------------------------------------------------------------ API

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        self._worker.start()
        self._supervisor.start()

    def submit(self, kind: str, job_id: UUID) -> bool:
        """Queue a committed job for the worker thread.

        Returns False when the runner is not accepting work (not started, or
        shutting down). That is not a loss: the row stays in PostgreSQL and the
        next sweep, in this process or the next one, delivers it.
        """
        if kind not in self._runners:
            raise ValueError("Unknown job kind")
        with self._lock:
            if not self._started or self._stopping:
                return False
            if (kind, job_id) in self._pending:
                return True
            self._pending.add((kind, job_id))
        self._queue.put((kind, job_id))
        return True

    def stop(self, timeout: float = SHUTDOWN_GRACE_SECONDS) -> bool:
        """Stop accepting work and wait for the running job. True if it finished."""
        with self._lock:
            if not self._started:
                return True
            already = self._stopping
            self._stopping = True
            running = self._current
        self._stop_event.set()
        if not already:
            self._queue.put(_STOP)
        self._worker.join(timeout)
        self._supervisor.join(2)
        finished = not self._worker.is_alive()
        if not finished and running is not None:
            logger.warning(
                "Shutting down while %s %s is still running; its row stays RUNNING"
                " and is retried after restart",
                running.kind,
                running.job_id,
            )
        return finished

    @property
    def alive(self) -> bool:
        return self._started and self._worker.is_alive() and self._supervisor.is_alive()

    def current(self) -> tuple[str, UUID] | None:
        with self._lock:
            return (self._current.kind, self._current.job_id) if self._current else None

    # --------------------------------------------------------------- worker

    def _work(self) -> None:
        while True:
            try:
                item = self._queue.get()
                if item is _STOP:
                    return
                self._execute(*item)
            except SoftTimeLimitExceeded:
                # A limit that fired as its job was returning. The job is over;
                # the loop must survive.
                continue
            except Exception as exc:  # never let the only worker thread die
                logger.error("Job runner error (%s)", type(exc).__name__)

    def _execute(self, kind: str, job_id: UUID) -> None:
        with self._lock:
            self._pending.discard((kind, job_id))
            if self._stopping:
                return  # Left in PostgreSQL for the next process.
            soft, hard = self._time_limits[kind]
            started = time.monotonic()
            running = _Running(kind, job_id, threading.get_ident(), started + soft, started + hard)
            self._current = running
        logger.info("Job started: %s %s", kind, job_id)
        outcome = "ended"
        try:
            self._runners[kind](job_id)
        except SoftTimeLimitExceeded:
            outcome = "stopped at its time limit"
        except Exception as exc:
            # As in the Celery tasks: durable state is left for reconciliation and
            # the exception text, which could quote source data, is never logged.
            outcome = f"interrupted ({type(exc).__name__}); reconciliation pending"
        finally:
            try:
                self._release(running)
            except SoftTimeLimitExceeded:
                self._release(running)
        logger.info("Job %s: %s %s (%.1fs)", outcome, kind, job_id, time.monotonic() - started)

    def _release(self, running: _Running) -> None:
        with self._lock:
            if self._current is running:
                self._current = None
            if running.soft_fired:
                # Cancel a limit that was scheduled but not yet delivered, so it
                # cannot surface inside the next job.
                _raise_in_thread(running.thread_id, None)

    # ----------------------------------------------------------- supervisor

    def _supervise(self) -> None:
        next_sweep = time.monotonic()  # First sweep right after startup: recovery.
        while not self._stop_event.wait(self._poll_interval):
            try:
                self._enforce_limits()
                if time.monotonic() >= next_sweep:
                    next_sweep = time.monotonic() + self._sweep_interval
                    self._sweep()
            except Exception as exc:
                logger.error("Job supervisor error (%s)", type(exc).__name__)

    def _enforce_limits(self) -> None:
        fired = None
        with self._lock:
            running = self._current
            if running is None:
                return
            now = time.monotonic()
            if not running.soft_fired and now >= running.soft_deadline:
                running.soft_fired = True
                _raise_in_thread(running.thread_id, SoftTimeLimitExceeded)
                fired = "soft"
            elif running.soft_fired and not running.hard_fired and now >= running.hard_deadline:
                running.hard_fired = True
                fired = "hard"
        if fired == "soft":
            logger.warning("Job reached its time limit: %s %s", running.kind, running.job_id)
        elif fired == "hard":
            self._on_hard_timeout(running.kind, running.job_id)

    def _sweep(self) -> None:
        for sweeper in self._sweepers:
            if self._stop_event.is_set():
                return
            try:
                sweeper()
            except Exception as exc:
                # Usually a database blip. Rows are untouched; the next sweep retries.
                logger.warning("Job sweep skipped (%s)", type(exc).__name__)


_runner: InlineJobRunner | None = None
_runner_lock = threading.Lock()


def start() -> InlineJobRunner:
    """Start the process-wide runner (idempotent)."""
    global _runner
    with _runner_lock:
        if _runner is None or not _runner.alive:
            _runner = InlineJobRunner()
            _runner.start()
            logger.info(
                "Jobs run in-process: one worker thread, sweep every %ds, no Redis or Celery",
                int(SWEEP_INTERVAL_SECONDS),
            )
        return _runner


def stop(timeout: float = SHUTDOWN_GRACE_SECONDS) -> bool:
    global _runner
    with _runner_lock:
        runner, _runner = _runner, None
    return runner.stop(timeout) if runner is not None else True


def submit(kind: str, job_id: UUID) -> bool:
    runner = _runner
    return runner.submit(kind, job_id) if runner is not None else False


def status() -> str:
    """Readiness value: "ok" while both runner threads are alive."""
    runner = _runner
    return "ok" if runner is not None and runner.alive else "unavailable"

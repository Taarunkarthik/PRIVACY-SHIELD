"""Bounded, safe benchmark for the local PrivacyShield stack over real HTTP.

It measures API readiness, login, and dashboard latency, then reports the
wall-clock duration of any in-flight or most recent scan, classification, and
deployment job by polling existing endpoints. It never creates jobs and never
prints credentials, session tokens, or source values. When the stack is down it
prints one clear message instead of a traceback.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import statistics
import time
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

from demo_client import DemoClient, ROOT

# Existing endpoints only; the benchmark observes jobs, it never creates them.
JOBS: dict[str, dict[str, object]] = {
    "scan": {
        "list": "/scans?page=1&page_size=10",
        "item": "/scans/{id}",
        "active": {"QUEUED", "RUNNING"},
        "done": {"COMPLETED", "FAILED", "CANCELLED"},
    },
    "classification": {
        "list": "/classification-jobs?page=1&page_size=10",
        "item": "/classification-jobs/{id}",
        "active": {"QUEUED", "RUNNING"},
        "done": {"COMPLETED", "PARTIAL", "FAILED"},
    },
    "deployment": {
        # There is no single-deployment endpoint, so in-flight jobs are followed via the list.
        "list": "/deployments?page=1&page_size=10",
        "item": None,
        "active": {"QUEUED", "RUNNING", "RECONCILING"},
        "done": {"COMPLETED", "FAILED"},
    },
}


class ServiceDown(RuntimeError):
    """Raised when the API cannot be reached at all."""


def measure_readiness(base_url: str, samples: int, timeout: float) -> tuple[list[float], list[int]]:
    url = f"{base_url}/api/v1/health/ready"
    latencies: list[float] = []
    statuses: list[int] = []
    for _ in range(samples):
        request = urlrequest.Request(url, headers={"Accept": "application/json"})
        started = time.perf_counter()
        try:
            with urlrequest.urlopen(request, timeout=timeout) as response:
                code = response.status
                response.read()
        except urlerror.HTTPError as exc:
            # 503 is a reachable but degraded readiness result, not a transport failure.
            code = exc.code
            exc.read()
        except (urlerror.URLError, OSError):
            raise ServiceDown(base_url) from None
        latencies.append(time.perf_counter() - started)
        statuses.append(code)
    return latencies, statuses


def report(label: str, seconds: list[float]) -> None:
    ordered = sorted(value * 1000 for value in seconds)
    print(
        f"{label}: {len(ordered)} sample(s) | min {ordered[0]:.1f} ms | "
        f"median {statistics.median(ordered):.1f} ms | max {ordered[-1]:.1f} ms | "
        f"mean {statistics.fmean(ordered):.1f} ms",
        flush=True,
    )


def parse_time(value: object) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def duration_seconds(job: dict) -> float | None:
    started = parse_time(job.get("started_at") or job.get("created_at"))
    finished = parse_time(job.get("finished_at"))
    if started is None or finished is None:
        return None
    delta = (finished - started).total_seconds()
    return delta if delta >= 0 else None


def report_job(
    client: DemoClient,
    kind: str,
    config: dict[str, object],
    wait_seconds: float,
    poll_seconds: float,
) -> None:
    active = config["active"]
    done = config["done"]
    listing = client.request("GET", config["list"])
    items = listing.get("items", []) if isinstance(listing, dict) else []

    in_flight = [item for item in items if item.get("status") in active]
    if in_flight:
        job_id = in_flight[0]["id"]
        print(f"{kind}: following an in-flight job {str(job_id)[:8]}…", flush=True)
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if config["item"]:
                job = client.request("GET", str(config["item"]).format(id=job_id))
            else:
                refreshed = client.request("GET", config["list"])
                job = next((item for item in refreshed.get("items", []) if item["id"] == job_id), None)
            if job is None:
                break
            if job.get("status") in done:
                elapsed = duration_seconds(job)
                measured = f"{elapsed:.2f}s" if elapsed is not None else "an unknown duration"
                print(f"{kind}: in-flight job finished {job['status']} in {measured}", flush=True)
                return
            time.sleep(poll_seconds)
        print(f"{kind}: in-flight job still running after {wait_seconds:.0f}s; not counted", flush=True)
        return

    finished = []
    for item in items:
        if item.get("status") in done:
            observed = duration_seconds(item)
            if observed is not None:
                finished.append((item, observed))
    if finished:
        newest, observed = finished[0]
        print(
            f"{kind}: most recent {str(newest['status']).lower()} job took "
            f"{observed:.2f}s (observed from timestamps)",
            flush=True,
        )
    else:
        print(f"{kind}: no existing jobs found; skipped (nothing was created)", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password-file", type=Path, default=ROOT / ".secrets/admin-password.txt")
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--samples", type=int, default=5, help="latency samples per endpoint (1-50)")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    parser.add_argument("--wait-seconds", type=float, default=60.0, help="max seconds to follow one in-flight job")
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="poll interval for in-flight jobs")
    args = parser.parse_args()
    if not 1 <= args.samples <= 50:
        parser.error("--samples must be between 1 and 50")
    if args.timeout <= 0 or args.wait_seconds < 0 or args.poll_seconds <= 0:
        parser.error("timeouts and poll intervals must be positive")
    base_url = args.base_url.rstrip("/")

    try:
        readiness, statuses = measure_readiness(base_url, args.samples, args.timeout)
    except ServiceDown:
        print(
            f"PrivacyShield API is not reachable at {base_url}. "
            "Start the local stack (for example, `docker compose up -d`) and retry.",
            flush=True,
        )
        return 1
    report("Readiness latency", readiness)
    degraded = sum(1 for code in statuses if code != 200)
    if degraded:
        print(
            f"Readiness returned a non-200 status {degraded} time(s); "
            "the API is up but a dependency may be degraded.",
            flush=True,
        )

    try:
        started = time.perf_counter()
        client = DemoClient(args.email, args.password_file, base_url)
        login_seconds = time.perf_counter() - started
    except (RuntimeError, OSError) as exc:
        print(f"Login failed: {exc}. Check the account and password file, then retry.", flush=True)
        return 1

    try:
        print(f"Login latency: {login_seconds * 1000:.1f} ms for one authentication round trip", flush=True)
        dashboard: list[float] = []
        for _ in range(args.samples):
            started = time.perf_counter()
            client.request("GET", "/dashboard/summary")
            dashboard.append(time.perf_counter() - started)
        report("Dashboard latency", dashboard)

        for kind, config in JOBS.items():
            try:
                report_job(client, kind, config, args.wait_seconds, args.poll_seconds)
            except RuntimeError as exc:
                print(f"{kind}: skipped ({exc})", flush=True)
    finally:
        try:
            client.close()
        except RuntimeError:
            pass

    print("Benchmark complete. No jobs or credentials were created or printed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

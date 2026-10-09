"""Run the synthetic demo through the HTTP API and real background scan worker."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from demo_client import DemoClient, ROOT, register_target


def results_for(client: DemoClient, job_id: str) -> list[dict]:
    results = []
    for page in range(1, 1001):
        response = client.request("GET", f"/scans/{job_id}/results?page={page}&page_size=100")
        results.extend(response["items"])
        if len(results) >= response["total"]:
            return results
    raise RuntimeError("Result pagination exceeded the demo's safety bound")


def run_scan(client: DemoClient, sample_limit: int = 100, timeout: int = 240) -> dict:
    connection = register_target(client)
    snapshot = client.request("POST", f"/connections/{connection['id']}/discover",
                              {"schemas": ["enterprise"]})
    job = client.request("POST", "/scans", {
        "connection_id": connection["id"], "snapshot_id": snapshot["snapshot_id"],
        "sample_limit": sample_limit,
    })
    started = time.monotonic()
    deadline = started + timeout
    previous_status = None
    while time.monotonic() < deadline:
        job = client.request("GET", f"/scans/{job['id']}")
        if job["status"] != previous_status:
            print(f"Scan {job['id']}: {job['status']}", flush=True)
            previous_status = job["status"]
        if job["status"] == "COMPLETED":
            rows = results_for(client, job["id"])
            assert rows, "Completed scan must contain sampled column results"
            assert all(0 <= row["matching_rows"] <= row["sampled_rows"] <= sample_limit
                       for row in rows), "Sample bounds violated"
            encoded = json.dumps(rows)
            # Known fabricated fixtures only, never print a failed response body.
            for fixture in ("customer1@example.com", "alternate1@example.org", "ABCDE0001F",
                            "2345 6789 0001", "Please contact customer"):
                assert fixture not in encoded, "Raw synthetic sample leaked in results"
            categories = {category for row in rows for category in row["category_counts"]}
            assert {"EMAIL_ADDRESS", "PAN_CANDIDATE", "AADHAAR_CANDIDATE"} <= categories, \
                "Expected email, PAN candidate, and Aadhaar candidate findings"
            assert any(row["json_path"] and row["matching_rows"] for row in rows), \
                "Expected bounded JSON-path findings"
            assert any(row["table_name"] == "support_records" and row["matching_rows"]
                       for row in rows), "Expected free-text findings"
            print(f"PASS: {len(rows)} sampled column/path results; "
                  f"{len(categories)} categories; {time.monotonic() - started:.1f}s")
            print("PASS: scalar, JSONB and free-text findings; no raw fixture samples returned")
            return {"job": job, "results": rows, "connection": connection}
        if job["status"] in {"FAILED", "CANCELLED"}:
            raise RuntimeError(f"Scan ended with {job['status']}; review its sanitized status in the app")
        time.sleep(2)
    raise RuntimeError("Scan is still pending after the demo timeout; check the durable job in the app")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password-file", type=Path, default=ROOT / ".secrets/admin-password.txt")
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--sample-limit", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.sample_limit <= 10000:
        parser.error("sample-limit must be between 1 and 10000")
    with DemoClient(args.email, args.password_file, args.base_url) as client:
        run_scan(client, args.sample_limit)


if __name__ == "__main__":
    main()

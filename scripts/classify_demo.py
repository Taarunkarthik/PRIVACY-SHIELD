"""Classify a synthetic email finding through the API and real local Ollama worker."""
from __future__ import annotations

import argparse
from pathlib import Path
import time
from uuid import UUID

from demo_client import DemoClient, ROOT
from scan_demo import results_for, run_scan


def run_classification(client: DemoClient, scan_id: str, timeout: int = 300) -> dict:
    rows = results_for(client, scan_id)
    email = next((row for row in rows if row["schema_name"] == "enterprise"
                  and row["table_name"] == "customers" and row["column_name"] == "email"
                  and not row["json_path"] and row["category_counts"].get("EMAIL_ADDRESS")), None)
    if email is None:
        raise RuntimeError("Run the synthetic scan first; an email finding is required")
    job = client.request("POST", f"/scans/{scan_id}/classify", {"result_ids": [email["id"]]})
    started = time.monotonic()
    previous = None
    while time.monotonic() - started < timeout:
        job = client.request("GET", f"/classification-jobs/{job['id']}")
        if job["status"] != previous:
            print(f"Classification {job['id']}: {job['status']}", flush=True)
            previous = job["status"]
        if job["status"] == "COMPLETED":
            response = client.request("GET", f"/classifications?job_id={job['id']}&page_size=100")
            assert response["total"] == 1 and len(response["items"]) == 1
            decision = response["items"][0]
            assert decision["scan_result_id"] == email["id"]
            assert decision["category"] == "EMAIL_ADDRESS"
            assert decision["recommendation"] != "KEEP"
            assert decision["requires_approval"] is True
            assert decision["model"] == "qwen2.5:1.5b"
            assert 0 <= decision["confidence"] <= 1 and decision["reason"]
            print(f"PASS: real {decision['model']} email recommendation in "
                  f"{time.monotonic() - started:.1f}s; explicit human approval required")
            return {"job": job, "decision": decision}
        if job["status"] in {"PARTIAL", "FAILED"}:
            raise RuntimeError(f"AI check ended with {job['status']} ({job['error_code']}); "
                               "scan findings remain available for manual review")
        time.sleep(2)
    raise RuntimeError("Classification is still pending; inspect its durable job in the app")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password-file", type=Path, default=ROOT / ".secrets/admin-password.txt")
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--scan-id", type=UUID, help="Reuse a completed synthetic scan")
    args = parser.parse_args()
    with DemoClient(args.email, args.password_file, args.base_url) as client:
        scan_id = str(args.scan_id) if args.scan_id else run_scan(client, sample_limit=10)["job"]["id"]
        run_classification(client, scan_id)


if __name__ == "__main__":
    main()

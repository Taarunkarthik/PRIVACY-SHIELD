"""Create, approve, and deploy a masking policy through the HTTP API and real worker.

The API records the plan; a separate worker performs the target-side DDL. This
script drives the control plane only and never prints row values or credentials.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import time

from demo_client import DemoClient, ROOT, register_target

# Deterministic protection for the synthetic customers table. Unlisted columns
# (id, profile, created_at) become typed NULL by contract.
DEMO_RULES = [
    {"column_name": "full_name", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
    {"column_name": "email", "action": "PSEUDONYMIZE", "pseudonym_domain": "demo"},
    {"column_name": "phone", "action": "NULLIFY"},
    {"column_name": "pan", "action": "NULLIFY"},
    {"column_name": "aadhaar", "action": "NULLIFY"},
    {"column_name": "address", "action": "REDACT"},
]


def deploy_policy(client: DemoClient, connection: dict, timeout: int = 180) -> dict:
    snapshot = client.request(
        "POST", f"/connections/{connection['id']}/discover", {"schemas": ["enterprise"]}
    )
    customers = next(
        table for table in snapshot["catalog"]["tables"] if table["name"] == "customers"
    )
    policy = client.request("POST", "/policies", {
        "connection_id": connection["id"],
        "schema_name": "enterprise",
        "table_name": "customers",
        "snapshot_id": snapshot["snapshot_id"],
        "rules": DEMO_RULES,
    })
    print(f"Policy {policy['id']}: {policy['status']} (v{policy['version']})", flush=True)

    policy = client.request("POST", f"/policies/{policy['id']}/submit")
    assert policy["status"] == "PENDING_APPROVAL"
    policy = client.request("POST", f"/policies/{policy['id']}/approve")
    assert policy["status"] == "APPROVED" and policy["compiled_plan_fingerprint"]

    preview = client.request("GET", f"/policies/{policy['id']}/preview")
    assert preview["view_schema"] == "privacyshield_masked"
    assert "security_barrier = true" in preview["sql"]
    assert all(column["source_column"] for column in preview["columns"])
    print(
        f"Preview view: {preview['view_schema']}.{preview['view_name']} "
        f"({len(preview['columns'])} columns, explicit decisions)",
        flush=True,
    )

    deployment = client.request("POST", f"/policies/{policy['id']}/deploy", {})
    started = time.monotonic()
    previous = None
    while time.monotonic() - started < timeout:
        status = client.request("GET", f"/policies/{policy['id']}")
        if status["status"] != previous:
            print(f"Deployment {deployment['id']}: {status['status']}", flush=True)
            previous = status["status"]
        if status["status"] == "DEPLOYED":
            print(
                f"PASS: approved policy deployed in {time.monotonic() - started:.1f}s; "
                "the restricted reader now sees only the compiled view",
                flush=True,
            )
            return {"policy": status, "preview": preview, "deployment": deployment}
        if status["status"] == "FAILED":
            raise RuntimeError("Deployment failed; review its bounded error code in the app")
        time.sleep(2)
    raise RuntimeError("Deployment is still pending; inspect its durable record in the app")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password-file", type=Path, default=ROOT / ".secrets/admin-password.txt")
    parser.add_argument("--base-url", default="http://localhost:8080")
    args = parser.parse_args()
    with DemoClient(args.email, args.password_file, args.base_url) as client:
        connection = register_target(client)
        deploy_policy(client, connection)


if __name__ == "__main__":
    main()

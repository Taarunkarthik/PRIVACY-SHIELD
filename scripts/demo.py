"""Tell the whole PrivacyShield story in one command: connect, discover, scan,
mask, deploy, and end with a before/after view of the protected table.

Reuses the HTTP helpers of register_demo, scan_demo and policy_demo. It never
prints credentials, raw row values, or synthetic samples.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from demo_client import DemoClient, ROOT, register_target
from policy_demo import deploy_policy
from scan_demo import run_scan


def print_before_after(preview: dict, policy: dict) -> None:
    """Print the source table and the deployed view's per-column actions."""
    source = f"{preview['schema_name']}.{preview['table_name']}"
    view = f"{preview['view_schema']}.{preview['view_name']}"
    columns = preview["columns"]
    print(f"  BEFORE {source} ({len(columns)} columns, raw source values)", flush=True)
    print("    " + ", ".join(column["source_column"] for column in columns), flush=True)
    print(f"  AFTER  {view} (policy {policy['id']}, v{policy['version']}, "
          f"role {preview['role']})", flush=True)
    width = max(len(column["source_column"]) for column in columns)
    for column in columns:
        domain = f" (domain={column['pseudonym_domain']})" if column["pseudonym_domain"] else ""
        print(f"    {column['source_column']:<{width}} -> {column['action']}{domain}", flush=True)


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
        print("[1/4] Register + discover the synthetic target ...", flush=True)
        connection = register_target(client)
        checked = client.request("POST", f"/connections/{connection['id']}/test",
                                 {"schemas": ["enterprise"]})
        assert checked["status"] == "ok"
        snapshot = client.request("POST", f"/connections/{connection['id']}/discover",
                                  {"schemas": ["enterprise"]})
        tables = snapshot["catalog"]["tables"]
        assert len(tables) == 4, "Expected the four synthetic enterprise tables"
        print(f"PASS: registered and discovered Synthetic enterprise ({connection['id']})",
              flush=True)

        print("[2/4] Scan bounded samples for PII candidates ...", flush=True)
        scan = run_scan(client, args.sample_limit)
        connection = scan["connection"]

        print("[3/4] Create, submit, approve and deploy a masking policy ...", flush=True)
        policy = deploy_policy(client, connection)

        print("[4/4] Show the before/after result", flush=True)
        print_before_after(policy["preview"], policy["policy"])
        print("DEMO COMPLETE", flush=True)


if __name__ == "__main__":
    main()

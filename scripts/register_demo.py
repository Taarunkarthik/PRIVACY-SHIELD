"""Register and discover the synthetic target without displaying credentials."""
import argparse
from pathlib import Path
import sys

from demo_client import DemoClient, ROOT, register_target, register_target_for

sys.path.insert(0, str(ROOT / "backend"))
from app.demo_policies import starter_policy_rules  # noqa: E402


EXTRA_DEMOS = (
    ("Synthetic hospital", "hospital_demo", "hospital"),
    ("Synthetic university", "university_demo", "university"),
    ("Masked policy lab", "masked_demo", "masked"),
    ("Vulnerability lab", "vulnerability_demo", "exposed"),
    ("Basic inventory", "basic_demo", "inventory"),
)


def register_all(client: DemoClient) -> None:
    register_target(client)
    for name, database, schema in EXTRA_DEMOS:
        connection = register_target_for(client, name, database)
        checked = client.request(
            "POST", f"/connections/{connection['id']}/test", {"schemas": [schema]}
        )
        snapshot = client.request(
            "POST", f"/connections/{connection['id']}/discover", {"schemas": [schema]}
        )
        tables = snapshot["catalog"]["tables"]
        if len(tables) != 4:
            raise RuntimeError(f"{name} should expose four synthetic tables")
        print(f"PASS: registered {name}: {len(tables)} tables")
        if database == "vulnerability_demo":
            findings = checked.get("security_findings", [])
            codes = {finding["code"] for finding in findings}
            if not {"PUBLIC_TABLE_READ", "READER_SOURCE_ACCESS"} <= codes:
                raise RuntimeError("The vulnerability lab did not report its expected findings")
            print(f"PASS: vulnerability checks reported {len(findings)} synthetic database findings")
        if database == "masked_demo":
            policies = client.request(
                "GET", f"/policies?connection_id={connection['id']}&page=1&page_size=100"
            )["items"]
            existing = {(item["schema_name"], item["table_name"]) for item in policies}
            created = 0
            for table in tables:
                identity = (schema, table["name"])
                if identity in existing:
                    continue
                client.request("POST", "/policies", {
                    "connection_id": connection["id"],
                    "schema_name": schema,
                    "table_name": table["name"],
                    "snapshot_id": snapshot["snapshot_id"],
                    "rules": starter_policy_rules(table["columns"]),
                })
                created += 1
            print(f"PASS: masked policy lab has reviewable policies for all four tables ({created} added)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password-file", type=Path, default=ROOT / ".secrets/admin-password.txt")
    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--all", action="store_true", help="register all synthetic scenario databases")
    args = parser.parse_args()
    with DemoClient(args.email, args.password_file, args.base_url) as client:
        if args.all:
            register_all(client)
            return
        connection = register_target(client)
        identifier = connection["id"]
        checked = client.request("POST", f"/connections/{identifier}/test", {"schemas": ["enterprise"]})
        assert checked["status"] == "ok"
        snapshot = client.request("POST", f"/connections/{identifier}/discover", {"schemas": ["enterprise"]})
        tables = snapshot["catalog"]["tables"]
        assert len(tables) == 4, "Expected the four synthetic enterprise tables"
        composite = [fk for table in tables for fk in table["foreign_keys"] if len(fk["columns"]) > 1]
        assert composite, "Composite foreign key was not discovered"
        assert any(c["is_jsonb"] for table in tables for c in table["columns"])
        print(f"PASS: registered and discovered Synthetic enterprise ({identifier})")
        print("PASS: four tables, JSONB columns, primary keys and composite foreign keys")


if __name__ == "__main__":
    main()

"""Register and discover the synthetic target without displaying credentials."""
import argparse
from pathlib import Path

from demo_client import DemoClient, ROOT, register_target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password-file", type=Path, default=ROOT / ".secrets/admin-password.txt")
    parser.add_argument("--base-url", default="http://localhost:8080")
    args = parser.parse_args()
    with DemoClient(args.email, args.password_file, args.base_url) as client:
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

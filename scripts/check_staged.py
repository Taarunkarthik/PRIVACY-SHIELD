"""Reject secret files and known local secret values from Git's index."""
from pathlib import Path
from io import BytesIO
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
)


def main() -> None:
    indexed = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=ROOT).decode()
    entries = []
    for record in filter(None, indexed.split("\0")):
        metadata, name = record.split("\t", 1)
        _, oid, stage = metadata.split()
        if stage != "0":
            raise SystemExit(f"Unresolved index entry: {name}")
        entries.append((name, oid))
    objects = subprocess.check_output(
        ["git", "cat-file", "--batch"],
        input="".join(oid + "\n" for _, oid in entries).encode(), cwd=ROOT,
    )
    object_stream = BytesIO(objects)
    local_secrets = []
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                if any(word in key for word in ("PASSWORD", "SECRET", "KEY")) and len(value) >= 12:
                    local_secrets.append(value.encode())
    failures = []
    for name, _ in entries:
        _, kind, length = object_stream.readline().split()
        if kind != b"blob":
            raise SystemExit(f"Unexpected non-file index entry: {name}")
        content = object_stream.read(int(length))
        object_stream.read(1)
        path = Path(name)
        forbidden = ((path.name == ".env" or path.name.startswith(".env."))
                     and path.name != ".env.example")
        forbidden |= any(part in {".secrets", ".venv", "node_modules", ".local"} for part in path.parts)
        forbidden |= path.suffix in {".pem", ".key", ".dump", ".backup"}
        if forbidden:
            failures.append(f"Forbidden tracked path: {name}")
            continue
        if any(secret in content for secret in local_secrets) or any(p.search(content) for p in PATTERNS):
            failures.append(f"Potential secret in staged content: {name}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"PASS: checked {len(entries)} indexed files for forbidden paths and secret patterns")


if __name__ == "__main__":
    main()

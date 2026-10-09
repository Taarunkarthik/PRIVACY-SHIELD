"""Reproducible foundation gate; integration uses a separate test database."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str], label: str, *, env=None, capture=False, cwd=ROOT):
    print(f"\n{label}", flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=capture)
    if result.returncode:
        if capture:
            print("Command failed; sensitive captured output was withheld.", file=sys.stderr)
        raise SystemExit(result.returncode)
    return result.stdout.strip() if capture else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration", action="store_true")
    parser.add_argument("--frontend", action="store_true", help="Also test and build frontend on host")
    args = parser.parse_args()
    if not (ROOT / ".env").exists():
        raise SystemExit("Run python scripts/setup.py first.")
    config = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line)
    env = os.environ | config
    compose = ["docker", "compose"]
    run(compose + ["config", "--quiet"], "Validate Compose configuration")
    run(compose + ["exec", "-T", "api", "ruff", "check", "."], "Backend lint")
    run(compose + ["exec", "-T", "api", "python", "-m", "pytest", "-q", "-m", "not integration"],
        "Backend unit tests")
    if args.integration:
        exists = run(compose + ["exec", "-T", "control-db", "psql", "-U", "postgres", "-d", "postgres",
                               "-tAc", "SELECT 1 FROM pg_database WHERE datname='privacyshield_test'"],
                     "Check isolated test database", capture=True)
        if exists != "1":
            run(compose + ["exec", "-T", "control-db", "psql", "-U", "postgres", "-d", "postgres",
                           "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE privacyshield_test OWNER ps_migrator"],
                "Create isolated test database")
        run(compose + ["exec", "-T", "control-db", "psql", "-U", "postgres", "-d", "privacyshield_test",
                       "-v", "ON_ERROR_STOP=1", "-c",
                       "REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO ps_app;"],
            "Prepare test role access")
        env["DATABASE_URL"] = f"postgresql+psycopg://ps_app:{quote(config['APP_DATABASE_PASSWORD'], safe='')}@control-db:5432/privacyshield_test"
        env["MIGRATION_DATABASE_URL"] = f"postgresql+psycopg://ps_migrator:{quote(config['MIGRATOR_PASSWORD'], safe='')}@control-db:5432/privacyshield_test"
        env.update(TEST_TARGET_HOST="target-db", TEST_TARGET_PORT="5432",
                   TARGET_ALLOWED_HOSTS='["target-db"]',
                   TEST_TARGET_SCANNER_PASSWORD=config["SCANNER_PASSWORD"],
                   TEST_TARGET_DEPLOYER_PASSWORD=config["DEPLOYER_PASSWORD"],
                   TEST_TARGET_SUPERUSER_PASSWORD=config["TARGET_POSTGRES_PASSWORD"])
        test_env_names = ["DATABASE_URL", "MIGRATION_DATABASE_URL", "TARGET_ALLOWED_HOSTS",
                          "TEST_TARGET_HOST", "TEST_TARGET_PORT", "TEST_TARGET_SCANNER_PASSWORD",
                          "TEST_TARGET_DEPLOYER_PASSWORD", "TEST_TARGET_SUPERUSER_PASSWORD"]
        isolated = compose + ["run", "--rm", "-T", "--no-deps"]
        for name in test_env_names:
            isolated.extend(["-e", name])
        isolated.append("migrate")
        run(isolated + ["alembic", "upgrade", "head"], "Migrate isolated test database", env=env)
        run(isolated + ["alembic", "check"], "Check models agree with migrations", env=env)
        run(isolated + ["python", "-m", "pytest", "-q", "-m", "integration"],
            "Real PostgreSQL and Redis integration tests", env=env)
        smoke = "from app.workers.celery_app import celery_app; r=celery_app.send_task('privacyshield.smoke',args=['foundation']); assert r.get(timeout=30)=={'status':'ok','message':'foundation'}; print('PASS: real Celery worker completed task using PostgreSQL'); r.forget()"
        run(compose + ["exec", "-T", "api", "python", "-c", smoke], "Real worker smoke test")
        run(compose + ["run", "--rm", "-T", "--no-deps", "-e", "SCANNER_PASSWORD", "-e", "READER_PASSWORD",
                       "-v", f"{ROOT / 'scripts'}:/checks:ro", "migrate", "python", "/checks/check_target.py"],
            "Real target database role boundaries", env=env)
    if args.frontend:
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not npm:
            raise SystemExit("Node 24/npm required for --frontend")
        for command in (["ci"], ["run", "typecheck"], ["test"], ["run", "build"]):
            run([npm, *command], "Frontend " + " ".join(command), cwd=ROOT / "frontend")
    print("\nAll requested checks passed.")


if __name__ == "__main__":
    main()

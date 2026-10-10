"""Reproducible gate with an isolated PostgreSQL database and Linux task worker."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
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
                   CELERY_QUEUE="privacyshield-check-" + uuid.uuid4().hex,
                   TEST_TARGET_SCANNER_PASSWORD=config["SCANNER_PASSWORD"],
                   TEST_TARGET_DEPLOYER_PASSWORD=config["DEPLOYER_PASSWORD"],
                   TEST_TARGET_READER_PASSWORD=config["READER_PASSWORD"],
                   TEST_TARGET_SUPERUSER_PASSWORD=config["TARGET_POSTGRES_PASSWORD"])
        ollama_name = "privacyshield-check-ollama-" + uuid.uuid4().hex[:12]
        env["OLLAMA_BASE_URL"] = f"http://{ollama_name}:11434"
        env["TEST_OLLAMA_BASE_URL"] = env["OLLAMA_BASE_URL"]
        test_env_names = ["DATABASE_URL", "MIGRATION_DATABASE_URL", "TARGET_ALLOWED_HOSTS",
                          "CELERY_QUEUE", "OLLAMA_BASE_URL", "TEST_OLLAMA_BASE_URL",
                          "TEST_TARGET_HOST", "TEST_TARGET_PORT", "TEST_TARGET_SCANNER_PASSWORD",
                          "TEST_TARGET_DEPLOYER_PASSWORD", "TEST_TARGET_READER_PASSWORD",
                          "TEST_TARGET_SUPERUSER_PASSWORD"]
        isolated = compose + ["run", "--rm", "-T", "--no-deps"]
        for name in test_env_names:
            isolated.extend(["-e", name])
        isolated.append("migrate")
        run(isolated + ["alembic", "upgrade", "head"], "Migrate isolated test database", env=env)
        run(isolated + ["alembic", "check"], "Check models agree with migrations", env=env)
        # A separate queue and process ensure API-submitted test jobs never reach
        # the application's worker (which uses the application's database).
        worker_name = "privacyshield-check-worker-" + uuid.uuid4().hex[:12]
        worker_args = compose + ["run", "--rm", "-T", "--no-deps", "-d", "--name", worker_name,
                      "-e", "DATABASE_URL", "-e", "CELERY_QUEUE", "-e", "TARGET_ALLOWED_HOSTS",
                      "-e", "OLLAMA_BASE_URL", "worker",
                      "celery", "-A", "app.workers.celery_app:celery_app", "worker",
                      "--loglevel=WARNING", "--concurrency=1", "--beat",
                      "--schedule=/tmp/privacyshield-test-beat"]
        try:
            run(compose + ["run", "--rm", "-T", "--no-deps", "-d", "--name", ollama_name,
                           "migrate", "python", "/app/tests/support/fake_ollama.py"],
                "Start controlled HTTP Ollama double (real model checked separately)", capture=True)
            run(worker_args, "Start isolated real Linux test worker", env=env, capture=True)
            ready = "from app.workers.celery_app import celery_app; r=celery_app.send_task('privacyshield.smoke',args=['isolated-check']); assert r.get(timeout=45)=={'status':'ok','message':'isolated-check'}; r.forget(); print('PASS: isolated worker ready')"
            run(isolated + ["python", "-c", ready], "Wait for isolated worker", env=env)
            run(isolated + ["python", "-m", "pytest", "-q", "-m", "integration"],
                "Real PostgreSQL and Redis integration tests", env=env)
        finally:
            print("Stop isolated test worker and controlled HTTP double", flush=True)
            # Auto-removed workers may already be absent after a failed startup.
            # Do not replace the original test failure with a cleanup traceback.
            for container_name in (worker_name, ollama_name):
                stopped = subprocess.run(["docker", "stop", "--time", "10", container_name],
                                     cwd=ROOT, capture_output=True, text=True)
                if stopped.returncode:
                    remaining = subprocess.run(["docker", "inspect", container_name],
                                           cwd=ROOT, capture_output=True, text=True)
                    if remaining.returncode == 0:
                        raise RuntimeError("Could not stop an isolated test container")
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

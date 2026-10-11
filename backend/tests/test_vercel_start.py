"""The Vercel start wrapper: environment mapping only, checked without Vercel.

The wrapper ends by running the single-service start script. Here that script
is replaced by one that prints the environment it was given, so these tests
show exactly what the real one would receive. Nothing in this file shows that
the image runs on Vercel; see docs/deploy-vercel.md.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
WRAPPER = BACKEND_ROOT / "scripts" / "vercel" / "start.sh"
OWNER_URL = "postgresql://neondb_owner:Own3rPassw0rd@ep-demo-123.us-east-1.aws.neon.tech/neondb"
POOLED_URL = OWNER_URL.replace("ep-demo-123", "ep-demo-123-pooler")
INJECTED = {
    "DATABASE_URL": POOLED_URL,
    "DATABASE_URL_UNPOOLED": OWNER_URL,
    "POSTGRES_URL": POOLED_URL,
    "POSTGRES_URL_NON_POOLING": OWNER_URL,
    "POSTGRES_PRISMA_URL": POOLED_URL,
    "POSTGRES_URL_NO_SSL": POOLED_URL,
    "POSTGRES_USER": "neondb_owner",
    "POSTGRES_PASSWORD": "Own3rPassw0rd",
    "POSTGRES_HOST": "ep-demo-123-pooler.us-east-1.aws.neon.tech",
    "POSTGRES_DATABASE": "neondb",
    "PGHOST": "ep-demo-123-pooler.us-east-1.aws.neon.tech",
    "PGHOST_UNPOOLED": "ep-demo-123.us-east-1.aws.neon.tech",
    "PGUSER": "neondb_owner",
    "PGPASSWORD": "Own3rPassw0rd",
    "PGDATABASE": "neondb",
    "NEON_PROJECT_ID": "demo-project",
}

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")


@pytest.fixture
def run(tmp_path):
    """Run the wrapper with a stand-in for start-all.sh that prints its environment."""
    scripts = tmp_path / "scripts"
    (scripts / "vercel").mkdir(parents=True)
    (scripts / "render").mkdir()
    shutil.copy(WRAPPER, scripts / "vercel" / "start.sh")
    (scripts / "render" / "start-all.sh").write_text("#!/bin/sh\necho HANDED-OVER\nenv\n")

    def _run(variables: dict[str, str], home: str | None = None):
        env = {"PATH": os.environ["PATH"], "HOME": home or str(tmp_path)} | variables
        result = subprocess.run(
            ["sh", str(scripts / "vercel" / "start.sh")],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        handed = {}
        if "HANDED-OVER" in result.stdout:
            for line in result.stdout.split("HANDED-OVER\n", 1)[1].splitlines():
                name, _, value = line.partition("=")
                handed[name] = value
        return result, handed

    return _run


def test_no_database_stops_with_what_to_do(run):
    result, handed = run({})
    assert result.returncode == 1 and not handed
    assert "ERROR Startup stopped: no database is connected" in result.stderr


def test_a_pooled_url_alone_is_refused_and_never_printed(run):
    result, handed = run({"DATABASE_URL": POOLED_URL, "POSTGRES_URL": POOLED_URL})
    assert result.returncode == 1 and not handed
    assert "only a pooled database URL was found" in result.stderr
    assert "Own3rPassw0rd" not in result.stderr + result.stdout


def test_the_direct_url_is_used_and_every_injected_credential_is_dropped(run):
    result, handed = run(INJECTED | {"APP_SECRET": "s" * 40, "PORT": "10000"})
    assert result.returncode == 0, result.stderr
    assert handed["CONTROL_ADMIN_URL"] == OWNER_URL
    # The only place the owner's password remains is the one variable the
    # bootstrap reads, which the start script unsets before the server starts.
    assert [name for name, value in handed.items() if "Own3rPassw0rd" in value] == [
        "CONTROL_ADMIN_URL"
    ]
    assert not set(INJECTED) & set(handed)
    assert handed["APP_SECRET"] == "s" * 40 and handed["PORT"] == "10000"
    assert "Own3rPassw0rd" not in result.stderr


def test_an_explicit_admin_url_wins_and_the_older_variable_name_is_understood(run):
    explicit = "postgresql://someone:else@db.example.test/main"
    _, handed = run(INJECTED | {"CONTROL_ADMIN_URL": explicit})
    assert handed["CONTROL_ADMIN_URL"] == explicit
    _, handed = run({"POSTGRES_URL": POOLED_URL, "POSTGRES_URL_NON_POOLING": OWNER_URL})
    assert handed["CONTROL_ADMIN_URL"] == OWNER_URL


def test_the_projects_own_addresses_are_allowed_origins(run, monkeypatch):
    vercel = {
        "VERCEL_PROJECT_PRODUCTION_URL": "privacy-shield.vercel.app",
        "VERCEL_BRANCH_URL": "privacy-shield-git-main-team.vercel.app",
        "VERCEL_URL": "privacy-shield.vercel.app",  # The same as production: listed once.
    }
    _, handed = run(INJECTED | vercel)
    assert handed["ALLOWED_ORIGINS"] == (
        '["https://privacy-shield.vercel.app",'
        '"https://privacy-shield-git-main-team.vercel.app"]'
    )
    # The application accepts exactly this form from its environment.
    from cryptography.fernet import Fernet

    from app.core.config import Settings

    monkeypatch.setenv("ALLOWED_ORIGINS", handed["ALLOWED_ORIGINS"])
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://a:b@h/d")
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    assert Settings().allowed_origins == [
        "https://privacy-shield.vercel.app",
        "https://privacy-shield-git-main-team.vercel.app",
    ]


def test_odd_host_values_are_ignored_and_an_explicit_list_is_kept(run):
    odd = {"VERCEL_URL": 'evil.example"],["x', "VERCEL_BRANCH_URL": "a b.vercel.app"}
    _, handed = run(INJECTED | odd)
    assert "ALLOWED_ORIGINS" not in handed
    explicit = '["https://privacy.example.org"]'
    _, handed = run(INJECTED | {"ALLOWED_ORIGINS": explicit, "VERCEL_URL": "x.vercel.app"})
    assert handed["ALLOWED_ORIGINS"] == explicit


def test_without_a_port_it_follows_the_platform_default_and_says_so(run):
    result, handed = run(INJECTED)
    assert handed["PORT"] == "80"
    assert "PORT is not set" in result.stdout and "PORT=10000" in result.stdout


def test_an_unwritable_home_falls_back_to_tmp(run, tmp_path):
    _, handed = run(INJECTED, home="/nonexistent-home")
    assert handed["HOME"] == "/tmp"
    _, handed = run(INJECTED)
    assert handed["HOME"] == str(tmp_path)


def _build_steps(dockerfile: Path) -> str:
    """Everything from the first build stage up to the hand-over to the runtime user."""
    text = dockerfile.read_text()
    return text[text.index("# ---- frontend") : text.index("USER 10001")]


def test_the_vercel_image_is_built_exactly_like_the_single_service_image():
    render, vercel = REPO_ROOT / "Dockerfile", REPO_ROOT / "Dockerfile.vercel"
    assert _build_steps(vercel) == _build_steps(render)
    tail = vercel.read_text().split("USER 10001", 1)[1]
    assert 'CMD ["sh", "/app/scripts/vercel/start.sh"]' in tail
    assert "JOB_RUNNER=inline" in tail and "STATIC_DIR=/app/static" in tail
    assert WRAPPER.is_file()
    # The wrapper hands over to the script that is tested end to end.
    assert 'exec sh "$(dirname "$0")/../render/start-all.sh"' in WRAPPER.read_text()

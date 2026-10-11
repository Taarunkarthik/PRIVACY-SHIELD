"""Hosted bootstrap pieces that need no database: secrets, URLs, the runtime file, origins.

The provisioning SQL itself runs against a real non-superuser in
tests/integration/test_free_hosting.py.
"""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from app import render_bootstrap as bootstrap
from app.api.dependencies import verify_origin
from app.core.config import Settings, get_settings

BACKEND_ROOT = Path(__file__).resolve().parents[1]
needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
APP_SECRET = "unit-test-app-secret-0123456789abcdef"
EXPLICIT = {
    "CREDENTIAL_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "APP_DATABASE_PASSWORD": "explicit-app",
    "MIGRATOR_PASSWORD": "explicit-migrator",
    "SCANNER_PASSWORD": "explicit-scanner",
    "DEPLOYER_PASSWORD": "explicit-deployer",
    "READER_PASSWORD": "explicit-reader",
}


def test_derived_secrets_are_deterministic_distinct_and_usable():
    first = bootstrap.resolve_secrets({"APP_SECRET": APP_SECRET})
    assert first == bootstrap.resolve_secrets({"APP_SECRET": APP_SECRET})
    assert set(first) == set(EXPLICIT)
    assert len(set(first.values())) == len(first)  # a distinct label per secret
    Fernet(first["CREDENTIAL_ENCRYPTION_KEY"].encode())  # a valid Fernet key
    for name, value in first.items():
        if name != "CREDENTIAL_ENCRYPTION_KEY":
            assert len(value) == 64 and int(value, 16) >= 0  # hex: safe in URLs and SQL
        assert APP_SECRET not in value
    other = bootstrap.resolve_secrets({"APP_SECRET": APP_SECRET + "x"})
    assert not set(first.values()) & set(other.values())
    # Surrounding whitespace from a pasted value does not change the result.
    assert bootstrap.resolve_secrets({"APP_SECRET": f"  {APP_SECRET}\n"}) == first


def test_derivation_is_pinned():
    # Changing a label or the construction would silently rotate every deployment's
    # database passwords and make stored credentials undecryptable.
    assert (
        bootstrap.derive_secret("0" * 32, "APP_DATABASE_PASSWORD")
        == "406e8368bb93f9ba77340c5f6d20f35196efe2d4641b14b3b92fe096a1605d01"
    )
    assert (
        bootstrap.derive_secret("0" * 32, "CREDENTIAL_ENCRYPTION_KEY")
        == "b9-Qc2XOHmtMbzrl2K4ODx7wI0z2B5dfWe8my10oPX4="
    )


def test_explicit_values_win_over_derived_ones():
    assert bootstrap.resolve_secrets(EXPLICIT) == EXPLICIT  # no APP_SECRET needed
    mixed = bootstrap.resolve_secrets(
        {"APP_SECRET": APP_SECRET, "SCANNER_PASSWORD": "explicit-scanner", "READER_PASSWORD": ""}
    )
    derived = bootstrap.resolve_secrets({"APP_SECRET": APP_SECRET})
    assert mixed["SCANNER_PASSWORD"] == "explicit-scanner"
    assert mixed["READER_PASSWORD"] == derived["READER_PASSWORD"]  # blank means unset
    assert mixed["DEPLOYER_PASSWORD"] == derived["DEPLOYER_PASSWORD"]


def test_short_or_missing_app_secret_is_rejected_with_instructions():
    with pytest.raises(bootstrap.BootstrapError) as short:
        bootstrap.resolve_secrets({"APP_SECRET": "x" * 31})
    assert "31 characters" in str(short.value) and "at least 32" in str(short.value)
    assert "x" * 31 not in str(short.value)  # the value itself is not echoed
    bootstrap.resolve_secrets({"APP_SECRET": "x" * 32})
    with pytest.raises(bootstrap.BootstrapError, match="Set APP_SECRET"):
        bootstrap.resolve_secrets({})
    incomplete = {k: v for k, v in EXPLICIT.items() if k != "READER_PASSWORD"}
    with pytest.raises(bootstrap.BootstrapError, match="READER_PASSWORD"):
        bootstrap.resolve_secrets(incomplete)
    with pytest.raises(bootstrap.BootstrapError, match="not a valid Fernet key"):
        bootstrap.resolve_secrets({"APP_SECRET": APP_SECRET, "CREDENTIAL_ENCRYPTION_KEY": "abc"})


def test_target_url_is_the_same_server_with_another_database():
    url = "postgresql://admin:p%40ss@dpg-abc123-a:5432/privacyshield?sslmode=require"
    target = bootstrap._with_database(url, "enterprise_demo")
    assert target == "postgresql://admin:p%40ss@dpg-abc123-a:5432/enterprise_demo"
    assert bootstrap._conninfo(target) == {
        "host": "dpg-abc123-a",
        "port": 5432,
        "user": "admin",
        "password": "p@ss",
        "dbname": "enterprise_demo",
    }
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap._conninfo("mysql://x/y")


@pytest.mark.parametrize("separator", ["/", "?", "#"])
def test_a_url_that_cannot_be_read_never_quotes_the_password(separator):
    # urlsplit reports the text it could not read as a port. With an unescaped
    # separator in the password, that text is the start of the password.
    url = f"postgresql://admin:Sup3rS3cretPrefix{separator}rest@db:5432/main"
    with pytest.raises(bootstrap.BootstrapError) as failure:
        bootstrap._conninfo(url)
    message = str(failure.value)
    assert "Sup3rS3cret" not in message and "rest" not in message.replace("Internal", "")
    assert "percent-encode" in message
    assert failure.value.__cause__ is None and failure.value.__suppress_context__


def test_tls_mode_is_validated(monkeypatch):
    monkeypatch.delenv("BOOTSTRAP_DB_SSLMODE", raising=False)
    assert bootstrap._sslmode() == "require"
    monkeypatch.setenv("BOOTSTRAP_DB_SSLMODE", "disable")
    assert bootstrap._sslmode() == "disable"
    monkeypatch.setenv("BOOTSTRAP_DB_SSLMODE", "prefer")
    with pytest.raises(bootstrap.BootstrapError, match="must be one of"):
        bootstrap._sslmode()


def test_runtime_url_uses_the_runtime_role_and_escapes_the_password(monkeypatch):
    monkeypatch.setenv("BOOTSTRAP_DB_SSLMODE", "require")
    url = bootstrap._runtime_url("postgresql://admin:x@db.internal:6543/main", "ps_app", "a/b@c:d")
    assert url == "postgresql+psycopg://ps_app:a%2Fb%40c%3Ad@db.internal:6543/main?sslmode=require"
    Settings(database_url=url, credential_encryption_key=EXPLICIT["CREDENTIAL_ENCRYPTION_KEY"])


def test_single_instance_rejects_a_control_database_named_like_the_target(monkeypatch):
    for name in ("TARGET_ADMIN_URL", *EXPLICIT):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APP_SECRET", APP_SECRET)
    monkeypatch.setenv("CONTROL_ADMIN_URL", "postgresql://admin:x@127.0.0.1:1/enterprise_demo")
    with pytest.raises(bootstrap.BootstrapError, match="reserved for the synthetic demo data"):
        bootstrap.main()  # refused before any connection is attempted


def test_unreachable_database_error_says_what_to_check(monkeypatch):
    monkeypatch.setenv("BOOTSTRAP_DB_SSLMODE", "disable")
    with pytest.raises(bootstrap.BootstrapError) as error:
        with bootstrap._admin("postgresql://admin:hunter2-secret@127.0.0.1:1/main"):
            pass
    message = str(error.value)
    assert "Cannot connect to database main on 127.0.0.1:1 as admin" in message
    assert "Internal Database URL" in message
    assert "hunter2-secret" not in message


def test_error_descriptions_never_quote_the_statement():
    class Diag:
        message_primary = "permission denied to alter role"
        message_detail = "Only roles with the SUPERUSER attribute may change it."
        sqlstate = "42501"

    class Failure(psycopg.Error):
        diag = Diag()

        def __str__(self):
            return "permission denied\nLINE 1: ALTER ROLE ps_app PASSWORD 'hunter2-secret'"

    text = bootstrap.describe(Failure())
    assert text == (
        "permission denied to alter role (Only roles with the SUPERUSER attribute may"
        " change it.) [SQLSTATE 42501]"
    )
    assert "hunter2" not in text
    assert bootstrap.describe(RuntimeError("hunter2-secret")) == "RuntimeError"


@needs_sh
def test_runtime_file_is_private_and_exports_exact_values(monkeypatch, tmp_path):
    path = tmp_path / "runtime_env"
    monkeypatch.setattr(bootstrap, "RUNTIME_ENV_FILE", str(path))
    monkeypatch.setenv("BOOTSTRAP_DB_SSLMODE", "require")
    monkeypatch.setenv("TARGET_ALLOWED_HOSTS", '["other-db", "dpg-abc123-a"]')
    path.write_text("stale")
    path.chmod(0o644)
    awkward = 'postgresql+psycopg://ps_app:it\'s "$HOME" `id` %41@h:5432/d?sslmode=require'
    bootstrap.write_runtime_env(
        awkward,
        "postgresql+psycopg://ps_migrator:m@h:5432/d",
        {"host": "dpg-abc123-a", "port": 5432, "dbname": "enterprise_demo"},
        EXPLICIT["CREDENTIAL_ENCRYPTION_KEY"],
        target_ready=True,
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert all(line.startswith("export ") for line in path.read_text().splitlines())
    # Sourced by a POSIX shell and inherited by a child process, as start-all.sh does.
    names = "DATABASE_URL CREDENTIAL_ENCRYPTION_KEY TARGET_ALLOWED_HOSTS PS_TARGET_HOST"
    names += " PS_TARGET_PORT PS_TARGET_DATABASE PS_TARGET_SSLMODE PS_TARGET_READY"
    script = f'. "$1"; for n in {names}; do printenv "$n"; done'
    result = subprocess.run(
        ["sh", "-c", script, "sh", str(path)],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "HOME": "/nonexistent"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        awkward,
        EXPLICIT["CREDENTIAL_ENCRYPTION_KEY"],
        "other-db,dpg-abc123-a",
        "dpg-abc123-a",
        "5432",
        "enterprise_demo",
        "require",
        "1",
    ]


def test_allowed_hosts_keep_the_operators_entries(monkeypatch):
    monkeypatch.delenv("TARGET_ALLOWED_HOSTS", raising=False)
    assert bootstrap._allowed_hosts("db") == "db"
    monkeypatch.setenv("TARGET_ALLOWED_HOSTS", "a.example, b.example")
    assert bootstrap._allowed_hosts("db") == "a.example,b.example,db"
    monkeypatch.setenv("TARGET_ALLOWED_HOSTS", "[not json")
    assert bootstrap._allowed_hosts("db") == "db"


def test_migrations_run_from_the_backend_root_with_this_interpreter(monkeypatch):
    calls = []

    def fake_run(command, env, cwd):
        calls.append((command, env, cwd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
    bootstrap.apply_migrations("postgresql+psycopg://m@h/d", "postgresql+psycopg://a@h/d")
    command, env, cwd = calls[0]
    assert command == [sys.executable, "-m", "alembic", "upgrade", "head"]
    assert Path(cwd) == BACKEND_ROOT and (Path(cwd) / "alembic.ini").is_file()
    assert env["MIGRATION_DATABASE_URL"] == "postgresql+psycopg://m@h/d"
    monkeypatch.setattr(bootstrap.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    with pytest.raises(bootstrap.BootstrapError, match="migrations failed"):
        bootstrap.apply_migrations("postgresql+psycopg://m@h/d", "postgresql+psycopg://a@h/d")


def test_importing_the_bootstrap_does_not_configure_logging():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import logging, app.render_bootstrap; print(len(logging.getLogger().handlers))",
        ],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "0", result.stderr


@needs_sh
@pytest.mark.parametrize(
    "variables,expected",
    [
        ({}, "CONTROL_ADMIN_URL is not set"),
        ({"CONTROL_ADMIN_URL": "postgresql://a:b@127.0.0.1:1/main"}, "APP_SECRET is not set"),
    ],
)
def test_start_script_names_the_missing_variable(tmp_path, variables, expected):
    env = {"PATH": os.environ["PATH"], "HOME": "/tmp", "PS_RUNTIME_ENV_FILE": str(tmp_path / "e")}
    result = subprocess.run(
        ["sh", str(BACKEND_ROOT / "scripts" / "render" / "start-all.sh")],
        env=env | variables,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert "ERROR Startup stopped:" in result.stderr and expected in result.stderr


@needs_sh
def test_start_script_reports_a_failed_bootstrap_without_starting_the_server(tmp_path):
    env = {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), os.environ["PATH"]]),
        "HOME": "/tmp",
        "PS_RUNTIME_ENV_FILE": str(tmp_path / "e"),
        "CONTROL_ADMIN_URL": "postgresql://admin:hunter2-secret@127.0.0.1:1/main",
        "APP_SECRET": "short",
    }
    result = subprocess.run(
        ["sh", str(BACKEND_ROOT / "scripts" / "render" / "start-all.sh")],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1
    assert "Bootstrap failed: APP_SECRET is 5 characters long" in output
    assert "ERROR Startup stopped: the database bootstrap failed" in output
    assert "Uvicorn" not in output and "hunter2-secret" not in output


# --------------------------------------------------------------- settings and origin


def _settings(**overrides) -> Settings:
    values = {
        "database_url": "postgresql+psycopg://ps_app@localhost/x",
        "credential_encryption_key": EXPLICIT["CREDENTIAL_ENCRYPTION_KEY"],
    }
    return Settings(**(values | overrides))


def test_deployment_origin_defaults_from_the_platform_url(monkeypatch):
    for name in (
        "FRONTEND_ORIGIN",
        "RENDER_EXTERNAL_URL",
        "JOB_RUNNER",
        "STATIC_DIR",
        "ALLOWED_ORIGINS",
    ):
        monkeypatch.delenv(name, raising=False)
    assert _settings().origins == ["http://localhost:8080"]
    assert _settings().job_runner == "celery" and _settings().static_dir is None

    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://privacy-shield.onrender.com/")
    assert "https://privacy-shield.onrender.com" in _settings().origins
    # An explicit FRONTEND_ORIGIN wins; a blank one counts as unset.
    monkeypatch.setenv("FRONTEND_ORIGIN", "https://privacy.example.org")
    assert _settings().origins == ["http://localhost:8080", "https://privacy.example.org"]
    monkeypatch.setenv("FRONTEND_ORIGIN", "")
    assert "https://privacy-shield.onrender.com" in _settings().origins
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "not a url")
    assert _settings().origins == ["http://localhost:8080"]

    monkeypatch.setenv("JOB_RUNNER", "threads")
    with pytest.raises(ValueError):
        _settings()


def _request(origin: str | None, host: str, forwarded_host: str | None = None):
    headers = {"host": host}
    if origin:
        headers["origin"] = origin
    if forwarded_host:
        headers["x-forwarded-host"] = forwarded_host
    return SimpleNamespace(headers=headers)


def test_origin_check_for_a_browser_behind_the_platform_proxy(monkeypatch):
    for name in ("FRONTEND_ORIGIN", "ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://privacy-shield.onrender.com")
    get_settings.cache_clear()
    try:
        external = "https://privacy-shield.onrender.com"
        # Allowed by the configured origin even if the proxy rewrote Host.
        verify_origin(_request(external, "10.0.3.7:10000"))
        # A custom domain is allowed because the proxy forwards the browser's Host.
        verify_origin(_request("https://privacy.example.org", "privacy.example.org"))
        with pytest.raises(HTTPException) as denied:
            verify_origin(_request("https://attacker.example", "privacy-shield.onrender.com"))
        assert denied.value.status_code == 403
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()

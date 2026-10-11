"""A PostgreSQL server with none of PrivacyShield's roles or databases.

That is what a newly created managed instance looks like, and it is the only
place the hosted bootstrap can be tested honestly: role names are cluster-wide
and fixed (migrations grant to ``ps_app`` by name), so the shared control and
target clusters, where a superuser already created those roles, cannot stand in
for it.

Two sources, in this order:

1. ``TEST_PRISTINE_POSTGRES_URL``: a superuser URL of a disposable, empty server
   (CI starts one as a service container);
2. a throwaway cluster made with the local ``initdb`` / ``pg_ctl`` binaries.

With neither, the caller is skipped with the reason.
"""

import glob
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

import psycopg
import pytest

from tests.support.hosted import free_port

RESERVED_ROLES = (
    "ps_app",
    "ps_migrator",
    "ps_scanner",
    "ps_deployer",
    "ps_view_owner",
    "ps_reader",
    "ps_support",
    "ps_analyst",
)
SKIP_REASON = (
    "No pristine PostgreSQL server available: set TEST_PRISTINE_POSTGRES_URL to a superuser"
    " URL of a disposable empty server, or install the PostgreSQL server binaries"
    " (initdb and pg_ctl) so a throwaway cluster can be created"
)


@dataclass
class PristineServer:
    host: str  # TCP address the application connects to
    port: int
    superuser: dict  # psycopg keyword arguments, without dbname
    disposable: bool  # True when the whole cluster is deleted afterwards

    def connect(self, dbname: str = "postgres") -> psycopg.Connection:
        return psycopg.connect(**self.superuser, dbname=dbname, autocommit=True, connect_timeout=5)


def _binaries() -> tuple[str, str] | None:
    directories = [str(Path(found).parent) for found in [shutil.which("initdb")] if found]
    directories += sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True)
    directories += ["/usr/local/pgsql/bin", "/opt/homebrew/bin", "/usr/local/bin"]
    for directory in directories:
        initdb, pg_ctl = Path(directory, "initdb"), Path(directory, "pg_ctl")
        if initdb.is_file() and pg_ctl.is_file():
            return str(initdb), str(pg_ctl)
    return None


def _assert_pristine(server: PristineServer) -> None:
    with server.connect() as connection:
        roles = connection.execute(
            "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname LIKE 'ps\\_%'"
        ).fetchall()
        databases = connection.execute(
            "SELECT datname FROM pg_catalog.pg_database WHERE datname IN"
            " ('enterprise_demo', 'hospital_demo', 'university_demo')"
        ).fetchall()
    if roles or databases:
        # Never "clean" a server this test did not create: it may be someone's data.
        pytest.fail(
            "TEST_PRISTINE_POSTGRES_URL must point at an empty disposable server, but it"
            f" already has {[row[0] for row in roles + databases]}"
        )


@contextmanager
def _provided(url: str) -> Iterator[PristineServer]:
    parts = urlsplit(url)
    superuser = {
        "host": parts.hostname or "127.0.0.1",
        "port": parts.port or 5432,
        "user": unquote(parts.username or "postgres"),
    }
    if parts.password:
        superuser["password"] = unquote(parts.password)
    server = PristineServer(superuser["host"], superuser["port"], superuser, disposable=False)
    _assert_pristine(server)
    yield server


@contextmanager
def _local(initdb: str, pg_ctl: str) -> Iterator[PristineServer]:
    run_as: dict = {}
    if os.geteuid() == 0:
        # The server refuses to run as root; use the packaged service account.
        import pwd

        try:
            account = pwd.getpwnam("postgres")
        except KeyError:
            pytest.skip(SKIP_REASON + " (running as root without a 'postgres' OS user)")
        run_as = {"user": account.pw_uid, "group": account.pw_gid}
    # A short path: the Unix socket lives here and socket paths are length-limited.
    base = Path(tempfile.mkdtemp(prefix="ps-pristine-", dir="/tmp"))
    try:
        os.chmod(base, 0o755)
        if run_as:
            os.chown(base, run_as["user"], run_as["group"])
        data, port = base / "data", free_port()

        def run(*command: str) -> None:
            result = subprocess.run(
                command, capture_output=True, text=True, cwd=base, timeout=120, **run_as
            )
            assert result.returncode == 0, f"{command[0]} failed: {result.stdout}{result.stderr}"

        run(
            initdb,
            "-D",
            str(data),
            "-U",
            "postgres",
            "--auth-local=trust",
            "--auth-host=scram-sha-256",
            "-E",
            "UTF8",
            "--locale=C",
        )
        options = (
            f"-p {port} -c listen_addresses=127.0.0.1 -c unix_socket_directories={base}"
            " -c fsync=off"
        )
        run(pg_ctl, "-D", str(data), "-o", options, "-l", str(base / "server.log"), "-w", "start")
        try:
            yield PristineServer(
                "127.0.0.1",
                port,
                {"host": str(base), "port": port, "user": "postgres"},
                disposable=True,
            )
        finally:
            subprocess.run(
                [pg_ctl, "-D", str(data), "-m", "immediate", "-w", "stop"],
                capture_output=True,
                cwd=base,
                timeout=60,
                **run_as,
            )
    finally:
        shutil.rmtree(base, ignore_errors=True)


@contextmanager
def pristine_server() -> Iterator[PristineServer]:
    url = os.environ.get("TEST_PRISTINE_POSTGRES_URL")
    if url:
        with _provided(url) as server:
            yield server
        return
    binaries = _binaries()
    if binaries is None:
        pytest.skip(SKIP_REASON)
    with _local(*binaries) as server:
        yield server

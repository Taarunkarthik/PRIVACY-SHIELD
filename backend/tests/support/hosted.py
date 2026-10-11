"""Helpers for tests that run the API as a real subprocess and drive it over HTTP.

Used by the in-process job runner test and the single-service hosting test. The
server under test is a separate operating-system process, exactly as deployed;
nothing here imports the application.
"""

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

BACKEND_ROOT = Path(__file__).resolve().parents[2]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def closed_port() -> int:
    """A port nothing listens on: bound once to reserve the number, then released."""
    return free_port()


def make_static_dir(root: Path) -> Path:
    """A minimal stand-in for the Vite build output."""
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(
        "<!doctype html><html><head><title>PrivacyShield</title></head><body>"
        '<div id="root"></div><script type="module" src="/assets/index-abc123.js"></script>'
        "</body></html>",
        encoding="utf-8",
    )
    (root / "assets" / "index-abc123.js").write_text('console.log("app")\n', encoding="utf-8")
    (root / "shield.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>\n', "utf-8")
    return root


def child_environment(overrides: dict[str, str], *, inherit: bool = True) -> dict[str, str]:
    """Environment for a server subprocess, with this interpreter's venv on PATH."""
    base = dict(os.environ) if inherit else {"HOME": os.environ.get("HOME", "/tmp")}
    base["PATH"] = os.pathsep.join(
        [str(Path(sys.executable).parent), os.environ.get("PATH", "/usr/bin:/bin")]
    )
    base.setdefault("OMP_NUM_THREADS", "1")
    base.setdefault("OPENBLAS_NUM_THREADS", "1")
    base.update(overrides)
    return base


class ServerProcess:
    """A server subprocess with its combined output captured in a file."""

    def __init__(self, command: list[str], env: dict[str, str], log_path: Path, port: int):
        self.command = command
        self.env = env
        self.log_path = log_path
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.process: subprocess.Popen | None = None
        self._stream = None

    def start(self, *, ready_path: str = "/api/v1/health/live", timeout: float = 120) -> None:
        self._stream = self.log_path.open("ab")
        self.process = subprocess.Popen(
            self.command,
            cwd=BACKEND_ROOT,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=self._stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # its own process group, so a kill reaches children
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(
                    f"Server exited with {self.process.returncode} during startup:\n{self.log()}"
                )
            try:
                if httpx.get(self.base_url + ready_path, timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        self.kill()
        raise AssertionError(f"Server did not become reachable:\n{self.log()}")

    def log(self) -> str:
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def _signal(self, signum: int) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signum)
            except ProcessLookupError:
                pass

    def terminate(self, timeout: float = 40) -> int:
        """SIGTERM, as a platform does on redeploy. Returns the exit code."""
        self._signal(signal.SIGTERM)
        try:
            code = self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionError(f"Server ignored SIGTERM:\n{self.log()}") from None
        self._close()
        return code

    def kill(self) -> None:
        """SIGKILL: the process gets no chance to clean up."""
        self._signal(signal.SIGKILL)
        if self.process is not None:
            self.process.wait(10)
        self._close()

    def _close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None


class ApiSession:
    """A signed-in browser stand-in.

    Cookies are carried by hand rather than by a cookie jar so that a ``Secure``
    session cookie still works against the plain-HTTP test port, the way it does
    behind a platform's HTTPS proxy.
    """

    def __init__(self, base_url: str, origin: str):
        self.origin = origin
        self.client = httpx.Client(base_url=base_url, timeout=30, trust_env=False)
        self.headers = {"Origin": origin}
        self.set_cookie_headers: list[str] = []

    def login(self, email: str, password: str) -> httpx.Response:
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
            headers={"Origin": self.origin},
        )
        if response.status_code == 200:
            self.set_cookie_headers = response.headers.get_list("set-cookie")
            token = response.cookies.get("ps_session")
            if token is None:  # httpx drops nothing here, but be explicit about the source
                token = next(
                    value.split(";")[0].split("=", 1)[1]
                    for value in self.set_cookie_headers
                    if value.startswith("ps_session=")
                )
            self.client.cookies.clear()
            self.headers = {
                "Origin": self.origin,
                "Cookie": f"ps_session={token}",
                "X-CSRF-Token": response.json()["csrf_token"],
            }
        return response

    def get(self, path: str, **kwargs) -> httpx.Response:
        return self.client.get(path, headers=self.headers, **kwargs)

    def post(self, path: str, **kwargs) -> httpx.Response:
        return self.client.post(path, headers=self.headers, **kwargs)

    def close(self) -> None:
        self.client.close()

    def wait_for(self, path: str, done, *, timeout: float, interval: float = 0.25) -> dict:
        """Poll ``path`` until ``done(body)`` is true; return the final body."""
        deadline = time.monotonic() + timeout
        body: dict = {}
        while time.monotonic() < deadline:
            response = self.get(path)
            assert response.status_code == 200, response.text
            body = response.json()
            if done(body):
                return body
            time.sleep(interval)
        raise AssertionError(f"Timed out waiting on {path}; last state: {body}")


TERMINAL_SCAN = ("COMPLETED", "FAILED", "CANCELLED")
TERMINAL_CLASSIFICATION = ("COMPLETED", "PARTIAL", "FAILED")
TERMINAL_POLICY = ("DEPLOYED", "FAILED")

# A policy for a table no other integration test deploys to.
ACCOUNT_RULES = [
    {"column_name": "id", "action": "KEEP"},
    {"column_name": "customer_id", "action": "KEEP"},
    {"column_name": "account_number", "action": "REDACT"},
    {"column_name": "currency", "action": "KEEP"},
]


def discover(session: ApiSession, connection_id: str) -> str:
    response = session.post(
        f"/api/v1/connections/{connection_id}/discover", json={"schemas": ["enterprise"]}
    )
    assert response.status_code == 200, response.text
    return response.json()["snapshot_id"]


def queue_scan(session: ApiSession, connection_id: str, snapshot_id: str) -> str:
    response = session.post(
        "/api/v1/scans",
        json={"connection_id": connection_id, "snapshot_id": snapshot_id, "sample_limit": 50},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def wait_scan(session: ApiSession, scan_id: str, *, timeout: float = 240) -> dict:
    # The first scan in a process also loads Presidio and the spaCy model.
    return session.wait_for(
        f"/api/v1/scans/{scan_id}", lambda body: body["status"] in TERMINAL_SCAN, timeout=timeout
    )


def classify(session: ApiSession, scan_id: str, *, count: int = 3, timeout: float = 120) -> dict:
    results = session.get(f"/api/v1/scans/{scan_id}/results?page=1&page_size=50").json()["items"]
    top_level = [item["id"] for item in results if item["json_path"] == ""][:count]
    assert top_level, "the scan produced no column-level findings to classify"
    response = session.post(f"/api/v1/scans/{scan_id}/classify", json={"result_ids": top_level})
    assert response.status_code == 202, response.text
    return session.wait_for(
        f"/api/v1/classification-jobs/{response.json()['id']}",
        lambda body: body["status"] in TERMINAL_CLASSIFICATION,
        timeout=timeout,
    )


def deploy_policy(
    session: ApiSession,
    connection_id: str,
    snapshot_id: str,
    *,
    schema_name: str = "enterprise",
    table_name: str = "accounts",
    rules: list[dict] | None = None,
    timeout: float = 90,
) -> tuple[dict, dict, dict]:
    """Create, submit, approve and deploy. Returns (policy, deployment, preview)."""
    created = session.post(
        "/api/v1/policies",
        json={
            "connection_id": connection_id,
            "schema_name": schema_name,
            "table_name": table_name,
            "snapshot_id": snapshot_id,
            "rules": ACCOUNT_RULES if rules is None else rules,
        },
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    assert session.post(f"/api/v1/policies/{policy_id}/submit").status_code == 200
    approved = session.post(f"/api/v1/policies/{policy_id}/approve")
    assert approved.status_code == 200, approved.text
    preview = session.get(f"/api/v1/policies/{policy_id}/preview").json()
    queued = session.post(f"/api/v1/policies/{policy_id}/deploy", json={})
    assert queued.status_code == 202, queued.text
    policy = session.wait_for(
        f"/api/v1/policies/{policy_id}",
        lambda body: body["status"] in TERMINAL_POLICY,
        timeout=timeout,
    )
    deployments = session.get("/api/v1/deployments?page=1&page_size=20").json()["items"]
    deployment = next(item for item in deployments if item["id"] == queued.json()["id"])
    return policy, deployment, preview

"""Small authenticated HTTP client for local demonstration scripts, never a secret logger."""
from __future__ import annotations

import http.cookiejar
import json
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def local_config() -> dict[str, str]:
    return dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                if line and not line.startswith("#") and "=" in line)


class DemoClient:
    def __init__(self, email: str, password_file: Path, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip("/")
        self.csrf = None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        user = self.request("POST", "/auth/login", {"email": email, "password": password})
        self.csrf = user["csrf_token"]

    def request(self, method: str, path: str, payload=None):
        headers = {"Accept": "application/json", "Origin": self.base_url}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        req = urllib.request.Request(self.base_url + "/api/v1" + path, data=data,
                                     headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=45) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            # Never print server bodies or submitted credentials on failure.
            raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise RuntimeError("Local PrivacyShield service is unavailable") from None

    def close(self):
        self.request("POST", "/auth/logout", {})

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def register_target(client: DemoClient):
    config = local_config()
    for page in range(1, 101):
        results = client.request("GET", f"/connections?page={page}&page_size=100")
        for connection in results["items"]:
            if connection["name"] == "Synthetic enterprise":
                if connection["host"] != "target-db" or connection["database_name"] != "enterprise_demo":
                    raise RuntimeError("Existing demo name refers to another target; it was preserved")
                return connection
        if page * 100 >= results["total"]:
            break
    return client.request("POST", "/connections", {
        "name": "Synthetic enterprise", "host": "target-db", "port": 5432,
        "database_name": "enterprise_demo", "ssl_mode": "disable",
        "scanner_username": "ps_scanner", "scanner_password": config["SCANNER_PASSWORD"],
        "deployer_username": "ps_deployer", "deployer_password": config["DEPLOYER_PASSWORD"],
    })

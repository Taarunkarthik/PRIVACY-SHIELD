"""Check a single-service (all-in-one) PrivacyShield deployment over real HTTP.

Works against the hosted URL or a local container; standard library only.

    ADMIN_PASSWORD=... python scripts/check_hosted.py \
        --base-url https://<name>.onrender.com --email you@example.com --scan

It verifies the frontend and its security headers, the API, readiness without
Redis, sign-in, and the automatically registered demo connection. With --scan
it also runs a real scan of the synthetic database, which proves that jobs run
inside the web process. The password is read from the environment or a file,
never from the command line, and is never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


class Client:
    def __init__(self, base_url: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cookie: str | None = None
        self.csrf: str | None = None
        self.set_cookie: list[str] = []

    def request(self, method: str, path: str, payload=None):
        """Return (status, headers, body bytes). Cookies are sent by hand so a
        Secure cookie still works when a local container is reached over http."""
        headers = {"Accept": "*/*", "Origin": self.base_url}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def json(self, method: str, path: str, payload=None, expect: int = 200):
        status, _, body = self.request(method, path, payload)
        if status != expect:
            # Bodies can echo identifiers; the status is enough to diagnose.
            raise SystemExit(f"FAIL: {method} {path} returned HTTP {status}, expected {expect}")
        return json.loads(body) if body else None


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"ok   {message}")


def wait_until_up(client: Client, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            status, _, body = client.request("GET", "/health")
            if status == 200 and body == b"ok":
                return
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise SystemExit(f"FAIL: {client.base_url}/health did not answer 'ok' in {seconds:.0f}s")
        time.sleep(2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password-file", type=Path,
                        help="Otherwise the ADMIN_PASSWORD environment variable is used")
    parser.add_argument("--wait", type=float, default=180,
                        help="Seconds to wait for a sleeping or starting service (default 180)")
    parser.add_argument("--scan", action="store_true",
                        help="Also run a scan of the demo database and wait for it")
    parser.add_argument("--scan-timeout", type=float, default=900)
    args = parser.parse_args()
    if args.password_file:
        password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
    else:
        password = os.environ.get("ADMIN_PASSWORD", "")
    if not password:
        raise SystemExit("Set ADMIN_PASSWORD or pass --password-file")

    client = Client(args.base_url, timeout=60)
    wait_until_up(client, args.wait)
    check(True, "/health answers ok")

    status, headers, body = client.request("GET", "/api/v1/health/ready")
    ready = json.loads(body)
    check(status == 200 and ready["checks"].get("database") == "ok", "database is ready")
    check(ready["checks"].get("redis") == "not_used" and ready["checks"].get("jobs") == "ok",
          "jobs run in-process; Redis is not used")

    status, headers, body = client.request("GET", "/")
    page = body.decode("utf-8", "replace")
    check(status == 200 and '<div id="root">' in page, "the frontend is served at /")
    check(headers["X-Content-Type-Options"] == "nosniff" and headers["X-Frame-Options"] == "DENY"
          and headers["Referrer-Policy"] == "no-referrer" and headers["Cache-Control"] == "no-store"
          and "script-src 'self';" in headers["Content-Security-Policy"],
          "security headers are present on the page")
    assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', page)
    check(bool(assets), "the page references hashed assets")
    for asset in assets:
        status, headers, body = client.request("GET", asset)
        expected = "text/css" if asset.endswith(".css") else "text/javascript"
        check(status == 200 and headers["Content-Type"].startswith(expected) and len(body) > 0,
              f"{asset} is served as {expected}")
    status, _, body = client.request("GET", "/policies")
    check(status == 200 and '<div id="root">' in body.decode("utf-8", "replace"),
          "a browser route falls back to the app")
    status, headers, body = client.request("GET", "/api/v1/no-such-endpoint")
    check(status == 404 and json.loads(body) == {"detail": "Not Found"},
          "an unknown API path is a JSON 404, not the page")
    status, _, _ = client.request("GET", "/assets/no-such-file.js")
    check(status == 404, "a missing asset is a 404")

    status, headers, body = client.request(
        "POST", "/api/v1/auth/login", {"email": args.email, "password": password})
    check(status == 200, "sign-in succeeds")
    user = json.loads(body)
    client.set_cookie = headers.get_all("Set-Cookie") or []
    session = next((c for c in client.set_cookie if c.startswith("ps_session=")), "")
    check(bool(session) and "HttpOnly" in session, "the session cookie is HttpOnly")
    if args.base_url.startswith("https://"):
        check("Secure" in session, "the session cookie is Secure")
    client.cookie = session.split(";", 1)[0]
    client.csrf = user["csrf_token"]
    check(client.json("GET", "/api/v1/auth/me")["role"] == "ADMIN",
          "the signed-in user is an administrator")

    connections = client.json("GET", "/api/v1/connections?page=1&page_size=100")["items"]
    demo = next((c for c in connections if c["name"] == "Synthetic enterprise"), None)
    check(demo is not None and demo["database_name"] == "enterprise_demo",
          "the demo connection 'Synthetic enterprise' is registered")
    for name, database in (("Synthetic hospital", "hospital_demo"),
                           ("Synthetic university", "university_demo")):
        check(any(c["name"] == name and c["database_name"] == database for c in connections),
              f"the demo connection '{name}' is registered")
    check(not any("password" in key for key in demo), "no credential is returned")
    tested = client.json("POST", f"/api/v1/connections/{demo['id']}/test", {"schemas": ["enterprise"]})
    check(tested["table_count"] >= 4, f"the scanner role reaches the demo database ({tested['table_count']} tables)")

    if args.scan:
        snapshot = client.json(
            "POST", f"/api/v1/connections/{demo['id']}/discover", {"schemas": ["enterprise"]})
        scan = client.json("POST", "/api/v1/scans", {
            "connection_id": demo["id"], "snapshot_id": snapshot["snapshot_id"], "sample_limit": 100,
        }, expect=202)
        started = time.monotonic()
        while scan["status"] in ("QUEUED", "RUNNING"):
            if time.monotonic() - started > args.scan_timeout:
                raise SystemExit(f"FAIL: the scan is still {scan['status']} after "
                                 f"{args.scan_timeout:.0f}s (see 'scan stays queued' in docs/deploy-render.md)")
            time.sleep(3)
            scan = client.json("GET", f"/api/v1/scans/{scan['id']}")
        check(scan["status"] == "COMPLETED",
              f"the scan completed in the web process ({time.monotonic() - started:.0f}s)"
              if scan["status"] == "COMPLETED" else f"the scan ended {scan['status']} ({scan['error_code']})")
        results = client.json("GET", f"/api/v1/scans/{scan['id']}/results?page=1&page_size=100")
        columns = sorted({item["column_name"] for item in results["items"] if item["matching_rows"]})
        check({"email", "phone"} <= set(columns), f"personal data was detected in: {', '.join(columns)}")

    status, _, _ = client.request("POST", "/api/v1/auth/logout", {})
    check(status == 204, "sign-out succeeds")
    print("PASS: the single-service deployment is working")


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.URLError, OSError) as error:
        sys.exit(f"FAIL: could not reach the service ({type(error).__name__})")

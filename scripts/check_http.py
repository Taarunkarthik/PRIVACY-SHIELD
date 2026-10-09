"""Exercise login, proxy headers, dashboard, CSRF, and logout over real HTTP."""
import argparse
import http.cookiejar
import json
from pathlib import Path
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--base-url", default="http://localhost:8080")
    args = parser.parse_args()
    password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(path, *, payload=None, csrf=None):
        headers = {"Accept": "application/json", "Origin": args.base_url}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(args.base_url + path, data=data, headers=headers)
        try:
            response = opener.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            return response.status, response.headers, json.loads(body) if body else None

    status, _, _ = request("/api/v1/auth/me")
    assert status == 401, "Unauthenticated identity should be denied"
    status, headers, health = request("/api/v1/health/ready")
    assert status == 200 and health["checks"] == {"database": "ok", "redis": "ok"}
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    status, _, user = request("/api/v1/auth/login", payload={"email": args.email, "password": password})
    assert status == 200, "Login did not succeed"
    assert set(user) == {"id", "email", "role", "csrf_token"}
    assert password not in json.dumps(user)
    status, _, summary = request("/api/v1/dashboard/summary")
    assert status == 200 and all(isinstance(v, int) and v >= 0 for v in summary.values())
    status, _, _ = request("/api/v1/auth/logout", payload={})
    assert status == 403, "Logout should require CSRF proof"
    status, _, _ = request("/api/v1/auth/logout", payload={}, csrf=user["csrf_token"])
    assert status == 204
    status, _, _ = request("/api/v1/auth/me")
    assert status == 401, "Revoked session should be denied"
    print("PASS: real HTTP readiness, security headers, login, dashboard, CSRF and logout")


if __name__ == "__main__":
    main()

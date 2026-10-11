"""The API serving the built frontend (STATIC_DIR set), and unchanged without it."""

import asyncio
import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import frontend
from app.core.config import get_settings
from app.main import create_app

NGINX_TEMPLATE = Path(__file__).resolve().parents[2] / "frontend" / "nginx.conf.template"
SECRET = "outside-the-static-directory"
INDEX = '<!doctype html><html><body><div id="root"></div></body></html>'


@pytest.fixture
def site(tmp_path):
    """A build output directory with a secret file beside it, outside the root."""
    (tmp_path / "secret.txt").write_text(SECRET)
    root = tmp_path / "static"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX)
    (root / "shield.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
    (root / "assets" / "index-abc123.js").write_text("console.log(1)")
    (root / "assets" / "index-abc123.css").write_text("body{}")
    (root / ".env").write_text(SECRET)  # a hidden file must never be served
    try:
        (root / "assets" / "leak.js").symlink_to(tmp_path / "secret.txt")
        (root / "outside").symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        pass  # no symlink support here; the same requests are then plain missing files
    return root


def _app_with(monkeypatch, static_dir):
    if static_dir is None:
        monkeypatch.delenv("STATIC_DIR", raising=False)
    else:
        monkeypatch.setenv("STATIC_DIR", str(static_dir))
    get_settings.cache_clear()
    app_logger = logging.getLogger("privacyshield")
    logging_state = (app_logger.handlers[:], app_logger.propagate, app_logger.level)
    try:
        return create_app()
    finally:
        # Later tests must see the settings and logging of the unmodified
        # environment: serving the frontend also routes the app's log to stderr.
        monkeypatch.undo()
        get_settings.cache_clear()
        app_logger.handlers[:], app_logger.propagate = logging_state[0], logging_state[1]
        app_logger.setLevel(logging_state[2])


@pytest.fixture
def served(monkeypatch, site):
    app = _app_with(monkeypatch, site)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def api_only(monkeypatch):
    app = _app_with(monkeypatch, None)
    with TestClient(app) as client:
        yield client


def raw_get(app, path: str, method: str = "GET") -> tuple[int, dict, bytes]:
    """Send a path exactly as written. HTTP clients normalise ``..`` away first;
    a hostile client does not, and uvicorn passes the decoded path through."""
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1", "replace"),
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return start["status"], headers, body


def test_health_is_plain_text_ok(served):
    response = served.get("/health")
    assert response.status_code == 200
    assert response.text == "ok"
    assert response.headers["content-type"].startswith("text/plain")


def test_files_are_served_with_the_right_type(served):
    script = served.get("/assets/index-abc123.js")
    assert script.status_code == 200 and script.text == "console.log(1)"
    assert script.headers["content-type"].startswith("text/javascript")
    assert served.get("/assets/index-abc123.css").headers["content-type"].startswith("text/css")
    icon = served.get("/shield.svg")
    assert icon.status_code == 200 and icon.headers["content-type"] == "image/svg+xml"
    head = served.head("/shield.svg")
    assert head.status_code == 200 and head.content == b""


@pytest.mark.parametrize(
    "path", ["/", "/login", "/policies/3f1c/preview", "/favicon.ico", "/assets", "/apiary"]
)
def test_other_paths_fall_back_to_the_app_shell(served, path):
    response = served.get(path)
    assert response.status_code == 200
    assert response.text == INDEX
    assert response.headers["content-type"].startswith("text/html")


def test_a_missing_asset_is_a_404_not_the_app_shell(served):
    response = served.get("/assets/index-old999.js")
    assert response.status_code == 404
    assert INDEX not in response.text


@pytest.mark.parametrize(
    "path",
    ["/api", "/api/", "/api/v1/does-not-exist", "/api/v1/scans/extra/segments", "/api/health"],
)
def test_unknown_api_paths_stay_json_404(served, path):
    response = served.get(path)
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"detail": "Not Found"}
    # Not a 405 either: the catch-all must not claim API paths for other methods.
    assert served.post(path, json={}).status_code == 404
    assert served.post(path, json={}).json() == {"detail": "Not Found"}


def test_api_routes_still_work_and_take_precedence(served):
    assert served.get("/api/v1/health/live").json() == {"status": "ok"}
    assert served.get("/api/v1/auth/me").status_code == 401
    assert served.get("/api/openapi.json").json()["info"]["title"] == "PrivacyShield"
    assert served.post("/login").status_code == 405  # a page, not an endpoint


def test_security_headers_match_nginx(served):
    for path in ("/", "/health", "/assets/index-abc123.js", "/api/v1/health/live", "/api/v1/x"):
        headers = served.get(path).headers
        assert headers["x-content-type-options"] == "nosniff", path
        assert headers["x-frame-options"] == "DENY", path
        assert headers["referrer-policy"] == "no-referrer", path
        assert headers["cache-control"] == "no-store", path
        assert headers["content-security-policy"] == frontend.CONTENT_SECURITY_POLICY, path
    docs = served.get("/api/docs")
    assert docs.status_code == 200
    assert docs.headers["content-security-policy"] == frontend.DOCS_CONTENT_SECURITY_POLICY
    assert "cdn.jsdelivr.net" not in frontend.CONTENT_SECURITY_POLICY
    # The relaxed policy is for that exact page only.
    for path in ("/api/docs/", "/api/docs/oauth2-redirect", "/api/openapi.json", "/docs"):
        policy = served.get(path, follow_redirects=False).headers["content-security-policy"]
        assert policy == frontend.CONTENT_SECURITY_POLICY, path


@pytest.mark.skipif(not NGINX_TEMPLATE.is_file(), reason="frontend/ is not in this build context")
def test_policies_are_the_ones_in_the_nginx_template():
    policies = re.findall(
        r'add_header Content-Security-Policy "([^"]+)" always;', NGINX_TEMPLATE.read_text()
    )
    assert policies == [frontend.CONTENT_SECURITY_POLICY, frontend.DOCS_CONTENT_SECURITY_POLICY]


TRAVERSALS = [
    "/assets/../../secret.txt",
    "/assets/../../etc/passwd",
    "/../secret.txt",
    "/../../../../etc/passwd",
    "/assets/./../../secret.txt",
    "/assets/..\\..\\secret.txt",
    "/assets/..%2f..%2fsecret.txt",  # still encoded after one decode: a literal name
    "/outside/secret.txt",  # through a symlinked directory
    "/assets/leak.js",  # a symlinked file
    "/.env",
    "/assets/.hidden",
    "/assets/index-abc123.js/../../../secret.txt",
    "/secret.txt\x00.js",
    "//etc/passwd",
]


@pytest.mark.parametrize("path", TRAVERSALS)
def test_nothing_outside_the_directory_is_ever_served(monkeypatch, site, path):
    app = _app_with(monkeypatch, site)
    status, headers, body = raw_get(app, path)
    assert SECRET.encode() not in body
    assert b"root:" not in body
    # Either refused outright or answered with the app shell; never another file.
    assert (status, body) in ((404, b"Not Found"), (200, INDEX.encode())), (status, body)
    if ".." in path or "\\" in path or "\x00" in path or "/." in path:
        assert status == 404, path
    assert headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize(
    "path",
    [
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/assets/..%2f..%2fsecret.txt",
        "/%2e%2e/secret.txt",
        "/assets/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/assets/..%5c..%5csecret.txt",
        "/outside/secret.txt",
        "/assets/leak.js",
        "/%2eenv",
    ],
)
def test_encoded_traversal_through_a_real_client(served, path):
    response = served.get(path)
    assert SECRET not in response.text and "root:" not in response.text
    if path.startswith("/outside/"):
        # A link out of the directory is not followed; the path is then just an
        # unknown browser route.
        assert (response.status_code, response.text) == (200, INDEX)
    else:
        assert response.status_code == 404


def test_resolve_file_only_returns_regular_files_inside_the_root(site):
    root = site.resolve()
    assert frontend.resolve_file(root, "/shield.svg") == root / "shield.svg"
    assert frontend.resolve_file(root, "/assets/index-abc123.js").parent == root / "assets"
    for path in ("/", "", "/assets", "/assets/", "/missing.js", "/assets/leak.js", "/outside"):
        assert frontend.resolve_file(root, path) is None, path


def test_without_static_dir_the_api_is_unchanged(api_only):
    for path in ("/", "/health", "/login", "/assets/index-abc123.js"):
        response = api_only.get(path)
        assert response.status_code == 404, path
        assert response.json() == {"detail": "Not Found"}
    live = api_only.get("/api/v1/health/live")
    assert live.json() == {"status": "ok"}
    assert "content-security-policy" not in live.headers
    assert live.headers["cache-control"] == "no-store"
    assert "content-security-policy" not in api_only.get("/api/docs").headers


def test_a_static_dir_without_a_build_fails_at_startup(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match="has no index.html"):
        _app_with(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="does not exist"):
        _app_with(monkeypatch, tmp_path / "missing")


def test_blank_static_dir_means_unset(monkeypatch):
    monkeypatch.setenv("STATIC_DIR", "  ")
    get_settings.cache_clear()
    try:
        assert get_settings().static_dir is None
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()

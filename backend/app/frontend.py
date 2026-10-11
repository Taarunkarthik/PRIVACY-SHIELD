"""Serve the built React frontend from the API process.

Enabled by ``STATIC_DIR``. It replaces the nginx container of the Compose
deployment for single-service hosting and mirrors
``frontend/nginx.conf.template``:

* ``GET /health`` answers ``ok`` as plain text;
* a file that exists under ``STATIC_DIR`` is served as that file;
* a missing file under ``/assets/`` is a 404;
* every other path that is not ``/api`` gets ``index.html``, so the browser
  router can handle it.

``/api`` paths are never matched here: an unknown API path keeps FastAPI's JSON
404 instead of receiving the HTML page.
"""

import mimetypes
from pathlib import Path

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, Response
from starlette.routing import Match, Route
from starlette.types import Scope

# Copied from frontend/nginx.conf.template; tests/test_frontend_serving.py
# compares them with that file so the two cannot drift apart.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
# FastAPI's interactive docs load Swagger UI from jsDelivr. As in nginx, this
# exception applies to the documentation page only, never to the application.
DOCS_PATH = "/api/docs"
DOCS_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; font-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)

# Browsers refuse scripts and styles with the wrong type under
# X-Content-Type-Options: nosniff, and a slim container image has no system
# mime.types file, so the types a Vite build emits are stated here.
MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".map": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
    ".webmanifest": "application/manifest+json",
}


def content_security_policy(path: str) -> str:
    return DOCS_CONTENT_SECURITY_POLICY if path == DOCS_PATH else CONTENT_SECURITY_POLICY


def is_api_path(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _unsafe(path: str) -> bool:
    """A path that tries to leave the directory or reach a hidden file."""
    return (
        "\x00" in path
        or "\\" in path
        or any(part in (".", "..") or part.startswith(".") for part in path.split("/"))
    )


def resolve_file(root: Path, path: str) -> Path | None:
    """The regular file under ``root`` that ``path`` names, or None.

    ``root`` must already be resolved. The lexical check rejects dot segments
    before the filesystem is touched; resolving and re-checking containment
    rejects a symlink that points outside the directory.
    """
    if _unsafe(path):
        return None
    parts = [part for part in path.split("/") if part]
    if not parts:
        return None
    try:
        candidate = root.joinpath(*parts).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


def _file_response(path: Path) -> FileResponse:
    media_type = MEDIA_TYPES.get(path.suffix.lower()) or mimetypes.guess_type(path.name)[0]
    return FileResponse(path, media_type=media_type or "application/octet-stream")


class _FrontendRoute(Route):
    """Catch-all for browser paths that leaves every ``/api`` path unmatched."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope["type"] == "http" and is_api_path(scope["path"]):
            return Match.NONE, {}
        return super().matches(scope)


def install(app: FastAPI, static_dir: Path) -> None:
    """Add the frontend routes after the API routes. Fails fast on a bad directory."""
    try:
        root = static_dir.resolve(strict=True)
    except OSError:
        raise RuntimeError(f"STATIC_DIR {static_dir} does not exist") from None
    index = root / "index.html"
    if not index.is_file():
        raise RuntimeError(f"STATIC_DIR {static_dir} has no index.html; build the frontend first")

    async def health(request: Request) -> Response:
        return PlainTextResponse("ok")

    async def frontend(request: Request) -> Response:
        path = request.scope["path"]
        found = resolve_file(root, path)
        if found is not None:
            return _file_response(found)
        if _unsafe(path) or path.startswith("/assets/"):
            return PlainTextResponse("Not Found", status_code=404)
        return _file_response(index)

    # Route(methods=["GET"]) also answers HEAD.
    app.router.routes.append(Route("/health", health, methods=["GET"], include_in_schema=False))
    app.router.routes.append(
        _FrontendRoute("/{path:path}", frontend, methods=["GET"], include_in_schema=False)
    )

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.api import (
    auth,
    classifications,
    connections,
    dashboard,
    health,
    policies,
    scans,
    users,
)
from app.api import settings as settings_routes
from app.core.config import get_settings

logger = logging.getLogger("privacyshield")


def _log_to_stderr() -> None:
    """Show this application's INFO lines in a hosting platform's log view.

    Only used by the single-service modes. Without it Python prints warnings and
    errors only, and the lines that say a job started or ended would be lost.
    """
    app_logger = logging.getLogger("privacyshield")
    if not app_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        app_logger.addHandler(handler)
        app_logger.propagate = False
    app_logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()  # Fail fast on missing secrets or invalid configuration.
    inline = settings.job_runner == "inline"
    if inline:
        # Imported only in this mode; the Celery deployment never loads it.
        from app.workers import inline as job_runner

        _log_to_stderr()
        job_runner.start()
    try:
        yield
    finally:
        if inline:
            # Waits for the running job, bounded; anything unfinished stays in
            # PostgreSQL and is recovered by the sweep after the next start.
            await run_in_threadpool(job_runner.stop)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="PrivacyShield",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )
    for router in (
        health.router,
        auth.router,
        dashboard.router,
        connections.router,
        scans.router,
        classifications.router,
        policies.router,
        settings_routes.router,
        users.router,
    ):
        app.include_router(router, prefix="/api/v1")

    serves_frontend = settings.static_dir is not None
    if serves_frontend:
        # Single-service hosting: this process also does what nginx does in the
        # Compose deployment. Added last so every API route takes precedence.
        from app import frontend

        _log_to_stderr()
        frontend.install(app, settings.static_dir)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if serves_frontend:
            # nginx adds this header to pages and proxied API responses alike.
            response.headers["Content-Security-Policy"] = frontend.content_security_policy(
                request.scope["path"]
            )
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        # FastAPI's default includes input values; these can contain passwords.
        return JSONResponse(
            status_code=422,
            content={
                "detail": [
                    {"loc": error["loc"], "type": error["type"], "msg": "Invalid value"}
                    for error in exc.errors()
                ],
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        logger.error("Database operation failed (%s)", type(exc).__name__)
        return JSONResponse(status_code=503, content={"detail": "Database temporarily unavailable"})

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        logger.error("Request failed (%s)", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Unexpected server error"})

    return app


app = create_app()

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.api import auth, classifications, connections, dashboard, health, policies, scans
from app.api import settings as settings_routes
from app.core.config import get_settings

logger = logging.getLogger("privacyshield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_settings()  # Fail fast on missing secrets or invalid configuration.
    yield


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
    ):
        app.include_router(router, prefix="/api/v1")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
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

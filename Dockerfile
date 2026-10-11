# All-in-one image for single-service hosting (Render free plan).
# Build context = repository root:  docker build -f Dockerfile .
#
# One container serves the API, the built React frontend and the background
# jobs. It needs one PostgreSQL instance and nothing else: no nginx, no Celery
# worker, no Redis. See docs/deploy-render.md.
#
# Docker Compose does not use this file; it builds backend/Dockerfile and
# frontend/Dockerfile, which are unchanged. The Python stage below mirrors
# backend/Dockerfile (same pinned bases, locked dependencies, bundled spaCy
# model check, non-root user) without the dev extras (pytest, ruff).

# ---- frontend: the same build as frontend/Dockerfile
FROM node:24.14.1-alpine3.23 AS frontend

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---- backend
FROM ghcr.io/astral-sh/uv:0.11.3@sha256:90bbb3c16635e9627f49eec6539f956d70746c409209041800a0280b93152823 AS uv
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

COPY --from=uv /uv /uvx /bin/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    UV_NO_CACHE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 UV_CONCURRENT_DOWNLOADS=4 \
    UV_HTTP_TIMEOUT=300
WORKDIR /app

# Dependencies first, so a source change does not reinstall them. The check
# fails the build if the detection model is not inside the image.
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --locked --no-install-project \
    && .venv/bin/python -c "import en_core_web_sm; en_core_web_sm.load(disable=['parser'])"

COPY backend/ ./
# Compile the application once here: the container starts three short Python
# processes on a small CPU share, and none of them may write bytecode at runtime.
RUN uv sync --locked \
    && .venv/bin/python -m compileall -q app migrations \
    && useradd --system --uid 10001 --create-home privacyshield

COPY --from=frontend /app/dist /app/static

USER 10001
ENV PATH="/app/.venv/bin:$PATH" STATIC_DIR=/app/static JOB_RUNNER=inline
# Render provides PORT (10000 by default); the start script listens on it.
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '10000') + '/health', timeout=3)"

CMD ["sh", "/app/scripts/render/start-all.sh"]

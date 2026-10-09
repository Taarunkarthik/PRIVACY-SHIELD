FROM ghcr.io/astral-sh/uv:0.11.3@sha256:90bbb3c16635e9627f49eec6539f956d70746c409209041800a0280b93152823 AS uv
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

COPY --from=uv /uv /uvx /bin/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    RUFF_CACHE_DIR=/tmp/ruff-cache PYTEST_ADDOPTS="-o cache_dir=/tmp/pytest-cache" \
    OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 UV_CONCURRENT_DOWNLOADS=4 UV_HTTP_TIMEOUT=300
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv,sharing=locked uv sync --locked --extra dev --no-install-project \
    && .venv/bin/python -c "import en_core_web_sm; en_core_web_sm.load(disable=['parser'])"
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv,sharing=locked uv sync --locked --extra dev && useradd --system --uid 10001 --create-home privacyshield
USER 10001
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

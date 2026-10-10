#!/bin/sh
# Render API start command: provision, migrate, then serve.
set -eu

# Creates the least-privilege roles/schemas/fixtures and applies migrations.
# Idempotent and advisory-locked, so it is safe to run alongside the worker.
python -m app.render_bootstrap
. /tmp/ps_runtime_env

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --no-access-log

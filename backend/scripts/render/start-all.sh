#!/bin/sh
# Single-service start command (Render free plan): one process serves the API,
# the built frontend and the background jobs. No Celery worker, no Redis.
#
# Steps, each of which logs one line saying what it did or what to fix:
#   1. app.render_bootstrap  roles, databases, demo data, migrations
#   2. load the runtime environment the bootstrap wrote
#   3. app.render_seed       administrator and demo connection
#   4. uvicorn               on 0.0.0.0:$PORT with JOB_RUNNER=inline
#
# Required: CONTROL_ADMIN_URL and APP_SECRET. For sign-in: ADMIN_EMAIL and
# ADMIN_PASSWORD. No secret is ever printed.
set -eu

# Run from the backend root (/app in the image) wherever the script is called from.
cd "$(dirname "$0")/../.."

fail() {
    echo "ERROR Startup stopped: $1" >&2
    exit 1
}

if [ -z "${CONTROL_ADMIN_URL:-}" ]; then
    fail "CONTROL_ADMIN_URL is not set. In Render open the Postgres database, copy its Internal Database URL, and add it to this service's Environment as CONTROL_ADMIN_URL."
fi
if [ -z "${APP_SECRET:-}" ] && [ -z "${CREDENTIAL_ENCRYPTION_KEY:-}" ]; then
    fail "APP_SECRET is not set. Add an APP_SECRET environment variable holding a random value of at least 32 characters."
fi

RUNTIME_ENV="${PS_RUNTIME_ENV_FILE:-/tmp/ps_runtime_env}"
rm -f "$RUNTIME_ENV"

python -m app.render_bootstrap || fail "the database bootstrap failed. The 'Bootstrap failed' line above says what to fix."
[ -f "$RUNTIME_ENV" ] || fail "the bootstrap did not write its runtime environment."
# shellcheck disable=SC1090
. "$RUNTIME_ENV"
rm -f "$RUNTIME_ENV"

# Hosted defaults. The browser reaches this service over the platform's HTTPS
# proxy, so session cookies are marked Secure unless explicitly overridden.
export JOB_RUNNER=inline
export COOKIE_SECURE="${COOKIE_SECURE:-true}"
export STATIC_DIR="${STATIC_DIR:-/app/static}"
# The public https://<name>.onrender.com origin, for the CSRF origin check.
if [ -z "${FRONTEND_ORIGIN:-}" ] && [ -n "${RENDER_EXTERNAL_URL:-}" ]; then
    export FRONTEND_ORIGIN="${RENDER_EXTERNAL_URL%/}"
fi

python -m app.render_seed || fail "administrator or demo-connection setup failed. The 'Setup failed' line above says what to fix."

# The server needs none of the provisioning credentials. Drop them so the
# long-running process holds only its own least-privilege database URL.
unset CONTROL_ADMIN_URL TARGET_ADMIN_URL APP_SECRET ADMIN_PASSWORD MIGRATION_DATABASE_URL \
    APP_DATABASE_PASSWORD MIGRATOR_PASSWORD SCANNER_PASSWORD DEPLOYER_PASSWORD READER_PASSWORD

PORT="${PORT:-10000}"
if [ -z "${OLLAMA_BASE_URL:-}" ]; then
    echo "INFO AI classification is off: OLLAMA_BASE_URL is not set. Detection and masking do not need it."
fi
echo "INFO Serving frontend from $STATIC_DIR, jobs run in-process, listening on 0.0.0.0:$PORT"

# One process and one event loop: the in-process job runner must exist exactly once.
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --no-access-log \
    --timeout-graceful-shutdown 5

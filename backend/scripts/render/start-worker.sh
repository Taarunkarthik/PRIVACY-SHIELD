#!/bin/sh
# Render worker start command: provision, migrate, then run Celery beat + worker.
set -eu

python -m app.render_bootstrap
. /tmp/ps_runtime_env

exec celery -A app.workers.celery_app:celery_app worker \
    --loglevel=WARNING --concurrency=1 --beat --schedule=/tmp/privacyshield-beat

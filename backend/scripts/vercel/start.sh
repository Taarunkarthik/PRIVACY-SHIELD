#!/bin/sh
# Start command for Vercel's container runtime (Dockerfile.vercel).
#
# It adapts the Vercel environment to the single-service start script and then
# hands over to it (scripts/render/start-all.sh), which does all the work:
# database bootstrap, migrations, administrator, then the server.
#
#   1. Database: a Postgres added from the Vercel Marketplace (Neon) injects the
#      database owner's connection string under several names. The direct,
#      unpooled one becomes CONTROL_ADMIN_URL.
#   2. Every injected copy of the owner's credentials is then removed from the
#      environment, so the long-running server holds only its own
#      least-privilege database URL, as on every other deployment.
#   3. Origin: the project's own *.vercel.app addresses are allowed for the
#      CSRF origin check.
#   4. Port: Vercel routes to the port named by the PORT project variable, or
#      to 80 when there is none.
#
# Status: EXPERIMENTAL. Nothing here has been run on Vercel. See
# docs/deploy-vercel.md for what is known and what is not.
set -eu

fail() {
    echo "ERROR Startup stopped: $1" >&2
    exit 1
}

if [ -z "${CONTROL_ADMIN_URL:-}" ]; then
    CONTROL_ADMIN_URL="${DATABASE_URL_UNPOOLED:-${POSTGRES_URL_NON_POOLING:-}}"
fi
if [ -z "${CONTROL_ADMIN_URL:-}" ]; then
    if [ -n "${DATABASE_URL:-}${POSTGRES_URL:-}" ]; then
        fail "only a pooled database URL was found. PrivacyShield needs a direct connection: its job locks and role switches do not work through a connection pooler. Add a CONTROL_ADMIN_URL variable holding the database's direct (unpooled) connection string."
    fi
    fail "no database is connected. In the Vercel project open Storage, create a Neon Postgres database, connect it to this project, and redeploy."
fi
export CONTROL_ADMIN_URL

# The names the Neon and Vercel Postgres integrations inject. All of them carry
# the database owner's password or identify its account.
unset DATABASE_URL DATABASE_URL_UNPOOLED \
    POSTGRES_URL POSTGRES_URL_NON_POOLING POSTGRES_URL_NO_SSL POSTGRES_PRISMA_URL \
    POSTGRES_USER POSTGRES_PASSWORD POSTGRES_HOST POSTGRES_DATABASE \
    PGHOST PGHOST_UNPOOLED PGUSER PGPASSWORD PGDATABASE \
    NEON_PROJECT_ID NEON_AUTH_BASE_URL

# The browser-facing addresses Vercel gives this deployment. Host names only,
# checked before use; a custom domain is covered by FRONTEND_ORIGIN.
if [ -z "${ALLOWED_ORIGINS:-}" ]; then
    origins=""
    for host in "${VERCEL_PROJECT_PRODUCTION_URL:-}" "${VERCEL_BRANCH_URL:-}" "${VERCEL_URL:-}"; do
        case "$host" in
            "" | *[!A-Za-z0-9.-]*) continue ;;
        esac
        case ",$origins," in
            *",\"https://$host\","*) continue ;;
        esac
        origins="${origins:+$origins,}\"https://$host\""
    done
    if [ -n "$origins" ]; then
        export ALLOWED_ORIGINS="[$origins]"
    fi
fi

# The image's user may not exist on the platform, or its home may be read-only.
# Libraries that keep a cache under $HOME then need somewhere writable.
if [ ! -w "${HOME:-/nonexistent}" ]; then
    export HOME=/tmp
fi

if [ -z "${PORT:-}" ]; then
    echo "WARNING PORT is not set, so Vercel routes to port 80 and this server will try to listen there. If the next lines show a permission error, add a project variable PORT=10000 and redeploy."
    export PORT=80
fi

exec sh "$(dirname "$0")/../render/start-all.sh"

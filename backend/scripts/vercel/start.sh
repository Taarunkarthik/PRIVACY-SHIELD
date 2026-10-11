#!/bin/sh
# Start command for Vercel's container runtime (Dockerfile.vercel).
#
# It adapts the Vercel environment to the single-service start script and then
# hands over to it (scripts/render/start-all.sh), which does all the work:
# database bootstrap, migrations, administrator, then the server.
#
#   1. Database: a Postgres added from the Vercel Marketplace (Neon) injects the
#      database owner's connection string under several names, which a custom
#      prefix changes. The direct, unpooled one becomes CONTROL_ADMIN_URL.
#   2. Every injected copy of the owner's credentials is then removed from the
#      environment, so the long-running server holds only its own
#      least-privilege database URL, as on every other deployment.
#   3. Origin: the project's own *.vercel.app addresses are allowed for the
#      CSRF origin check.
#   4. Port: Vercel routes to the port named by the PORT project variable, or
#      to 80 when there is none.
#
# Status: an earlier version of this script started one working deployment on
# Vercel (11 October 2026), set up by giving CONTROL_ADMIN_URL by hand. Finding
# the database from prefixed variable names has only been run in the tests.
# See docs/deploy-vercel.md for what is known and what is not.
set -eu

fail() {
    echo "ERROR Startup stopped: $1" >&2
    exit 1
}

# Variable names in the environment, one per line. A value that spans several
# lines can add a line that looks like a name; reading such a name gives an
# empty value, so it is harmless.
env_names() {
    env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*$/\1/p' | sort -u
}

# The value of the variable called $1. Only ever called with a name that
# matched the pattern above, so the eval cannot run anything else.
value_of() {
    eval "printf '%s' \"\${$1:-}\""
}

is_postgres_url() {
    case "$1" in
        postgres://* | postgresql://*) return 0 ;;
    esac
    return 1
}

if [ -z "${CONTROL_ADMIN_URL:-}" ]; then
    CONTROL_ADMIN_URL="${DATABASE_URL_UNPOOLED:-${POSTGRES_URL_NON_POOLING:-}}"
fi
if [ -z "${CONTROL_ADMIN_URL:-}" ]; then
    # Connecting the database with a custom prefix renames its variables. The
    # direct URL is still the one whose name ends in _UNPOOLED or _NON_POOLING.
    for name in $(env_names); do
        case "$name" in
            *_UNPOOLED | *_NON_POOLING)
                candidate="$(value_of "$name")"
                if is_postgres_url "$candidate"; then
                    CONTROL_ADMIN_URL="$candidate"
                    echo "INFO Using the direct database URL from $name"
                    break
                fi
                ;;
        esac
    done
fi
if [ -z "${CONTROL_ADMIN_URL:-}" ]; then
    for name in $(env_names); do
        if is_postgres_url "$(value_of "$name")"; then
            fail "only a pooled database URL was found ($name). PrivacyShield needs a direct connection: its job locks and role switches do not work through a connection pooler. Add a CONTROL_ADMIN_URL variable holding the database's direct (unpooled) connection string."
        fi
    done
    fail "no database is connected. In the Vercel project open Storage, create a Neon Postgres database, connect it to this project, and redeploy."
fi
export CONTROL_ADMIN_URL

# Remove every other copy of the database owner's credentials, whatever the
# integration called them: any variable that holds a Postgres URL, any that
# contains the owner's password, and the ones that name its host and account.
# The application's own DATABASE_URL is written later by the bootstrap.
userinfo="${CONTROL_ADMIN_URL#*://}"
userinfo="${userinfo%%@*}"
owner_password=""
case "$userinfo" in
    *:*) owner_password="${userinfo#*:}" ;;
esac
for name in $(env_names); do
    case "$name" in
        CONTROL_ADMIN_URL | TARGET_ADMIN_URL) continue ;;
        *PGHOST | *PGHOST_UNPOOLED | *PGUSER | *PGPASSWORD | *PGDATABASE | \
            *POSTGRES_USER | *POSTGRES_HOST | *POSTGRES_PASSWORD | *POSTGRES_DATABASE | \
            *NEON_PROJECT_ID | *NEON_AUTH_BASE_URL)
            unset "$name"
            continue
            ;;
    esac
    value="$(value_of "$name")"
    if is_postgres_url "$value"; then
        unset "$name"
    elif [ "${#owner_password}" -ge 8 ]; then
        case "$value" in
            *"$owner_password"*) unset "$name" ;;
        esac
    fi
done

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

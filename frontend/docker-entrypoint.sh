#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# Render supplies API_HOSTPORT through the Blueprint. The fallback supports an
# existing service created manually before the Blueprint was synced.
set -eu

: "${API_HOSTPORT:=privacyshield-api:10000}"
: "${PORT:=8080}"
export API_HOSTPORT PORT

envsubst '${API_HOSTPORT} ${PORT}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

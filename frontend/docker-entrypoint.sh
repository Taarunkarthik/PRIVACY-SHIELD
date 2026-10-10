#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# Render supplies API_HOSTPORT through the Blueprint. The fallback supports an
# existing service created manually before the Blueprint was synced.
set -eu

: "${API_BASE_URL:=https://privacyshield-api.onrender.com}"
: "${PORT:=8080}"
export API_BASE_URL PORT

envsubst '${API_BASE_URL} ${PORT}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

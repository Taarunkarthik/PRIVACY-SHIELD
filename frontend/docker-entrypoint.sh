#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# Render supplies API_HOSTPORT through the Blueprint. Keep local Compose
# behavior explicit without silently hiding a broken hosted configuration.
set -eu

: "${API_HOSTPORT:?API_HOSTPORT must be configured as host:port}"
: "${PORT:=8080}"
export API_HOSTPORT PORT

envsubst '${API_HOSTPORT} ${PORT}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# Defaults preserve the local Docker Compose topology.
set -eu

: "${API_HOSTPORT:=api:8000}"
: "${PORT:=8080}"
export API_HOSTPORT PORT

envsubst '${API_HOSTPORT} ${PORT}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

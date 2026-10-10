#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# Defaults preserve the local Docker Compose topology.
set -eu

: "${API_HOST:=api}"
: "${API_PORT:=8000}"
: "${PORT:=8080}"
if [ -z "${RESOLVER:-}" ]; then
    RESOLVER="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
    [ -n "$RESOLVER" ] || RESOLVER="127.0.0.11"
fi
export API_HOST API_PORT PORT RESOLVER

envsubst '${API_HOST} ${API_PORT} ${PORT} ${RESOLVER}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# Defaults preserve the local Docker Compose topology.
set -eu

: "${API_HOSTPORT:=api:8000}"
: "${PORT:=8080}"
if [ -z "${RESOLVER:-}" ]; then
    RESOLVER="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
    [ -n "$RESOLVER" ] || RESOLVER="127.0.0.11"
fi
export API_HOSTPORT PORT RESOLVER

envsubst '${API_HOSTPORT} ${PORT} ${RESOLVER}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

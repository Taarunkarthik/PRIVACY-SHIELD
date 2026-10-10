#!/bin/sh
# Render the nginx config from the template with deployment-provided values.
# The default preserves local Docker Compose; Render supplies API_BASE_URL.
set -eu

: "${API_BASE_URL:=http://api:8000}"
: "${PORT:=8080}"
if [ -z "${RESOLVER:-}" ]; then
    # Docker uses 127.0.0.11; Render uses its own DNS. Derive from resolv.conf.
    RESOLVER="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
    [ -n "$RESOLVER" ] || RESOLVER="127.0.0.11"
fi
# Host (and port) of the upstream, used as the proxy Host header so the edge
# routes to the API rather than looping back to this frontend.
API_UPSTREAM_HOST="$(printf '%s' "$API_BASE_URL" | sed -E 's#^[a-z]+://##; s#/.*$##')"
export API_BASE_URL PORT RESOLVER API_UPSTREAM_HOST

envsubst '${API_BASE_URL} ${PORT} ${RESOLVER} ${API_UPSTREAM_HOST}' \
    < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -c /tmp/nginx.conf -g 'daemon off;'

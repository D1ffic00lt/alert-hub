#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

api_readiness_url=http://alert-hub:8080/health/ready
nginx_pid=""

# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap.
cleanup() {
  status=$?
  trap - EXIT TERM INT
  if [ -n "${nginx_pid}" ]; then
    kill -TERM "${nginx_pid}" 2>/dev/null || true
    wait "${nginx_pid}" 2>/dev/null || true
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

api_ready() {
  wget -q -T 2 -t 1 -O /dev/null "${api_readiness_url}"
}

mkdir -p /tmp/nginx/client_body /tmp/nginx/proxy /tmp/nginx/fastcgi /tmp/nginx/uwsgi /tmp/nginx/scgi
/usr/local/bin/render-ui-runtime

attempt=1
while [ "${attempt}" -le 120 ]; do
  if api_ready; then
    break
  fi
  if [ "${attempt}" -eq 120 ]; then
    printf '%s\n' 'Alert Hub API did not become ready within 120 seconds.' >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 1
done

nginx -c /etc/alert-hub/nginx.conf -g 'daemon off;' &
nginx_pid=$!

failures=0
degraded=false
while kill -0 "${nginx_pid}" 2>/dev/null; do
  sleep 5
  if api_ready; then
    if [ "${degraded}" = true ]; then
      printf '%s\n' 'Alert Hub API readiness recovered; web requests are enabled again.' >&2
    fi
    failures=0
    degraded=false
  else
    failures=$((failures + 1))
    if [ "${failures}" -ge 3 ] && [ "${degraded}" = false ]; then
      printf '%s\n' 'Alert Hub API readiness failed three consecutive checks; web remains up in guarded 503 mode.' >&2
      degraded=true
    fi
  fi
done

status=0
wait "${nginx_pid}" || status=$?
nginx_pid=""
exit "${status}"

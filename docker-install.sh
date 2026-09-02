#!/usr/bin/env sh
set -eu

repository=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "${repository}"

if ! docker compose version >/dev/null 2>&1; then
  printf '%s\n' 'Docker Engine with Compose v2 is required.' >&2
  exit 1
fi

if [ -L .env ]; then
  printf '%s\n' 'Refusing to replace a symlinked .env file.' >&2
  exit 1
fi
if [ ! -f .env ]; then
  umask 077
  cp .env.example .env
  chmod 0600 .env
  printf '%s\n' 'Created .env from .env.example.'
fi

if [ -L runtime ] || [ -L runtime/secrets ]; then
  printf '%s\n' 'Refusing a symlinked runtime secrets path.' >&2
  exit 1
fi
umask 077
mkdir -p runtime/secrets
chmod 0700 runtime runtime/secrets

mode=${ALERT_HUB_INSTALL_MODE:-}
if [ -z "${mode}" ] && [ -t 0 ]; then
  printf '%s\n' 'Select deployment mode:'
  printf '%s\n' '  1) split (API + Web, recommended)'
  printf '%s\n' '  2) API only'
  printf '%s' 'Choice [1]: '
  IFS= read -r choice || choice=1
  case ${choice:-1} in
    1) mode='split' ;;
    2) mode='api-only' ;;
    *)
      printf '%s\n' 'Unknown choice.' >&2
      exit 2
      ;;
  esac
fi
mode=${mode:-split}

case ${mode} in
  split)
    compose_file=docker-compose.yml
    ;;
  api-only)
    compose_file=docker-compose.api-only.yml
    ;;
  *)
    printf '%s\n' 'ALERT_HUB_INSTALL_MODE must be split or api-only.' >&2
    exit 2
    ;;
esac

docker compose --env-file .env -f "${compose_file}" config --quiet
docker compose --env-file .env -f "${compose_file}" up -d --build --wait
printf 'Alert Hub %s deployment is ready on %s:%s.\n' \
  "${mode}" "${ALERT_HUB_BIND_ADDRESS:-127.0.0.1}" "${ALERT_HUB_HOST_PORT:-8080}"

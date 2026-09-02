#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

case "${MIGRATE_ON_START:-true}" in
  true)
    alembic -c /app/backend/alembic.ini upgrade head
    ;;
  false)
    ;;
  *)
    printf '%s\n' 'MIGRATE_ON_START must be true or false' >&2
    exit 2
    ;;
esac

exec alert-hub

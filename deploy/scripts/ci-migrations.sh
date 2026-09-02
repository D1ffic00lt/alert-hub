#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
backend_dir=${repo_root}/backend
if [[ -n ${PYTHON:-} ]]; then
  migration_python=${PYTHON}
elif [[ -x ${repo_root}/.venv/bin/python ]]; then
  migration_python=${repo_root}/.venv/bin/python
else
  migration_python=python3
fi
[[ -f ${backend_dir}/alembic.ini ]] || {
  printf 'backend/alembic.ini is required for migration verification\n' >&2
  exit 1
}

temporary_dir=$(mktemp -d)
trap 'rm -rf -- "${temporary_dir}"' EXIT
database_path=${temporary_dir}/migration-test.db
export DATABASE_URL=sqlite:///${database_path}

cd "${backend_dir}"

# Clean database path.
"${migration_python}" -m alembic -c alembic.ini upgrade head
"${migration_python}" - "${database_path}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
try:
    assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
finally:
    connection.close()
PY

# Previous schema path. A project with a single migration has `base` as its
# previous state; later releases exercise an actual N-1 revision here.
"${migration_python}" -m alembic -c alembic.ini downgrade -1
"${migration_python}" -m alembic -c alembic.ini upgrade head
"${migration_python}" -m alembic -c alembic.ini check

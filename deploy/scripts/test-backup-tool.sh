#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || {
  printf 'test-backup-tool.sh must run as root (use sudo on an ephemeral CI host)\n' >&2
  exit 1
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d /tmp/alert-hub-backup-test.XXXXXX)
cleanup() {
  [[ ${test_root} == /tmp/alert-hub-backup-test.* ]] && rm -rf -- "${test_root}"
}
trap cleanup EXIT

install -d -m 0700 "${test_root}/data" "${test_root}/backups"
install -o root -g root -m 0755 "${repo_root}/deploy/scripts/alert-hub-backup" "${test_root}/alert-hub-backup"
backup_tool=${test_root}/alert-hub-backup
config=${test_root}/backup.env
database=${test_root}/data/alert-hub.db
cat >"${config}" <<EOF
NODE_NAME=ci
DATABASE_PATH=${database}
BACKUP_DIR=${test_root}/backups
CONTAINER_NAME=alert-hub-backup-ci-not-running
DATABASE_UID=0
DATABASE_GID=0
KEEP_DAILY=7
KEEP_WEEKLY=4
KEEP_MONTHLY=6
EOF
chmod 0600 "${config}"

python3 - "${database}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("CREATE TABLE evidence (value TEXT NOT NULL)")
connection.execute("INSERT INTO evidence VALUES ('before')")
connection.commit()
connection.close()
PY

backup=$(ALERT_HUB_BACKUP_CONFIG="${config}" "${backup_tool}" backup --label ci)
ALERT_HUB_BACKUP_CONFIG="${config}" "${backup_tool}" verify "${backup}"

python3 - "${database}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("INSERT INTO evidence VALUES ('after')")
connection.commit()
connection.close()
PY

ALERT_HUB_BACKUP_CONFIG="${config}" "${backup_tool}" \
  restore "${backup}" --confirm 'RESTORE ci'

python3 - "${database}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
rows = connection.execute("SELECT value FROM evidence ORDER BY rowid").fetchall()
connection.close()
if rows != [("before",)]:
    raise SystemExit(f"restore verification failed: {rows!r}")
PY

fake_bin=${test_root}/fake-bin
install -d -m 0700 "${fake_bin}"
cat >"${fake_bin}/docker" <<EOF
#!/bin/sh
case "\$*" in
  'container ls --quiet')
    printf '%s\n' fake-running-container
    ;;
  'container inspect fake-running-container')
    printf '%s\n' '[{"Name":"/unexpected-running-container","State":{"Running":true},"Mounts":[{"Source":"${test_root}/data","Destination":"/data"}]}]'
    ;;
  *)
    printf 'unexpected fake Docker arguments: %s\n' "\$*" >&2
    exit 2
    ;;
esac
EOF
chmod 0700 "${fake_bin}/docker"

guard_output=""
if guard_output=$(PATH="${fake_bin}:${PATH}" ALERT_HUB_BACKUP_CONFIG="${config}" \
  "${backup_tool}" restore "${backup}" --confirm 'RESTORE ci' 2>&1); then
  printf 'restore unexpectedly ignored a running container with the database bind-mounted\n' >&2
  exit 1
fi
[[ ${guard_output} == *unexpected-running-container* && ${guard_output} == *contains* ]] || {
  printf 'unexpected running-container guard output: %s\n' "${guard_output}" >&2
  exit 1
}

printf 'Online backup, checksum, safety backup, restore, and running-container guard tests passed.\n'

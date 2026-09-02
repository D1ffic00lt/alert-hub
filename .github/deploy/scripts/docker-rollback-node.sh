#!/bin/bash
set -Eeuo pipefail

# Keep this wrapper deliberately small. It gives sudoers a distinct rollback
# entry point and delegates the state-machine work to the same root-owned engine
# used by deploys, so readiness failure always restores the starting image.
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly DEPLOY_ENGINE=/usr/local/sbin/docker-deploy-node.sh

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_root_controlled_file() {
  local path=$1 description=$2 owner mode mode_value
  [[ -f ${path} && ! -L ${path} ]] || die "${description} must be a regular file: ${path}"
  owner=$(stat -c '%u' -- "${path}")
  mode=$(stat -c '%a' -- "${path}")
  [[ ${owner} == 0 ]] || die "${description} must be owned by root"
  [[ ${mode} =~ ^[0-7]{3,4}$ ]] || die "could not validate ${description} permissions"
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || die "${description} must not be group/other writable"
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ $# -eq 0 ]] || die "rollback arguments are accepted only through validated environment variables"
: "${NODE_NAME:?NODE_NAME is required}"
: "${ALERT_HUB_CONFIRMATION:?ALERT_HUB_CONFIRMATION is required}"
[[ ${NODE_NAME} =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "NODE_NAME is invalid"
[[ ${ALERT_HUB_CONFIRMATION} == "ROLLBACK ${NODE_NAME}" ]] || die "rollback confirmation does not match this node"

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
require_root_controlled_file "${script_path}" "rollback wrapper"
require_root_controlled_file "${DEPLOY_ENGINE}" "deployment engine"
exec "${DEPLOY_ENGINE}" rollback

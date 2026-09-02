#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly INSTALL_ROOT=/opt/alert-hub
readonly STATE_DIR=${INSTALL_ROOT}/state
readonly CURRENT_FILE=${STATE_DIR}/current.env
readonly APP_ENV_FILE=${INSTALL_ROOT}/config/alert-hub.env
readonly LOCK_FILE=${INSTALL_ROOT}/.deploy.lock
readonly DEPLOY_POLICY_FILE=/etc/alert-hub/deploy-policy.env
readonly API_CONTAINER=alert-hub-api
readonly WEB_CONTAINER=alert-hub-web
HOST_PORT=""

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

state_value() {
  local key=$1
  awk -F= -v wanted="${key}" '$1 == wanted {print substr($0, index($0, "=") + 1); found = 1; exit} END {if (!found) exit 1}' "${CURRENT_FILE}"
}

policy_value() {
  local key=$1
  awk -F= -v wanted="${key}" '$1 == wanted {print substr($0, index($0, "=") + 1); found = 1; exit} END {if (!found) exit 1}' "${DEPLOY_POLICY_FILE}"
}

load_status_policy() {
  require_root_controlled_file "${DEPLOY_POLICY_FILE}" "deployment policy"
  [[ $(stat -c '%a' -- "${DEPLOY_POLICY_FILE}") == 600 ]] || die "deployment policy must have mode 0600"
  awk -F= '
    NF != 2 {exit 1}
    $1 !~ /^(GITHUB_REPOSITORY|NODE_NAME|HOST_PORT|EDGE_SUBNET|API_IP|WEB_IP|MONITORING_NETWORK)$/ {exit 1}
    seen[$1]++ > 0 {exit 1}
    END {
      required["GITHUB_REPOSITORY"] = required["NODE_NAME"] = required["HOST_PORT"] = 1
      required["EDGE_SUBNET"] = required["API_IP"] = required["WEB_IP"] = 1
      required["MONITORING_NETWORK"] = 1
      for (key in required) if (!seen[key]) exit 1
    }
  ' "${DEPLOY_POLICY_FILE}" || die "deployment policy is malformed"
  HOST_PORT=$(policy_value HOST_PORT)
  if [[ ! ${HOST_PORT} =~ ^[1-9][0-9]{0,4}$ ]] || ((10#${HOST_PORT} > 65535)); then
    die "deployment policy HOST_PORT is invalid"
  fi
  readonly HOST_PORT
}

container_status() {
  local container=$1
  local status health
  status=$(docker container inspect "${container}" --format '{{.State.Status}}' 2>/dev/null || true)
  health=$(docker container inspect "${container}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || true)
  printf '%s/%s\n' "${status:-absent}" "${health:-unknown}"
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
for command_name in awk curl date docker flock readlink sha256sum stat; do
  command -v "${command_name}" >/dev/null || die "required command is missing: ${command_name}"
done
script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
require_root_controlled_file "${script_path}" "status script"
require_root_controlled_file "${CURRENT_FILE}" "deployment state"
[[ $(stat -c '%a' -- "${CURRENT_FILE}") == 600 ]] || die "deployment state must have mode 0600"
load_status_policy
[[ -f ${LOCK_FILE} && ! -L ${LOCK_FILE} ]] || die "deployment lock is unavailable"
exec 9<"${LOCK_FILE}"
flock -s 9

node_name=$(state_value NODE_NAME)
api_ref=$(state_value API_REF)
api_version=$(state_value API_VERSION)
api_compatibility=$(state_value API_COMPATIBILITY)
web_ref=$(state_value WEB_REF)
web_version=$(state_value WEB_VERSION)
web_compatibility=$(state_value WEB_COMPATIBILITY)
config_sha256=$(state_value CONFIG_SHA256)
deployed_at=$(state_value DEPLOYED_AT)

if [[ -n ${api_ref} ]]; then
  [[ ${config_sha256} =~ ^[0-9a-f]{64}$ ]] || die "deployment state has an invalid runtime config checksum"
  require_root_controlled_file "${APP_ENV_FILE}" "runtime application config"
  [[ $(stat -c '%a' -- "${APP_ENV_FILE}") == 600 ]] || die "runtime application config must have mode 0600"
  actual_config_sha256=$(sha256sum "${APP_ENV_FILE}" | awk '{print $1}')
  [[ ${actual_config_sha256} == "${config_sha256}" ]] ||
    die "active runtime config does not match deployment state"
else
  [[ -z ${config_sha256} ]] || die "deployment state has config without an API image"
  [[ ! -e ${APP_ENV_FILE} && ! -L ${APP_ENV_FILE} ]] ||
    die "runtime config exists without a recorded API image"
fi

printf 'node=%s\n' "${node_name}"
printf 'deployed_at=%s\n' "${deployed_at}"
printf 'config_sha256=%s\n' "${config_sha256:-not-deployed}"
printf 'api_version=%s\napi_image=%s\napi_compatibility=%s\napi_status=%s\n' \
  "${api_version:-not-deployed}" "${api_ref:-not-deployed}" "${api_compatibility:-not-deployed}" "$(container_status "${API_CONTAINER}")"
printf 'web_version=%s\nweb_image=%s\nweb_compatibility=%s\nweb_status=%s\n' \
  "${web_version:-not-deployed}" "${web_ref:-not-deployed}" "${web_compatibility:-not-deployed}" "$(container_status "${WEB_CONTAINER}")"

healthy=true
if [[ -n ${api_ref} && $(container_status "${API_CONTAINER}") != running/healthy ]]; then
  healthy=false
fi
if [[ -n ${web_ref} ]]; then
  if [[ $(container_status "${WEB_CONTAINER}") != running/healthy ]]; then
    healthy=false
  elif ! curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${HOST_PORT}/health/ready" >/dev/null; then
    healthy=false
  fi
fi
[[ ${healthy} == true ]] || die "one or more recorded components are not ready"

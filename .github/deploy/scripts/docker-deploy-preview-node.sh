#!/bin/bash
set -Eeuo pipefail

umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly INSTALL_ROOT=/opt/alert-hub
readonly PREVIEW_STATE_DIR=${INSTALL_ROOT}/preview
readonly PREVIEW_STATE_FILE=${PREVIEW_STATE_DIR}/current.env
readonly PRODUCTION_STATE_FILE=${INSTALL_ROOT}/state/current.env
readonly LOCK_FILE=${INSTALL_ROOT}/.deploy.lock
readonly DEPLOY_POLICY_FILE=/etc/alert-hub/deploy-policy.env
readonly COMPOSE_FILE=/etc/alert-hub/docker-compose.preview.yml
readonly PREVIEW_CONTAINER=alert-hub-web-preview
readonly PREVIEW_HOST_PORT=18083
readonly API_CONTAINER=alert-hub-api

POLICY_GITHUB_REPOSITORY=""
POLICY_NODE_NAME=""
POLICY_HOST_PORT=""
POLICY_API_HOST_PORT=""
EXPECTED_WEB_REPOSITORY=""
AUTH_DIR=""

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_commands() {
  local command_name
  for command_name in awk chmod chown curl date docker find flock install mktemp mv readlink rmdir sleep stat tr; do
    command -v "${command_name}" >/dev/null || die "required command is missing: ${command_name}"
  done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
}

require_root_directory() {
  local path=$1 description=$2
  [[ -d ${path} && ! -L ${path} ]] || die "${description} must be a real directory: ${path}"
  [[ $(stat -c '%u' -- "${path}") == 0 ]] || die "${description} must be owned by root"
  [[ $(stat -c '%a' -- "${path}") == 700 ]] || die "${description} must have mode 0700"
}

require_root_controlled_file() {
  local path=$1 description=$2 owner mode mode_value
  [[ -f ${path} && ! -L ${path} ]] || die "${description} must be a regular file: ${path}"
  owner=$(stat -c '%u' -- "${path}")
  mode=$(stat -c '%a' -- "${path}")
  [[ ${owner} == 0 ]] || die "${description} must be owned by root: ${path}"
  [[ ${mode} =~ ^[0-7]{3,4}$ ]] || die "could not validate permissions for ${description}"
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) ||
    die "${description} must not be group/other writable: ${path}"
}

require_private_file() {
  local path=$1 description=$2
  require_root_controlled_file "${path}" "${description}"
  [[ $(stat -c '%a' -- "${path}") == 600 ]] || die "${description} must have mode 0600"
}

state_value() {
  local file=$1 key=$2
  awk -F= -v wanted="${key}" '$1 == wanted {print substr($0, index($0, "=") + 1); found = 1; exit} END {if (!found) exit 1}' "${file}"
}

validate_revision() {
  [[ $1 =~ ^[0-9a-f]{40}$ ]]
}

validate_compatibility() {
  [[ $1 =~ ^openapi-sha256:[0-9a-f]{64}$ ]]
}

validate_image_ref() {
  local reference=$1 digest
  [[ -n ${EXPECTED_WEB_REPOSITORY} && ${reference} == "${EXPECTED_WEB_REPOSITORY}@sha256:"* ]] ||
    return 1
  digest=${reference#"${EXPECTED_WEB_REPOSITORY}@sha256:"}
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]]
}

validate_single_line() {
  [[ $1 != *$'\n'* && $1 != *$'\r'* ]]
}

load_deploy_policy() {
  require_private_file "${DEPLOY_POLICY_FILE}" "deployment policy"
  awk -F= '
    NF != 2 {exit 1}
    $1 !~ /^(GITHUB_REPOSITORY|NODE_NAME|HOST_PORT|API_HOST_PORT|EDGE_SUBNET|API_IP|WEB_IP|MONITORING_NETWORK)$/ {exit 1}
    seen[$1]++ > 0 {exit 1}
    END {
      required["GITHUB_REPOSITORY"] = required["NODE_NAME"] = required["HOST_PORT"] = 1
      required["EDGE_SUBNET"] = required["API_IP"] = required["WEB_IP"] = 1
      for (key in required) if (!seen[key]) exit 1
    }
  ' "${DEPLOY_POLICY_FILE}" || die "deployment policy is malformed"
  POLICY_GITHUB_REPOSITORY=$(state_value "${DEPLOY_POLICY_FILE}" GITHUB_REPOSITORY)
  POLICY_NODE_NAME=$(state_value "${DEPLOY_POLICY_FILE}" NODE_NAME)
  POLICY_HOST_PORT=$(state_value "${DEPLOY_POLICY_FILE}" HOST_PORT)
  POLICY_API_HOST_PORT=$(state_value "${DEPLOY_POLICY_FILE}" API_HOST_PORT 2>/dev/null || printf '18081\n')
  [[ ${POLICY_GITHUB_REPOSITORY} =~ ^[A-Za-z0-9-]+/alert-hub$ ]] ||
    die "deployment policy repository is invalid"
  [[ ${POLICY_NODE_NAME} =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] ||
    die "deployment policy node name is invalid"
  [[ ${POLICY_HOST_PORT} != "${PREVIEW_HOST_PORT}" && ${POLICY_API_HOST_PORT} != "${PREVIEW_HOST_PORT}" ]] ||
    die "preview host port collides with a production listener"
}

validate_production_state() {
  require_private_file "${PRODUCTION_STATE_FILE}" "production deployment state"
  awk -F= '
    NF != 2 {exit 1}
    $1 !~ /^(NODE_NAME|API_REF|API_VERSION|API_COMPATIBILITY|WEB_REF|WEB_VERSION|WEB_COMPATIBILITY|CONFIG_SHA256|DEPLOYED_AT|LAST_BACKUP|PEER_TRANSPORT)$/ {exit 1}
    seen[$1]++ > 0 {exit 1}
    END {
      required["NODE_NAME"] = required["API_REF"] = required["API_COMPATIBILITY"] = 1
      for (key in required) if (!seen[key]) exit 1
    }
  ' "${PRODUCTION_STATE_FILE}" || die "production deployment state is malformed"
  [[ $(state_value "${PRODUCTION_STATE_FILE}" NODE_NAME) == "${POLICY_NODE_NAME}" ]] ||
    die "production deployment state belongs to another node"
}

validate_preview_state() {
  require_private_file "${PREVIEW_STATE_FILE}" "preview deployment state"
  awk -F= '
    NF != 2 {exit 1}
    $1 !~ /^(IMAGE_REF|REVISION|COMPATIBILITY|DEPLOYED_AT)$/ {exit 1}
    seen[$1]++ > 0 {exit 1}
    END {
      required["IMAGE_REF"] = required["REVISION"] = required["COMPATIBILITY"] = required["DEPLOYED_AT"] = 1
      for (key in required) if (!seen[key]) exit 1
    }
  ' "${PREVIEW_STATE_FILE}" || die "preview deployment state is malformed"
  validate_image_ref "$(state_value "${PREVIEW_STATE_FILE}" IMAGE_REF)" ||
    die "preview deployment state contains an invalid image reference"
  validate_revision "$(state_value "${PREVIEW_STATE_FILE}" REVISION)" ||
    die "preview deployment state contains an invalid revision"
  validate_compatibility "$(state_value "${PREVIEW_STATE_FILE}" COMPATIBILITY)" ||
    die "preview deployment state contains invalid compatibility"
}

inspect_label() {
  docker image inspect "$1" --format "{{index .Config.Labels \"$2\"}}"
}

start_registry_auth() {
  : "${GHCR_TOKEN:?GHCR_TOKEN is required}"
  [[ ${GITHUB_ACTOR} =~ ^[A-Za-z0-9-]+$ ]] || die "GITHUB_ACTOR is invalid"
  AUTH_DIR=$(mktemp -d /run/alert-hub-preview-docker-auth.XXXXXX)
  chmod 0700 "${AUTH_DIR}"
  export DOCKER_CONFIG=${AUTH_DIR}
  printf '%s' "${GHCR_TOKEN}" |
    docker login ghcr.io --username "${GITHUB_ACTOR}" --password-stdin >/dev/null
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  set +e
  if [[ -n ${AUTH_DIR} && ${AUTH_DIR} == /run/alert-hub-preview-docker-auth.* && -d ${AUTH_DIR} ]]; then
    docker logout ghcr.io >/dev/null 2>&1 || true
    find "${AUTH_DIR}" -mindepth 1 -maxdepth 2 -type f -delete 2>/dev/null || true
    find "${AUTH_DIR}" -mindepth 1 -maxdepth 2 -type d -empty -delete 2>/dev/null || true
    rmdir "${AUTH_DIR}" 2>/dev/null || true
  fi
  exit "${exit_status}"
}

pull_and_verify_image() {
  local reference=$1 revision=$2 compatibility=$3
  local component actual_revision actual_version actual_compatibility schema_compatibility source

  validate_image_ref "${reference}" || die "preview image reference is not an immutable Alert Hub web digest"
  validate_revision "${revision}" || die "preview revision must be a full lowercase commit SHA"
  validate_compatibility "${compatibility}" || die "preview compatibility is invalid"
  docker pull "${reference}" >/dev/null || die "could not pull preview web image"
  component=$(inspect_label "${reference}" org.alert-hub.component)
  actual_revision=$(inspect_label "${reference}" org.opencontainers.image.revision)
  actual_version=$(inspect_label "${reference}" org.opencontainers.image.version)
  actual_compatibility=$(inspect_label "${reference}" org.alert-hub.compatibility)
  schema_compatibility=$(inspect_label "${reference}" org.alert-hub.schema-compatibility)
  source=$(inspect_label "${reference}" org.opencontainers.image.source)
  [[ ${component} == web ]] || die "preview image has the wrong component label"
  [[ ${actual_revision} == "${revision}" ]] || die "preview image revision label does not match the push"
  [[ ${actual_version} == "dev-${revision}" ]] || die "preview image version label does not match the push"
  [[ ${actual_compatibility} == "${compatibility}" ]] ||
    die "preview image compatibility label does not match the workflow"
  [[ ${schema_compatibility} == n-1-expand-contract ]] ||
    die "preview image does not declare N-1 schema compatibility"
  [[ ${source} == "https://github.com/${POLICY_GITHUB_REPOSITORY}" ]] ||
    die "preview image source label does not match the deployment policy"
}

compose() {
  local image_ref=$1
  shift
  env \
    ALERT_HUB_PREVIEW_WEB_IMAGE="${image_ref}" \
    ALERT_HUB_PREVIEW_HOST_PORT="${PREVIEW_HOST_PORT}" \
    APP_NAME="${APP_NAME}" \
    docker compose --project-name alert-hub-dev-preview --file "${COMPOSE_FILE}" "$@"
}

container_healthy() {
  local status health
  status=$(docker container inspect "${PREVIEW_CONTAINER}" --format '{{.State.Status}}' 2>/dev/null || true)
  health=$(docker container inspect "${PREVIEW_CONTAINER}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || true)
  [[ ${status} == running && ${health} == healthy ]]
}

container_uses_image() {
  [[ $(docker container inspect "${PREVIEW_CONTAINER}" --format '{{.Config.Image}}' 2>/dev/null || true) == "$1" ]]
}

wait_preview_healthy() {
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    if container_healthy; then
      return 0
    fi
    sleep 2
  done
  return 1
}

container_has_exact_networks() {
  local output candidate expected found
  local -a actual=()
  output=$(docker container inspect "${PREVIEW_CONTAINER}" \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
    2>/dev/null) || return 1
  while IFS= read -r candidate; do
    [[ -z ${candidate} ]] || actual+=("${candidate}")
  done <<<"${output}"
  ((${#actual[@]} == 2)) || return 1
  for expected in alert-hub-edge alert-hub-ingress; do
    found=false
    for candidate in "${actual[@]}"; do
      if [[ ${candidate} == "${expected}" ]]; then
        found=true
        break
      fi
    done
    [[ ${found} == true ]] || return 1
  done
}

container_has_exact_port_binding() {
  local output
  output=$(docker container inspect "${PREVIEW_CONTAINER}" \
    --format '{{range $containerPort, $bindings := .HostConfig.PortBindings}}{{printf "%s=" $containerPort}}{{range $bindings}}{{printf "%s:%s," .HostIp .HostPort}}{{end}}{{println}}{{end}}' \
    2>/dev/null) || return 1
  [[ ${output} == "8080/tcp=127.0.0.1:${PREVIEW_HOST_PORT}," ]]
}

verify_preview_ready() {
  wait_preview_healthy || return 1
  container_has_exact_networks || return 1
  container_has_exact_port_binding || return 1
  curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:${PREVIEW_HOST_PORT}/health/ready" >/dev/null || return 1
  curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:${PREVIEW_HOST_PORT}/" >/dev/null || return 1
  curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:${PREVIEW_HOST_PORT}/runtime-config.js" >/dev/null || return 1
}

apply_preview() {
  local image_ref=$1
  compose "${image_ref}" up --detach --no-build --no-deps --force-recreate alert-hub-web-preview ||
    return 1
  container_uses_image "${image_ref}" || return 1
  verify_preview_ready
}

write_preview_state() {
  local image_ref=$1 revision=$2 compatibility=$3 temporary
  temporary=$(mktemp "${PREVIEW_STATE_DIR}/.current.env.XXXXXX")
  printf '%s\n' \
    "IMAGE_REF=${image_ref}" \
    "REVISION=${revision}" \
    "COMPATIBILITY=${compatibility}" \
    "DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${temporary}"
  chown root:root "${temporary}"
  chmod 0600 "${temporary}"
  mv -f -- "${temporary}" "${PREVIEW_STATE_FILE}"
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ $# -eq 0 ]] || die "docker-deploy-preview-node.sh does not accept arguments"
require_commands
script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
require_root_controlled_file "${script_path}" "preview deployment script"
require_root_controlled_file "${COMPOSE_FILE}" "preview Compose file"
require_private_file "${LOCK_FILE}" "deployment lock"
exec 9<>"${LOCK_FILE}"
flock -n 9 || die "another deployment, rollback, preview, or provisioning operation is running"
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
load_deploy_policy

: "${NODE_NAME:?NODE_NAME is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_ACTOR:?GITHUB_ACTOR is required}"
: "${ALERT_HUB_PREVIEW_IMAGE:?ALERT_HUB_PREVIEW_IMAGE is required}"
: "${ALERT_HUB_PREVIEW_REVISION:?ALERT_HUB_PREVIEW_REVISION is required}"
: "${ALERT_HUB_PREVIEW_COMPATIBILITY:?ALERT_HUB_PREVIEW_COMPATIBILITY is required}"
APP_NAME=${APP_NAME:-Alert Hub Preview}
[[ ${GITHUB_REPOSITORY} == "${POLICY_GITHUB_REPOSITORY}" ]] ||
  die "workflow repository does not match the root-owned deployment policy"
[[ ${NODE_NAME} == "${POLICY_NODE_NAME}" ]] ||
  die "workflow node does not match the root-owned deployment policy"
validate_single_line "${APP_NAME}" || die "APP_NAME must be a single line"
[[ -n ${APP_NAME} && ${#APP_NAME} -le 80 ]] || die "APP_NAME must contain 1 to 80 characters"
registry_owner=$(printf '%s' "${POLICY_GITHUB_REPOSITORY%%/*}" | tr '[:upper:]' '[:lower:]')
EXPECTED_WEB_REPOSITORY=ghcr.io/${registry_owner}/alert-hub-web

validate_production_state
recorded_production_compatibility=$(state_value "${PRODUCTION_STATE_FILE}" API_COMPATIBILITY)
validate_compatibility "${recorded_production_compatibility}" ||
  die "recorded production API compatibility is invalid"
api_status=$(docker container inspect "${API_CONTAINER}" --format '{{.State.Status}}' 2>/dev/null || true)
api_health=$(docker container inspect "${API_CONTAINER}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || true)
[[ ${api_status} == running && ${api_health} == healthy ]] ||
  die "production API must be healthy before preview deployment"
production_compatibility=$(docker container inspect "${API_CONTAINER}" \
  --format '{{index .Config.Labels "org.alert-hub.compatibility"}}' 2>/dev/null || true)
validate_compatibility "${production_compatibility}" ||
  die "running production API compatibility is invalid"
[[ ${production_compatibility} == "${recorded_production_compatibility}" ]] ||
  die "running production API does not match recorded compatibility"
[[ ${ALERT_HUB_PREVIEW_COMPATIBILITY} == "${production_compatibility}" ]] ||
  die "preview web is not compatible with the running production API"
docker network inspect alert-hub-edge >/dev/null 2>&1 || die "alert-hub-edge network is unavailable"
docker network inspect alert-hub-ingress >/dev/null 2>&1 || die "alert-hub-ingress network is unavailable"

if [[ -e ${PREVIEW_STATE_DIR} || -L ${PREVIEW_STATE_DIR} ]]; then
  require_root_directory "${PREVIEW_STATE_DIR}" "preview state directory"
else
  install -d -o root -g root -m 0700 "${PREVIEW_STATE_DIR}"
fi
previous_image=""
previous_revision=""
previous_compatibility=""
if [[ -e ${PREVIEW_STATE_FILE} || -L ${PREVIEW_STATE_FILE} ]]; then
  validate_preview_state
  previous_image=$(state_value "${PREVIEW_STATE_FILE}" IMAGE_REF)
  previous_revision=$(state_value "${PREVIEW_STATE_FILE}" REVISION)
  previous_compatibility=$(state_value "${PREVIEW_STATE_FILE}" COMPATIBILITY)
fi

trap cleanup EXIT
start_registry_auth
pull_and_verify_image \
  "${ALERT_HUB_PREVIEW_IMAGE}" \
  "${ALERT_HUB_PREVIEW_REVISION}" \
  "${ALERT_HUB_PREVIEW_COMPATIBILITY}"

if [[ ${previous_image} == "${ALERT_HUB_PREVIEW_IMAGE}" ]] &&
  container_uses_image "${ALERT_HUB_PREVIEW_IMAGE}" && verify_preview_ready; then
  log "Preview already runs the requested immutable image"
  exit 0
fi

log "Deploying frontend preview ${ALERT_HUB_PREVIEW_REVISION} on 127.0.0.1:${PREVIEW_HOST_PORT}"
if ! apply_preview "${ALERT_HUB_PREVIEW_IMAGE}"; then
  log "Preview candidate failed readiness"
  if [[ -n ${previous_image} && ${previous_compatibility} == "${production_compatibility}" ]]; then
    log "Restoring previous preview ${previous_revision}"
    if ! apply_preview "${previous_image}"; then
      die "preview candidate failed and the previous preview could not be restored"
    fi
    die "preview candidate failed readiness; the previous preview was restored"
  fi
  compose "${ALERT_HUB_PREVIEW_IMAGE}" rm --stop --force alert-hub-web-preview >/dev/null 2>&1 || true
  die "preview candidate failed readiness; no compatible previous preview was available"
fi

write_preview_state \
  "${ALERT_HUB_PREVIEW_IMAGE}" \
  "${ALERT_HUB_PREVIEW_REVISION}" \
  "${ALERT_HUB_PREVIEW_COMPATIBILITY}"
log "Frontend preview deployment completed"

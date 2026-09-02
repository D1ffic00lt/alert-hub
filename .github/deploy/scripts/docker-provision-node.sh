#!/bin/bash
set -Eeuo pipefail

# Provision the fixed root-owned deployment boundary from a reviewed checkout.
# GitHub runner registration and its short-lived registration token are
# deliberately outside this script.
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly INSTALL_ROOT=/opt/alert-hub
readonly CONFIG_ROOT=/etc/alert-hub
readonly INSTALL_SBIN=/usr/local/sbin
readonly SUDOERS_DIRECTORY=/etc/sudoers.d
readonly SUDOERS_FILE=${SUDOERS_DIRECTORY}/alert-hub-deploy
readonly POLICY_FILE=${CONFIG_ROOT}/deploy-policy.env
readonly COMPOSE_FILE=${CONFIG_ROOT}/docker-compose.production.yml
readonly MONITORING_COMPOSE_FILE=${CONFIG_ROOT}/docker-compose.production-monitoring.yml
readonly LOCK_FILE=${INSTALL_ROOT}/.deploy.lock
readonly PROXY_INSTALLER_FILE=${INSTALL_SBIN}/install-proxy-config.sh
readonly BACKUP_TOOL_FILE=${INSTALL_SBIN}/alert-hub-backup
readonly BACKUP_CONFIG_FILE=${CONFIG_ROOT}/backup.env
readonly DEFAULT_BACKUP_DIR=${INSTALL_ROOT}/backups
# Kept outside the six-key legacy policy unless explicitly overridden, so an
# existing node can refresh its root-owned boundary without a topology rewrite.
readonly DEFAULT_API_HOST_PORT=18081

declare -a BOUNDARY_SOURCES=()
declare -a BOUNDARY_DESTINATIONS=()
declare -a BOUNDARY_MODES=()
declare -a BOUNDARY_BACKUPS=()
declare -a BOUNDARY_EXISTED=()
declare -a BOUNDARY_STAGED=()
ACTIVATION_STARTED=false
ACTIVATION_COMPLETE=false
PRESERVE_RECOVERY_MATERIAL=false
BACKUP_DIRECTORY_CREATED=false

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  docker-provision-node.sh \
    --source-dir /path/to/reviewed/alert-hub \
    --runner-user USER \
    --repository OWNER/alert-hub \
    --node-name NODE \
    --host-port PORT \
    --edge-subnet RFC1918_CIDR \
    --api-ip RFC1918_IPV4 \
    --web-ip RFC1918_IPV4 \
    [--api-host-port PORT] \
    [--monitoring-network EXISTING_DOCKER_NETWORK]

Run as root on the target node. This installs only local root-owned files and a
narrow sudoers rule. Register the repository-scoped GitHub runner separately;
this command never accepts or reads a GitHub registration token.
EOF
  exit 2
}

require_commands() {
  local command_name
  for command_name in awk basename bash chmod chown cmp cp date dirname docker env find flock getent grep id install mktemp mv python3 readlink rm rmdir sha256sum sort stat tr visudo; do
    command -v "${command_name}" >/dev/null || die "required command is missing: ${command_name}"
  done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
}

validate_backup_runtime() {
  python3 - <<'PY' || die "Python 3.9+ with sqlite3 backup support is required"
import sqlite3
import sys

if sys.version_info < (3, 9) or not hasattr(sqlite3.Connection, "backup"):
    raise SystemExit(1)
PY
}

validate_runner_user() {
  local runner_user=$1 runner_uid
  [[ ${runner_user} =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "runner user name is invalid"
  getent passwd "${runner_user}" >/dev/null || die "runner user does not exist"
  runner_uid=$(id -u "${runner_user}")
  [[ ${runner_uid} =~ ^[0-9]+$ && ${runner_uid} != 0 ]] || die "runner user must be a dedicated non-root account"
  if id -nG "${runner_user}" | tr ' ' '\n' | grep -Fxq docker; then
    die "runner user must not belong to the docker group"
  fi
}

validate_repository() {
  [[ $1 =~ ^[A-Za-z0-9-]+/alert-hub$ ]] || die "repository must be OWNER/alert-hub"
}

validate_node_name() {
  [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "node name is invalid"
}

validate_host_port() {
  if [[ ! $1 =~ ^[1-9][0-9]{0,4}$ ]] || ((10#$1 > 65535)); then
    die "host port is invalid"
  fi
}

validate_private_ipv4() {
  local address=$1 first second octet
  local -a octets

  [[ ${address} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a octets <<<"${address}"
  ((${#octets[@]} == 4)) || return 1
  for octet in "${octets[@]}"; do
    [[ ${octet} == 0 || ${octet} =~ ^[1-9][0-9]{0,2}$ ]] || return 1
    ((10#${octet} <= 255)) || return 1
  done
  first=$((10#${octets[0]}))
  second=$((10#${octets[1]}))
  (( first == 10 || (first == 172 && second >= 16 && second <= 31) || (first == 192 && second == 168) ))
}

ipv4_to_integer() {
  local address=$1
  local -a octets
  IFS=. read -r -a octets <<<"${address}"
  printf '%u\n' "$((
    (10#${octets[0]} << 24) |
      (10#${octets[1]} << 16) |
      (10#${octets[2]} << 8) |
      10#${octets[3]}
  ))"
}

validate_private_cidr() {
  local cidr=$1 network prefix network_integer mask
  [[ ${cidr} == */* ]] || return 1
  network=${cidr%/*}
  prefix=${cidr##*/}
  validate_private_ipv4 "${network}" || return 1
  [[ ${prefix} =~ ^[0-9]+$ ]] || return 1
  ((10#${prefix} >= 16 && 10#${prefix} <= 29)) || return 1
  network_integer=$(ipv4_to_integer "${network}")
  mask=$(((0xFFFFFFFF << (32 - 10#${prefix})) & 0xFFFFFFFF))
  (( (network_integer & mask) == network_integer ))
}

usable_address_in_cidr() {
  local address=$1 cidr=$2 network prefix address_integer network_integer mask broadcast
  validate_private_ipv4 "${address}" || return 1
  validate_private_cidr "${cidr}" || return 1
  network=${cidr%/*}
  prefix=${cidr##*/}
  address_integer=$(ipv4_to_integer "${address}")
  network_integer=$(ipv4_to_integer "${network}")
  mask=$(((0xFFFFFFFF << (32 - 10#${prefix})) & 0xFFFFFFFF))
  broadcast=$((network_integer | ((~mask) & 0xFFFFFFFF)))
  (( (address_integer & mask) == network_integer )) &&
    (( address_integer > network_integer + 1 )) &&
    (( address_integer < broadcast ))
}

validate_monitoring_network() {
  local network_name=$1 driver scope internal masquerade inter_container subnets
  [[ -z ${network_name} ]] && return 0
  [[ ${#network_name} -le 128 && ${network_name} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
    die "monitoring network name is invalid"
  [[ ${network_name} != bridge && ${network_name} != host && ${network_name} != none ]] ||
    die "monitoring network must be a user-defined bridge"
  [[ ${network_name} != alert-hub-edge && ${network_name} != alert-hub-egress && ${network_name} != alert-hub-ingress ]] ||
    die "monitoring network collides with an application network"
  docker network inspect "${network_name}" >/dev/null 2>&1 ||
    die "configured monitoring Docker network does not exist"
  driver=$(docker network inspect "${network_name}" --format '{{.Driver}}')
  scope=$(docker network inspect "${network_name}" --format '{{.Scope}}')
  internal=$(docker network inspect "${network_name}" --format '{{.Internal}}')
  masquerade=$(docker network inspect "${network_name}" --format '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}')
  inter_container=$(docker network inspect "${network_name}" --format '{{index .Options "com.docker.network.bridge.enable_icc"}}')
  subnets=$(docker network inspect "${network_name}" --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}')
  [[ ${driver} == bridge && ${scope} == local && ${internal} == false ]] ||
    die "monitoring network must be a non-internal local bridge"
  [[ -z ${masquerade} || ${masquerade} == '<no value>' || ${masquerade} == true ]] ||
    die "monitoring network must permit masqueraded outbound traffic"
  [[ -z ${inter_container} || ${inter_container} == '<no value>' || ${inter_container} == true ]] ||
    die "monitoring network must permit API-to-monitoring traffic"
  grep -Eq '(^|[[:space:]])([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}($|[[:space:]])' <<<"${subnets}" ||
    die "monitoring network must have an IPv4 subnet"
}

require_root_directory() {
  local path=$1 description=$2 owner mode mode_value
  [[ -d ${path} && ! -L ${path} ]] || die "${description} must be a real directory: ${path}"
  owner=$(stat -c '%u' -- "${path}")
  mode=$(stat -c '%a' -- "${path}")
  [[ ${owner} == 0 && ${mode} =~ ^[0-7]{3,4}$ ]] || die "${description} ownership or mode is invalid"
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || die "${description} must not be group/other writable"
}

require_root_directory_chain() {
  local current=$1
  while :; do
    require_root_directory "${current}" "reviewed source directory"
    [[ ${current} == / ]] && break
    current=$(dirname -- "${current}")
  done
}

require_root_controlled_file() {
  local path=$1 description=$2 owner mode mode_value
  [[ -f ${path} && ! -L ${path} ]] || die "${description} must be a regular non-symlink: ${path}"
  owner=$(stat -c '%u' -- "${path}")
  mode=$(stat -c '%a' -- "${path}")
  [[ ${owner} == 0 && ${mode} =~ ^[0-7]{3,4}$ ]] || die "${description} ownership or mode is invalid: ${path}"
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || die "${description} must not be group/other writable: ${path}"
}

require_exact_root_file() {
  local path=$1 expected_mode=$2 description=$3
  require_root_controlled_file "${path}" "${description}"
  [[ $(stat -c '%a' -- "${path}") == "${expected_mode}" ]] ||
    die "${description} must have mode ${expected_mode}: ${path}"
}

require_exact_root_directory() {
  local path=$1 expected_mode=$2 description=$3
  require_root_directory "${path}" "${description}"
  [[ $(stat -c '%a' -- "${path}") == "${expected_mode}" ]] ||
    die "${description} must have mode ${expected_mode}: ${path}"
}

write_policy_candidate() {
  local target=$1 repository=$2 node_name=$3 host_port=$4 edge_subnet=$5 api_ip=$6 web_ip=$7
  local monitoring_network=$8 api_host_port=${9:-}

  printf '%s\n' \
    "GITHUB_REPOSITORY=${repository}" \
    "NODE_NAME=${node_name}" \
    "HOST_PORT=${host_port}" \
    "EDGE_SUBNET=${edge_subnet}" \
    "API_IP=${api_ip}" \
    "WEB_IP=${web_ip}" >"${target}"
  if [[ -n ${api_host_port} ]]; then
    printf 'API_HOST_PORT=%s\n' "${api_host_port}" >>"${target}"
  fi
  if [[ -n ${monitoring_network} ]]; then
    printf 'MONITORING_NETWORK=%s\n' "${monitoring_network}" >>"${target}"
  fi
  chmod 0600 "${target}"
}

read_policy_node_name() {
  local policy=$1 line node_name="" seen=false
  while IFS= read -r line || [[ -n ${line} ]]; do
    if [[ ${line} == NODE_NAME=* ]]; then
      [[ ${seen} == false ]] || die "deployment policy contains duplicate NODE_NAME"
      node_name=${line#NODE_NAME=}
      seen=true
    fi
  done <"${policy}"
  [[ ${seen} == true ]] || die "deployment policy is missing NODE_NAME"
  validate_node_name "${node_name}"
  printf '%s\n' "${node_name}"
}

validate_backup_path() {
  local path=$1 segment
  local -a segments
  [[ ${path} =~ ^/[A-Za-z0-9._/-]+$ && ${path} != / && ${path} != */ && ${path} != *//* ]] ||
    return 1
  IFS=/ read -r -a segments <<<"${path}"
  for segment in "${segments[@]}"; do
    [[ ${segment} != . && ${segment} != .. ]] || return 1
  done
}

validate_backup_config() {
  local config=$1 expected_node_name=$2 line key value line_number=0
  local configured_node_name="" database_path=/opt/alert-hub/data/alert-hub.db
  local backup_dir=${DEFAULT_BACKUP_DIR} seen_keys='|'

  while IFS= read -r line || [[ -n ${line} ]]; do
    ((line_number += 1))
    [[ -z ${line} || ${line} == \#* ]] && continue
    [[ ${line} =~ ^([A-Z_]+)=([^[:space:]]+)$ ]] ||
      die "existing backup config has an invalid line ${line_number}"
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    case ${seen_keys} in
      *"|${key}|"*) die "existing backup config contains duplicate key: ${key}" ;;
    esac
    seen_keys=${seen_keys}${key}'|'

    case ${key} in
      NODE_NAME)
        validate_node_name "${value}"
        [[ ${value} == "${expected_node_name}" ]] ||
          die "existing backup config NODE_NAME does not match deployment policy"
        configured_node_name=${value}
        ;;
      DATABASE_PATH)
        validate_backup_path "${value}" || die "existing backup config DATABASE_PATH is unsafe"
        database_path=${value}
        ;;
      BACKUP_DIR)
        validate_backup_path "${value}" || die "existing backup config BACKUP_DIR is unsafe"
        backup_dir=${value}
        ;;
      CONTAINER_NAME)
        [[ ${value} =~ ^[A-Za-z0-9_.-]+$ ]] ||
          die "existing backup config CONTAINER_NAME is invalid"
        ;;
      DATABASE_UID | DATABASE_GID)
        if [[ ! ${value} =~ ^(0|[1-9][0-9]{0,9})$ ]] || ((10#${value} > 4294967294)); then
          die "existing backup config ${key} is invalid"
        fi
        ;;
      KEEP_DAILY | KEEP_WEEKLY | KEEP_MONTHLY)
        [[ ${value} =~ ^[0-9]{1,4}$ ]] ||
          die "existing backup config ${key} is invalid"
        ;;
      *) die "existing backup config contains an unsupported key: ${key}" ;;
    esac
  done <"${config}"

  [[ -n ${configured_node_name} ]] || die "existing backup config is missing NODE_NAME"
  [[ ${database_path} != "${backup_dir}" ]] ||
    die "existing backup config must use distinct database and backup paths"
}

write_backup_config_candidate() {
  local target=$1 node_name=$2
  validate_node_name "${node_name}"
  printf '%s\n' \
    "NODE_NAME=${node_name}" \
    'DATABASE_PATH=/opt/alert-hub/data/alert-hub.db' \
    "BACKUP_DIR=${DEFAULT_BACKUP_DIR}" \
    'CONTAINER_NAME=alert-hub-api' \
    'DATABASE_UID=10001' \
    'DATABASE_GID=10001' \
    'KEEP_DAILY=7' \
    'KEEP_WEEKLY=4' \
    'KEEP_MONTHLY=6' >"${target}"
  chmod 0600 "${target}"
}

prepare_backup_config_candidate() {
  local target=$1 node_name=$2 existing=${3:-${BACKUP_CONFIG_FILE}}
  if [[ -e ${existing} || -L ${existing} ]]; then
    require_exact_root_file "${existing}" 600 "existing backup config"
    validate_backup_config "${existing}" "${node_name}"
    install -m 0600 -- "${existing}" "${target}"
  else
    write_backup_config_candidate "${target}" "${node_name}"
  fi
}

read_backup_directory() {
  local config=$1 default_directory=${2:-${DEFAULT_BACKUP_DIR}} line
  while IFS= read -r line || [[ -n ${line} ]]; do
    if [[ ${line} == BACKUP_DIR=* ]]; then
      printf '%s\n' "${line#BACKUP_DIR=}"
      return 0
    fi
  done <"${config}"
  printf '%s\n' "${default_directory}"
}

prepare_backup_directory() {
  local config=$1 default_directory=${2:-${DEFAULT_BACKUP_DIR}} backup_directory
  backup_directory=$(read_backup_directory "${config}" "${default_directory}")
  if [[ -e ${backup_directory} || -L ${backup_directory} ]]; then
    require_exact_root_directory "${backup_directory}" 700 "backup directory"
    return 0
  fi
  [[ ${backup_directory} == "${default_directory}" ]] ||
    die "custom backup directory must be created as root:root mode 0700 before provisioning"
  install -d -o root -g root -m 0700 "${default_directory}"
  require_exact_root_directory "${default_directory}" 700 "backup directory"
  BACKUP_DIRECTORY_CREATED=true
}

write_sudoers_candidate() {
  local target=$1 runner_user=$2
  local preserved_environment
  preserved_environment='NODE_NAME NODE_IP PUBLIC_DOMAIN PEER_PUBLIC_URL ALERT_HUB_VERSION ALERT_HUB_COMPONENT ALERT_HUB_API_IMAGE ALERT_HUB_WEB_IMAGE ALERT_HUB_RELEASE_COMPATIBILITY CLUSTER_MASTER_KEY SESSION_SIGNING_KEY VAPID_PRIVATE_KEY GHCR_TOKEN GITHUB_ACTOR GITHUB_REPOSITORY APP_NAME PEER_URLS PEER_ALLOWED_CIDRS VAPID_PUBLIC_KEY ALERT_HUB_ROLLBACK_VERSION ALERT_HUB_CONFIRMATION'
  printf '%s\n' \
    '# Managed by Alert Hub. Runner registration is intentionally separate.' \
    "Defaults:${runner_user} !requiretty" \
    "Defaults:${runner_user} env_reset" \
    "Defaults:${runner_user} secure_path=${PATH}" \
    "Defaults:${runner_user} env_keep += \"${preserved_environment}\"" \
    "${runner_user} ALL=(root) NOPASSWD: ${INSTALL_SBIN}/docker-deploy-node.sh \"\"" \
    "${runner_user} ALL=(root) NOPASSWD: ${INSTALL_SBIN}/docker-rollback-node.sh \"\"" \
    "${runner_user} ALL=(root) NOPASSWD: ${INSTALL_SBIN}/docker-status-node.sh \"\"" \
    >"${target}"
  chmod 0440 "${target}"
}

validate_compose_sources() {
  local source_root=$1 temporary_env=$2
  local zero_digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
  local -a compose_environment=(
    ALERT_HUB_API_IMAGE="ghcr.io/invalid/alert-hub-api@${zero_digest}"
    ALERT_HUB_WEB_IMAGE="ghcr.io/invalid/alert-hub-web@${zero_digest}"
    ALERT_HUB_ENV_FILE="${temporary_env}"
    ALERT_HUB_DATA_DIR=/tmp
    ALERT_HUB_SECRETS_DIR=/tmp
    ALERT_HUB_HOST_PORT="${HOST_PORT}"
    ALERT_HUB_API_HOST_PORT="${API_HOST_PORT:-${DEFAULT_API_HOST_PORT}}"
    ALERT_HUB_API_IP="${API_IP}"
    ALERT_HUB_WEB_IP="${WEB_IP}"
    ALERT_HUB_EDGE_SUBNET="${EDGE_SUBNET}"
    MONITORING_NETWORK=alert-hub-validation-monitoring
  )

  env "${compose_environment[@]}" docker compose \
    --file "${source_root}/.github/deploy/docker-compose.production.yml" \
    config --quiet
  env "${compose_environment[@]}" docker compose \
    --file "${source_root}/.github/deploy/docker-compose.production.yml" \
    --file "${source_root}/.github/deploy/docker-compose.production-monitoring.yml" \
    config --quiet
}

prepare_install_root_and_lock() {
  install -d -o root -g root -m 0755 "${CONFIG_ROOT}"
  install -d -o root -g root -m 0700 "${INSTALL_ROOT}"
  require_root_directory "${CONFIG_ROOT}" "configuration root"
  require_root_directory "${INSTALL_ROOT}" "install root"

  if [[ ! -e ${LOCK_FILE} && ! -L ${LOCK_FILE} ]]; then
    (set -o noclobber; : >"${LOCK_FILE}") 2>/dev/null || true
  fi
  require_exact_root_file "${LOCK_FILE}" 600 "deployment lock"
  exec 9<>"${LOCK_FILE}"
  flock -n 9 || die "deployment or provisioning is already running"
}

require_immutable_policy() {
  local candidate=$1 existing=${2:-${POLICY_FILE}}
  if [[ -e ${existing} || -L ${existing} ]]; then
    require_exact_root_file "${existing}" 600 "existing deployment policy"
    cmp -s -- "${candidate}" "${existing}" ||
      die "deployment policy is immutable; use an explicitly reviewed topology migration"
  else
    [[ ! -e ${INSTALL_ROOT}/state/current.env && ! -L ${INSTALL_ROOT}/state/current.env ]] ||
      die "deployment state exists without an immutable deployment policy"
    [[ ! -e ${INSTALL_ROOT}/config/alert-hub.env && ! -L ${INSTALL_ROOT}/config/alert-hub.env ]] ||
      die "runtime config exists without an immutable deployment policy"
    ! docker container inspect alert-hub-api >/dev/null 2>&1 ||
      die "API container exists without an immutable deployment policy"
    ! docker container inspect alert-hub-web >/dev/null 2>&1 ||
      die "web container exists without an immutable deployment policy"
  fi
}

stage_boundary_file() {
  local source=$1 destination=$2 mode=$3 description=$4
  local destination_directory backup staged index
  index=${#BOUNDARY_DESTINATIONS[@]}
  destination_directory=$(dirname -- "${destination}")
  require_root_directory "${destination_directory}" "${description} destination directory"
  backup=${temporary_directory}/backup-${index}

  if [[ -e ${destination} || -L ${destination} ]]; then
    require_exact_root_file "${destination}" "${mode}" "existing ${description}"
    install -o root -g root -m "${mode}" -- "${destination}" "${backup}"
    BOUNDARY_EXISTED+=(true)
  else
    BOUNDARY_EXISTED+=(false)
  fi

  staged=$(mktemp "${destination_directory}/.alert-hub-provision.XXXXXX")
  BOUNDARY_STAGED+=("${staged}")
  install -o root -g root -m "${mode}" -- "${source}" "${staged}"
  BOUNDARY_SOURCES+=("${source}")
  BOUNDARY_DESTINATIONS+=("${destination}")
  BOUNDARY_MODES+=("${mode}")
  BOUNDARY_BACKUPS+=("${backup}")
}

restore_boundary() {
  local index destination destination_directory restore_candidate restore_failed=false
  for ((index = ${#BOUNDARY_DESTINATIONS[@]} - 1; index >= 0; index--)); do
    destination=${BOUNDARY_DESTINATIONS[index]}
    destination_directory=$(dirname -- "${destination}")
    if [[ ${BOUNDARY_EXISTED[index]} == true ]]; then
      restore_candidate=$(mktemp "${destination_directory}/.alert-hub-restore.XXXXXX") || {
        restore_failed=true
        continue
      }
      if ! install -o root -g root -m "${BOUNDARY_MODES[index]}" -- \
        "${BOUNDARY_BACKUPS[index]}" "${restore_candidate}" ||
        ! mv -f -- "${restore_candidate}" "${destination}"; then
        rm -f -- "${restore_candidate}"
        restore_failed=true
      fi
    elif ! rm -f -- "${destination}"; then
      restore_failed=true
    fi
  done
  if [[ ${restore_failed} == true ]]; then
    PRESERVE_RECOVERY_MATERIAL=true
    log "CRITICAL: boundary rollback was incomplete; recovery material remains in ${temporary_directory}"
    return 1
  fi
  if [[ -e ${SUDOERS_FILE} || -L ${SUDOERS_FILE} ]]; then
    visudo -cf "${SUDOERS_FILE}" >/dev/null || {
      PRESERVE_RECOVERY_MATERIAL=true
      log "CRITICAL: restored sudoers policy failed validation; recovery material remains in ${temporary_directory}"
      return 1
    }
  fi
  return 0
}

activate_boundary() {
  local index
  ACTIVATION_STARTED=true
  for ((index = 0; index < ${#BOUNDARY_DESTINATIONS[@]}; index++)); do
    mv -f -- "${BOUNDARY_STAGED[index]}" "${BOUNDARY_DESTINATIONS[index]}"
    BOUNDARY_STAGED[index]=""
  done
  for ((index = 0; index < ${#BOUNDARY_DESTINATIONS[@]}; index++)); do
    require_exact_root_file \
      "${BOUNDARY_DESTINATIONS[index]}" "${BOUNDARY_MODES[index]}" "installed deployment boundary"
    cmp -s -- "${BOUNDARY_SOURCES[index]}" "${BOUNDARY_DESTINATIONS[index]}" ||
      die "installed deployment boundary content verification failed"
  done
  visudo -cf "${SUDOERS_FILE}" >/dev/null || die "installed sudoers policy failed validation"
  ACTIVATION_COMPLETE=true
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
require_commands
validate_backup_runtime
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"

SOURCE_ROOT=""
RUNNER_USER=""
REPOSITORY=""
NODE_NAME=""
HOST_PORT=""
API_HOST_PORT=""
EDGE_SUBNET=""
API_IP=""
WEB_IP=""
MONITORING_NETWORK=""

while (($#)); do
  case $1 in
    --source-dir | --runner-user | --repository | --node-name | --host-port | --api-host-port | --edge-subnet | --api-ip | --web-ip | --monitoring-network)
      (($# >= 2)) || usage
      option=$1
      value=$2
      shift 2
      case ${option} in
        --source-dir) SOURCE_ROOT=${value} ;;
        --runner-user) RUNNER_USER=${value} ;;
        --repository) REPOSITORY=${value} ;;
        --node-name) NODE_NAME=${value} ;;
        --host-port) HOST_PORT=${value} ;;
        --api-host-port) API_HOST_PORT=${value} ;;
        --edge-subnet) EDGE_SUBNET=${value} ;;
        --api-ip) API_IP=${value} ;;
        --web-ip) WEB_IP=${value} ;;
        --monitoring-network) MONITORING_NETWORK=${value} ;;
      esac
      ;;
    *) usage ;;
  esac
done

for required in SOURCE_ROOT RUNNER_USER REPOSITORY NODE_NAME HOST_PORT EDGE_SUBNET API_IP WEB_IP; do
  [[ -n ${!required} ]] || die "required option is missing: ${required}"
done
[[ ! -L ${SOURCE_ROOT} && -d ${SOURCE_ROOT} ]] || die "source directory must be a real directory"
SOURCE_ROOT=$(readlink -f -- "${SOURCE_ROOT}")
require_root_directory_chain "${SOURCE_ROOT}"
validate_runner_user "${RUNNER_USER}"
validate_repository "${REPOSITORY}"
validate_node_name "${NODE_NAME}"
validate_host_port "${HOST_PORT}"
if [[ -n ${API_HOST_PORT} ]]; then
  validate_host_port "${API_HOST_PORT}"
fi
effective_api_host_port=${API_HOST_PORT:-${DEFAULT_API_HOST_PORT}}
[[ ${effective_api_host_port} != "${HOST_PORT}" ]] || die "API host port and web host port must be distinct"
validate_private_cidr "${EDGE_SUBNET}" || die "edge subnet must be a canonical private IPv4 /16 through /29"
usable_address_in_cidr "${API_IP}" "${EDGE_SUBNET}" || die "API address is not usable in the edge subnet"
usable_address_in_cidr "${WEB_IP}" "${EDGE_SUBNET}" || die "web address is not usable in the edge subnet"
[[ ${API_IP} != "${WEB_IP}" ]] || die "API and web addresses must be distinct"
validate_monitoring_network "${MONITORING_NETWORK}"
require_root_directory "${INSTALL_SBIN}" "system executable directory"
require_root_directory "${SUDOERS_DIRECTORY}" "sudoers include directory"
[[ ! -e ${CONFIG_ROOT} || ( -d ${CONFIG_ROOT} && ! -L ${CONFIG_ROOT} ) ]] ||
  die "configuration root must be a real directory"
[[ ! -e ${INSTALL_ROOT} || ( -d ${INSTALL_ROOT} && ! -L ${INSTALL_ROOT} ) ]] ||
  die "install root must be a real directory"

for relative_path in \
  .github \
  .github/deploy \
  .github/deploy/scripts \
  deploy \
  deploy/scripts; do
  require_root_directory "${SOURCE_ROOT}/${relative_path}" "reviewed source directory"
done
for relative_path in \
  .github/deploy/docker-compose.production.yml \
  .github/deploy/docker-compose.production-monitoring.yml \
  .github/deploy/scripts/docker-deploy-node.sh \
  .github/deploy/scripts/docker-rollback-node.sh \
  .github/deploy/scripts/docker-status-node.sh \
  .github/deploy/scripts/docker-provision-node.sh \
  deploy/scripts/alert-hub-backup \
  deploy/scripts/install-proxy-config.sh; do
  require_root_controlled_file "${SOURCE_ROOT}/${relative_path}" "reviewed deployment source"
done
for script_name in docker-deploy-node.sh docker-rollback-node.sh docker-status-node.sh docker-provision-node.sh; do
  bash -n "${SOURCE_ROOT}/.github/deploy/scripts/${script_name}" || die "deployment script syntax validation failed: ${script_name}"
done
bash -n "${SOURCE_ROOT}/deploy/scripts/install-proxy-config.sh" ||
  die "deployment script syntax validation failed: install-proxy-config.sh"
bash -n "${SOURCE_ROOT}/deploy/scripts/alert-hub-backup" ||
  die "deployment script syntax validation failed: alert-hub-backup"

temporary_directory=$(mktemp -d /tmp/alert-hub-provision.XXXXXX)
readonly temporary_directory
cleanup() {
  local exit_status=$? staged
  trap - EXIT
  set +e
  if [[ ${ACTIVATION_STARTED} == true && ${ACTIVATION_COMPLETE} != true ]]; then
    restore_boundary || exit_status=1
  fi
  if [[ ${ACTIVATION_COMPLETE} != true && ${BACKUP_DIRECTORY_CREATED} == true ]]; then
    if ! rmdir "${DEFAULT_BACKUP_DIR}"; then
      PRESERVE_RECOVERY_MATERIAL=true
      log "CRITICAL: newly created backup directory is not empty and was not removed"
      exit_status=1
    fi
  fi
  for staged in "${BOUNDARY_STAGED[@]}"; do
    [[ -z ${staged} ]] || rm -f -- "${staged}"
  done
  if [[ ${PRESERVE_RECOVERY_MATERIAL} != true ]]; then
    find "${temporary_directory}" -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || true
    rmdir "${temporary_directory}" 2>/dev/null || true
  fi
  exit "${exit_status}"
}
trap cleanup EXIT
policy_candidate=${temporary_directory}/deploy-policy.env
sudoers_candidate=${temporary_directory}/sudoers
compose_env=${temporary_directory}/compose.env
backup_config_candidate=${temporary_directory}/backup.env
: >"${compose_env}"
chmod 0600 "${compose_env}"
write_policy_candidate \
  "${policy_candidate}" "${REPOSITORY}" "${NODE_NAME}" "${HOST_PORT}" \
  "${EDGE_SUBNET}" "${API_IP}" "${WEB_IP}" "${MONITORING_NETWORK}" "${API_HOST_PORT}"
write_sudoers_candidate "${sudoers_candidate}" "${RUNNER_USER}"
visudo -cf "${sudoers_candidate}" >/dev/null || die "generated sudoers policy failed validation"
validate_compose_sources "${SOURCE_ROOT}" "${compose_env}"
prepare_install_root_and_lock
require_immutable_policy "${policy_candidate}"
backup_node_name=$(read_policy_node_name "${policy_candidate}")
prepare_backup_config_candidate "${backup_config_candidate}" "${backup_node_name}"
prepare_backup_directory "${backup_config_candidate}"
stage_boundary_file \
  "${SOURCE_ROOT}/.github/deploy/docker-compose.production.yml" \
  "${COMPOSE_FILE}" 644 "production Compose file"
stage_boundary_file \
  "${SOURCE_ROOT}/.github/deploy/docker-compose.production-monitoring.yml" \
  "${MONITORING_COMPOSE_FILE}" 644 "production monitoring Compose override"
stage_boundary_file \
  "${SOURCE_ROOT}/.github/deploy/scripts/docker-deploy-node.sh" \
  "${INSTALL_SBIN}/docker-deploy-node.sh" 755 "deployment engine"
stage_boundary_file \
  "${SOURCE_ROOT}/.github/deploy/scripts/docker-rollback-node.sh" \
  "${INSTALL_SBIN}/docker-rollback-node.sh" 755 "rollback wrapper"
stage_boundary_file \
  "${SOURCE_ROOT}/.github/deploy/scripts/docker-status-node.sh" \
  "${INSTALL_SBIN}/docker-status-node.sh" 755 "status wrapper"
stage_boundary_file \
  "${SOURCE_ROOT}/.github/deploy/scripts/docker-provision-node.sh" \
  "${INSTALL_SBIN}/docker-provision-node.sh" 755 "provisioning helper"
stage_boundary_file \
  "${SOURCE_ROOT}/deploy/scripts/install-proxy-config.sh" \
  "${PROXY_INSTALLER_FILE}" 755 "proxy configuration installer"
stage_boundary_file \
  "${SOURCE_ROOT}/deploy/scripts/alert-hub-backup" \
  "${BACKUP_TOOL_FILE}" 755 "backup tool"
stage_boundary_file \
  "${backup_config_candidate}" \
  "${BACKUP_CONFIG_FILE}" 600 "backup config"
stage_boundary_file "${policy_candidate}" "${POLICY_FILE}" 600 "deployment policy"
stage_boundary_file "${sudoers_candidate}" "${SUDOERS_FILE}" 440 "sudoers policy"
activate_boundary

log "Provisioned root-owned Alert Hub deployment boundary for node ${NODE_NAME}"
if [[ -n ${MONITORING_NETWORK} ]]; then
  log "Optional monitoring network attachment is enabled"
else
  log "Optional monitoring network attachment is disabled"
fi
log "Register the repository-scoped runner separately; no registration token was handled"

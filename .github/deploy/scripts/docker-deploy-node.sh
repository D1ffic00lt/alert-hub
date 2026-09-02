#!/bin/bash
set -Eeuo pipefail

# An operator provisions this file from a reviewed commit as a root-owned
# executable before enabling the protected workflow. Never enable shell tracing:
# GitHub passes production secrets in the environment and this script keeps them
# out of argv and logs.
set +x
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly INSTALL_ROOT=/opt/alert-hub
readonly CONFIG_DIR=${INSTALL_ROOT}/config
readonly STATE_DIR=${INSTALL_ROOT}/state
readonly HISTORY_DIR=${INSTALL_ROOT}/history
readonly CONFIG_HISTORY_DIR=${HISTORY_DIR}/configs
readonly DATA_DIR=${INSTALL_ROOT}/data
readonly BACKUPS_DIR=${DATA_DIR}/backups
readonly SECRETS_DIR=${INSTALL_ROOT}/secrets
readonly APP_ENV_FILE=${CONFIG_DIR}/alert-hub.env
readonly CURRENT_FILE=${STATE_DIR}/current.env
readonly LOCK_FILE=${INSTALL_ROOT}/.deploy.lock
readonly COMPOSE_FILE=/etc/alert-hub/docker-compose.production.yml
readonly MONITORING_COMPOSE_FILE=/etc/alert-hub/docker-compose.production-monitoring.yml
readonly DEPLOY_POLICY_FILE=/etc/alert-hub/deploy-policy.env
readonly API_SERVICE=alert-hub
readonly WEB_SERVICE=alert-hub-web
readonly API_CONTAINER=alert-hub-api
readonly WEB_CONTAINER=alert-hub-web
readonly API_UID=10001
readonly API_GID=10001
readonly MIN_FREE_KIB=1048576
readonly DEPLOYMENT_SMOKE_TOKEN_FILE=${SECRETS_DIR}/deployment-smoke-token
readonly ZERO_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000
readonly PLACEHOLDER_API=ghcr.io/invalid/alert-hub-api@${ZERO_DIGEST}
readonly PLACEHOLDER_WEB=ghcr.io/invalid/alert-hub-web@${ZERO_DIGEST}
readonly EXPECTED_PEER_TRANSPORT=https-peer-v1
readonly LEGACY_PEER_TRANSPORT=legacy
EXPECTED_API_REPOSITORY=""
EXPECTED_WEB_REPOSITORY=""
HOST_PORT=""
API_HOST_PORT=""
EDGE_SUBNET=""
API_IP=""
WEB_IP=""
MONITORING_NETWORK=""
COMPOSE_FILES=()

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
  docker-deploy-node.sh
  docker-deploy-node.sh rollback

The deploy workflow calls the first form. The separately installed
docker-rollback-node.sh wrapper calls the second form after validating an
explicit node-scoped confirmation.
EOF
  exit 2
}

require_commands() {
  local command_name
  for command_name in awk curl date df docker find flock grep install mktemp readlink sha256sum sort stat tr; do
    command -v "${command_name}" >/dev/null || die "required command is missing: ${command_name}"
  done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
}

available_kib() {
  local path=$1 value
  value=$(df -Pk -- "${path}" | awk 'NR == 2 {print $4; found = 1} END {if (!found) exit 1}') ||
    die "could not inspect free space for ${path}"
  [[ ${value} =~ ^[0-9]+$ ]] || die "free-space result is malformed for ${path}"
  printf '%s\n' "${value}"
}

require_free_kib() {
  local path=$1 required=$2 description=$3 available
  available=$(available_kib "${path}")
  ((available >= required)) ||
    die "${description} has less than the required $((required / 1024)) MiB free"
}

check_disk_preflight() {
  local database_bytes=0 data_required_kib docker_root sqlite_file sqlite_size

  for sqlite_file in \
    "${DATA_DIR}/alert-hub.db" \
    "${DATA_DIR}/alert-hub.db-wal" \
    "${DATA_DIR}/alert-hub.db-shm"; do
    [[ ! -L ${sqlite_file} ]] || die "SQLite storage must not contain symlinks"
    [[ ! -e ${sqlite_file} || -f ${sqlite_file} ]] || die "SQLite storage is not a regular file"
    if [[ -f ${sqlite_file} ]]; then
      sqlite_size=$(stat -c '%s' -- "${sqlite_file}")
      [[ ${sqlite_size} =~ ^[0-9]+$ ]] || die "SQLite storage size is malformed"
      database_bytes=$((database_bytes + sqlite_size))
    fi
  done
  data_required_kib=$((MIN_FREE_KIB + ((database_bytes + 1023) / 1024)))
  docker_root=$(docker info --format '{{.DockerRootDir}}')
  [[ ${docker_root} == /* && -d ${docker_root} ]] || die "Docker root directory is unavailable"
  require_free_kib "${DATA_DIR}" "${data_required_kib}" "application data filesystem"
  require_free_kib "${docker_root}" "${MIN_FREE_KIB}" "Docker storage filesystem"
  log "Disk preflight passed for application data, one online backup, and Docker storage"
}

require_root_controlled_file() {
  local path=$1
  local description=$2
  local owner mode mode_value

  [[ -f ${path} && ! -L ${path} ]] || die "${description} must be a regular file: ${path}"
  owner=$(stat -c '%u' -- "${path}")
  mode=$(stat -c '%a' -- "${path}")
  [[ ${owner} == 0 ]] || die "${description} must be owned by root: ${path}"
  [[ ${mode} =~ ^[0-7]{3,4}$ ]] || die "could not validate permissions for ${description}"
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 )) || die "${description} must not be group/other writable: ${path}"
}

require_private_file() {
  local path=$1
  local expected_owner=$2
  local description=$3

  private_file_is_valid "${path}" "${expected_owner}" ||
    die "${description} must be a regular file owned by uid ${expected_owner} with mode 0600"
}

private_file_is_valid() {
  local path=$1
  local expected_owner=$2
  local owner mode

  [[ -f ${path} && ! -L ${path} ]] || return 1
  owner=$(stat -c '%u' -- "${path}") || return 1
  mode=$(stat -c '%a' -- "${path}") || return 1
  [[ ${owner} == "${expected_owner}" && ${mode} == 600 ]]
}

validate_version() {
  [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
}

validate_compatibility() {
  [[ $1 =~ ^openapi-sha256:[0-9a-f]{64}$ ]]
}

validate_peer_transport() {
  [[ $1 == "${EXPECTED_PEER_TRANSPORT}" || $1 == "${LEGACY_PEER_TRANSPORT}" ]]
}

validate_component() {
  [[ $1 == api || $1 == web || $1 == all ]]
}

validate_image_ref() {
  local component=$1
  local reference=$2
  local expected digest
  case "${component}" in
    api) expected=${EXPECTED_API_REPOSITORY} ;;
    web) expected=${EXPECTED_WEB_REPOSITORY} ;;
    *) return 1 ;;
  esac
  [[ -n ${expected} && ${reference} == "${expected}@sha256:"* ]] || return 1
  digest=${reference#"${expected}@sha256:"}
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]]
}

validate_host_token() {
  local value=$1
  [[ -n ${value} && ${#value} -le 253 && ${value} =~ ^[A-Za-z0-9._:%-]+$ ]]
}

validate_private_ipv4() {
  local address=$1
  local first second octet
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
  # Docker normally reserves the first usable address for the bridge gateway.
  (( (address_integer & mask) == network_integer )) &&
    (( address_integer > network_integer + 1 )) &&
    (( address_integer < broadcast ))
}

validate_host_port() {
  [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

validate_docker_network_name() {
  [[ -n $1 && ${#1} -le 128 && $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
}

validate_monitoring_network() {
  local network_name=$1 driver scope internal masquerade inter_container subnets
  validate_docker_network_name "${network_name}" || die "deployment policy MONITORING_NETWORK is invalid"
  [[ ${network_name} != bridge && ${network_name} != host && ${network_name} != none ]] ||
    die "monitoring network must be a user-defined bridge"
  [[ ${network_name} != alert-hub-edge && ${network_name} != alert-hub-egress && ${network_name} != alert-hub-ingress ]] ||
    die "deployment policy MONITORING_NETWORK collides with an application network"
  docker network inspect "${network_name}" >/dev/null 2>&1 ||
    die "the configured monitoring Docker network is unavailable"
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

validate_managed_network_if_present() {
  local network_name=$1 logical_name=$2 expected_subnet=${3:-}
  local project_label logical_label actual_subnet
  docker network inspect "${network_name}" >/dev/null 2>&1 || return 0
  project_label=$(docker network inspect "${network_name}" --format '{{index .Labels "com.docker.compose.project"}}')
  logical_label=$(docker network inspect "${network_name}" --format '{{index .Labels "com.docker.compose.network"}}')
  [[ ${project_label} == alert-hub && ${logical_label} == "${logical_name}" ]] ||
    die "existing Docker network ${network_name} is not owned by the alert-hub Compose project"
  if [[ -n ${expected_subnet} ]]; then
    actual_subnet=$(docker network inspect "${network_name}" --format '{{(index .IPAM.Config 0).Subnet}}')
    [[ ${actual_subnet} == "${expected_subnet}" ]] ||
      die "existing Docker network ${network_name} does not match the inventoried subnet"
  fi
}

validate_domain() {
  local domain
  local label
  local -a labels

  domain=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')

  [[ -n ${domain} && ${#domain} -le 253 && ${domain} != .* && ${domain} != *. && ${domain} != *..* ]] || return 1
  IFS=. read -r -a labels <<<"${domain}"
  ((${#labels[@]} >= 2)) || return 1
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && ${label} =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
  done
}

validate_https_origin() {
  local origin=$1 authority host port=""

  [[ ${origin} == https://* ]] || return 1
  authority=${origin#https://}
  [[ -n ${authority} && ${authority} != */* && ${authority} != *\?* && ${authority} != *\#* && ${authority} != *@* ]] ||
    return 1
  host=${authority}
  if [[ ${authority} == *:* ]]; then
    [[ ${authority} != *:*:* ]] || return 1
    host=${authority%:*}
    port=${authority##*:}
    validate_host_port "${port}" || return 1
  fi
  [[ ${host} == *[A-Za-z]* ]] || return 1
  validate_domain "${host}"
}

validate_single_line() {
  [[ $1 != *$'\n'* && $1 != *$'\r'* ]]
}

validate_config_checksum() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

secret_is_acceptable() {
  local name=$1
  local value=$2
  [[ ${#value} -ge 32 ]] || die "${name} must contain at least 32 characters"
  [[ ${value} != *$'\r'* ]] || die "${name} contains an unsupported carriage return"
}

vapid_private_key_has_unencrypted_pem_envelope() {
  local private_key=${1%$'\n'}

  [[ -n ${private_key} && ${private_key} != *$'\r'* && ${private_key} != *$'\n' ]] || return 1
  printf '%s\n' "${private_key}" | awk '
    NR == 1 {
      pem_begin = "-----BEGIN "
      if ($0 == pem_begin "PRIVATE KEY-----") {
        footer = "-----END PRIVATE KEY-----"
      } else if ($0 == pem_begin "EC PRIVATE KEY-----") {
        footer = "-----END EC PRIVATE KEY-----"
      } else {
        exit 1
      }
      next
    }
    /ENCRYPTED/ || /^Proc-Type:/ || /^DEK-Info:/ || /^-----BEGIN / {
      exit 1
    }
    /^-----END / {
      if (found_footer || $0 != footer) {
        exit 1
      }
      found_footer = 1
      next
    }
    found_footer {
      exit 1
    }
    END {
      if (!found_footer) {
        exit 1
      }
    }
  '
}

vapid_private_key_is_p256() {
  local private_key=${1%$'\n'}

  if openssl pkey -help 2>&1 |
    grep -E -- '(^|[[:space:]])-check([[:space:]]|$)' >/dev/null; then
    printf '%s\n' "${private_key}" |
      openssl pkey -passin pass: -check -noout >/dev/null 2>&1 || return 1
  else
    printf '%s\n' "${private_key}" |
      openssl pkey -passin pass: -noout >/dev/null 2>&1 || return 1
  fi
  printf '%s\n' "${private_key}" |
    openssl pkey -passin pass: -text_pub -noout 2>/dev/null |
    grep -E '^[[:space:]]*ASN1 OID: prime256v1[[:space:]]*$' >/dev/null
}

derive_vapid_public_key() {
  local private_key=${1%$'\n'}

  printf '%s\n' "${private_key}" |
    openssl pkey -passin pass: -pubout 2>/dev/null |
    openssl ec \
      -pubin \
      -conv_form uncompressed \
      -param_enc named_curve \
      -outform DER 2>/dev/null |
    tail -c 65 |
    openssl base64 -A 2>/dev/null |
    tr '+/' '-_' |
    tr -d '='
}

validate_vapid_material() {
  local private_key=$1
  local public_key=$2
  local derived_public_key

  if ! vapid_private_key_has_unencrypted_pem_envelope "${private_key}" ||
    ! vapid_private_key_is_p256 "${private_key}"; then
    die "VAPID_PRIVATE_KEY must be an unencrypted PEM EC private key on P-256"
  fi
  derived_public_key=$(derive_vapid_public_key "${private_key}") ||
    die "could not derive the VAPID public key"
  [[ ${derived_public_key} =~ ^B[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$ ]] ||
    die "derived VAPID public key is malformed"

  if [[ -n ${public_key} ]]; then
    [[ ${public_key} =~ ^B[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$ ]] ||
      die "VAPID_PUBLIC_KEY must be a canonical unpadded base64url P-256 public point"
    [[ ${public_key} == "${derived_public_key}" ]] ||
      die "VAPID_PUBLIC_KEY does not match VAPID_PRIVATE_KEY"
  fi
  log "VAPID key material preflight passed"
}

preflight_vapid_material() {
  local operation=$1
  local component=$2
  local command_name

  [[ ${operation} == deploy && ( ${component} == api || ${component} == all ) ]] || return 0
  : "${VAPID_PRIVATE_KEY:?VAPID_PRIVATE_KEY is required for API deployment}"
  for command_name in openssl tail; do
    command -v "${command_name}" >/dev/null || die "required VAPID preflight command is missing: ${command_name}"
  done
  validate_vapid_material "${VAPID_PRIVATE_KEY}" "${VAPID_PUBLIC_KEY:-}"
}

state_value() {
  local file=$1
  local key=$2
  awk -F= -v wanted="${key}" '$1 == wanted {print substr($0, index($0, "=") + 1); found = 1; exit} END {if (!found) exit 1}' "${file}"
}

state_peer_transport() {
  local file=$1
  state_value "${file}" PEER_TRANSPORT 2>/dev/null || printf '%s\n' "${LEGACY_PEER_TRANSPORT}"
}

load_deploy_policy() {
  require_private_file "${DEPLOY_POLICY_FILE}" 0 "deployment policy"
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
  HOST_PORT=$(state_value "${DEPLOY_POLICY_FILE}" HOST_PORT)
  # Legacy six-key policies predate the separate loopback API listener.
  API_HOST_PORT=$(state_value "${DEPLOY_POLICY_FILE}" API_HOST_PORT 2>/dev/null || printf '18081\n')
  EDGE_SUBNET=$(state_value "${DEPLOY_POLICY_FILE}" EDGE_SUBNET)
  API_IP=$(state_value "${DEPLOY_POLICY_FILE}" API_IP)
  WEB_IP=$(state_value "${DEPLOY_POLICY_FILE}" WEB_IP)
  MONITORING_NETWORK=$(state_value "${DEPLOY_POLICY_FILE}" MONITORING_NETWORK 2>/dev/null || true)
  [[ ${POLICY_GITHUB_REPOSITORY} =~ ^[A-Za-z0-9-]+/alert-hub$ ]] || die "deployment policy repository is invalid"
  [[ ${POLICY_NODE_NAME} =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "deployment policy node name is invalid"
  validate_host_port "${HOST_PORT}" || die "deployment policy HOST_PORT is invalid"
  validate_host_port "${API_HOST_PORT}" || die "deployment policy API_HOST_PORT is invalid"
  [[ ${API_HOST_PORT} != "${HOST_PORT}" ]] || die "deployment policy API_HOST_PORT and HOST_PORT must be distinct"
  validate_private_cidr "${EDGE_SUBNET}" || die "deployment policy EDGE_SUBNET must be a canonical private IPv4 /16 through /29"
  usable_address_in_cidr "${API_IP}" "${EDGE_SUBNET}" || die "deployment policy API_IP is not usable in EDGE_SUBNET"
  usable_address_in_cidr "${WEB_IP}" "${EDGE_SUBNET}" || die "deployment policy WEB_IP is not usable in EDGE_SUBNET"
  [[ ${API_IP} != "${WEB_IP}" ]] || die "deployment policy API_IP and WEB_IP must be distinct"
  if [[ -n ${MONITORING_NETWORK} ]]; then
    validate_docker_network_name "${MONITORING_NETWORK}" || die "deployment policy MONITORING_NETWORK is invalid"
  fi
}

configure_compose_files() {
  COMPOSE_FILES=(--file "${COMPOSE_FILE}")
  if [[ -n ${MONITORING_NETWORK} ]]; then
    require_root_controlled_file "${MONITORING_COMPOSE_FILE}" "production monitoring Compose override"
    validate_monitoring_network "${MONITORING_NETWORK}"
    COMPOSE_FILES+=(--file "${MONITORING_COMPOSE_FILE}")
  fi
}

validate_state_file() {
  local file=$1 peer_transport
  require_private_file "${file}" 0 "deployment state"
  awk -F= '
    NF != 2 {exit 1}
    $1 !~ /^(NODE_NAME|API_REF|API_VERSION|API_COMPATIBILITY|WEB_REF|WEB_VERSION|WEB_COMPATIBILITY|CONFIG_SHA256|DEPLOYED_AT|LAST_BACKUP|PEER_TRANSPORT)$/ {exit 1}
    seen[$1]++ > 0 {exit 1}
    END {
      required["NODE_NAME"] = required["API_REF"] = required["API_VERSION"] = 1
      required["API_COMPATIBILITY"] = required["WEB_REF"] = required["WEB_VERSION"] = 1
      required["WEB_COMPATIBILITY"] = required["CONFIG_SHA256"] = required["DEPLOYED_AT"] = 1
      required["LAST_BACKUP"] = 1
      for (key in required) if (!seen[key]) exit 1
    }
  ' "${file}" || die "deployment state is malformed: ${file}"
  peer_transport=$(state_peer_transport "${file}")
  validate_peer_transport "${peer_transport}" ||
    die "deployment state has an unsupported peer transport: ${file}"
}

config_snapshot_path() {
  local checksum=$1
  validate_config_checksum "${checksum}" || die "runtime config checksum is invalid"
  printf '%s/sha256-%s.env\n' "${CONFIG_HISTORY_DIR}" "${checksum}"
}

file_checksum() {
  sha256sum "$1" | awk '{print $1}'
}

verify_config_snapshot() {
  local checksum=$1 snapshot actual
  snapshot=$(config_snapshot_path "${checksum}")
  require_private_file "${snapshot}" 0 "runtime config snapshot"
  actual=$(file_checksum "${snapshot}")
  [[ ${actual} == "${checksum}" ]] || die "runtime config snapshot checksum mismatch"
}

validate_state_config() {
  local api_ref=$1 checksum=$2
  if [[ -n ${api_ref} ]]; then
    validate_config_checksum "${checksum}" || die "state contains an invalid runtime config checksum"
    verify_config_snapshot "${checksum}"
  else
    [[ -z ${checksum} ]] || die "state has a runtime config checksum without an API image"
  fi
}

require_active_config_checksum() {
  local expected=$1 actual
  validate_config_checksum "${expected}" || die "active runtime config checksum is invalid"
  require_private_file "${APP_ENV_FILE}" 0 "runtime application config"
  actual=$(file_checksum "${APP_ENV_FILE}")
  [[ ${actual} == "${expected}" ]] || die "active runtime config does not match deployment state"
}

store_config_snapshot() {
  local source=$1 checksum snapshot
  require_private_file "${source}" 0 "candidate runtime config"
  checksum=$(file_checksum "${source}")
  validate_config_checksum "${checksum}" || die "could not calculate the runtime config checksum"
  snapshot=$(config_snapshot_path "${checksum}")
  if [[ -e ${snapshot} || -L ${snapshot} ]]; then
    verify_config_snapshot "${checksum}"
  else
    install -o root -g root -m 0600 -- "${source}" "${snapshot}"
    verify_config_snapshot "${checksum}"
  fi
  printf '%s\n' "${checksum}"
}

activate_config_snapshot() {
  local checksum=$1 snapshot temporary
  verify_config_snapshot "${checksum}"
  snapshot=$(config_snapshot_path "${checksum}")
  temporary=$(mktemp "${CONFIG_DIR}/.alert-hub.env.XXXXXX")
  install -o root -g root -m 0600 -- "${snapshot}" "${temporary}"
  [[ $(file_checksum "${temporary}") == "${checksum}" ]] || die "copied runtime config checksum mismatch"
  mv -f -- "${temporary}" "${APP_ENV_FILE}"
  require_active_config_checksum "${checksum}"
}

remove_active_config() {
  if [[ -e ${APP_ENV_FILE} || -L ${APP_ENV_FILE} ]]; then
    rm -f -- "${APP_ENV_FILE}"
  fi
}

validate_state_values() {
  local api_ref=$1 api_version=$2 api_compatibility=$3
  local web_ref=$4 web_version=$5 web_compatibility=$6

  if [[ -n ${api_ref} ]]; then
    validate_image_ref api "${api_ref}" || die "state contains an invalid API image reference"
    validate_version "${api_version}" || die "state contains an invalid API version"
    validate_compatibility "${api_compatibility}" || die "state contains invalid API compatibility"
  else
    [[ -z ${api_version} && -z ${api_compatibility} ]] || die "state has API metadata without an API image"
  fi
  if [[ -n ${web_ref} ]]; then
    validate_image_ref web "${web_ref}" || die "state contains an invalid web image reference"
    validate_version "${web_version}" || die "state contains an invalid web version"
    validate_compatibility "${web_compatibility}" || die "state contains invalid web compatibility"
    [[ -n ${api_ref} ]] || die "a deployed web image requires a deployed API image"
  else
    [[ -z ${web_version} && -z ${web_compatibility} ]] || die "state has web metadata without a web image"
  fi
  if [[ -n ${api_ref} && -n ${web_ref} ]]; then
    [[ ${api_compatibility} == "${web_compatibility}" ]] || die "deployed API and web compatibility labels differ"
  fi
}

write_state() {
  local api_ref=$1 api_version=$2 api_compatibility=$3
  local web_ref=$4 web_version=$5 web_compatibility=$6 config_checksum=$7 last_backup=$8
  local peer_transport=$9 temporary

  validate_peer_transport "${peer_transport}" || die "refusing to record an unsupported peer transport"
  validate_state_values \
    "${api_ref}" "${api_version}" "${api_compatibility}" \
    "${web_ref}" "${web_version}" "${web_compatibility}"
  validate_state_config "${api_ref}" "${config_checksum}"
  if [[ -n ${api_ref} ]]; then
    require_active_config_checksum "${config_checksum}"
  fi
  temporary=$(mktemp "${STATE_DIR}/.current.env.XXXXXX")
  printf '%s\n' \
    "NODE_NAME=${NODE_NAME}" \
    "API_REF=${api_ref}" \
    "API_VERSION=${api_version}" \
    "API_COMPATIBILITY=${api_compatibility}" \
    "WEB_REF=${web_ref}" \
    "WEB_VERSION=${web_version}" \
    "WEB_COMPATIBILITY=${web_compatibility}" \
    "PEER_TRANSPORT=${peer_transport}" \
    "CONFIG_SHA256=${config_checksum}" \
    "DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "LAST_BACKUP=${last_backup}" >"${temporary}"
  chown root:root "${temporary}"
  chmod 0600 "${temporary}"
  mv -f -- "${temporary}" "${CURRENT_FILE}"
}

snapshot_current_state() {
  local snapshot config_checksum api_ref
  [[ -f ${CURRENT_FILE} ]] || return 0
  validate_state_file "${CURRENT_FILE}"
  api_ref=$(state_value "${CURRENT_FILE}" API_REF)
  config_checksum=$(state_value "${CURRENT_FILE}" CONFIG_SHA256)
  validate_state_config "${api_ref}" "${config_checksum}"
  if [[ -n ${api_ref} ]]; then
    require_active_config_checksum "${config_checksum}"
  fi
  snapshot=${HISTORY_DIR}/$(date -u +%Y%m%dT%H%M%SZ)-$$.env
  [[ ! -e ${snapshot} && ! -L ${snapshot} ]] || die "deployment state snapshot already exists"
  install -o root -g root -m 0600 -- "${CURRENT_FILE}" "${snapshot}"
  validate_state_file "${snapshot}"
}

install_secret_if_unchanged() {
  local name=$1
  local content=$2
  local target=${SECRETS_DIR}/${name}
  local expected_hash existing_hash temporary

  expected_hash=$(printf '%s\n' "${content}" | sha256sum | awk '{print $1}')
  if [[ -e ${target} ]]; then
    require_private_file "${target}" "${API_UID}" "runtime secret ${name}"
    existing_hash=$(sha256sum "${target}" | awk '{print $1}')
    [[ ${existing_hash} == "${expected_hash}" ]] ||
      die "refusing to rotate ${name} during an image deployment"
    return 0
  fi

  temporary=$(mktemp "${SECRETS_DIR}/.${name}.XXXXXX")
  printf '%s\n' "${content}" >"${temporary}"
  chown "${API_UID}:${API_GID}" "${temporary}"
  chmod 0600 "${temporary}"
  mv -- "${temporary}" "${target}"
}

derive_cluster_secret() {
  local context=$1
  {
    printf '%s\0' "${context}"
    printf '%s' "${CLUSTER_MASTER_KEY}"
  } | sha256sum | awk '{print $1}'
}

write_runtime_material() {
  local master_key cluster_bearer deployment_smoke_token sync_enabled temporary

  secret_is_acceptable CLUSTER_MASTER_KEY "${CLUSTER_MASTER_KEY}"
  secret_is_acceptable SESSION_SIGNING_KEY "${SESSION_SIGNING_KEY}"
  secret_is_acceptable VAPID_PRIVATE_KEY "${VAPID_PRIVATE_KEY}"
  [[ ${CLUSTER_MASTER_KEY} != "${SESSION_SIGNING_KEY}" && ${CLUSTER_MASTER_KEY} != "${VAPID_PRIVATE_KEY}" && ${SESSION_SIGNING_KEY} != "${VAPID_PRIVATE_KEY}" ]] ||
    die "production cryptographic secrets must be distinct"

  master_key=$(derive_cluster_secret alert-hub/master-encryption-key/v1)
  cluster_bearer=$(derive_cluster_secret alert-hub/cluster-bearer/v1)
  deployment_smoke_token=$(derive_cluster_secret alert-hub/deployment-smoke/v1)
  [[ ${master_key} != "${cluster_bearer}" && ${cluster_bearer} != "${SESSION_SIGNING_KEY}" && ${deployment_smoke_token} != "${cluster_bearer}" ]] ||
    die "derived production secrets are not distinct"

  install_secret_if_unchanged master-encryption-key "${master_key}"
  install_secret_if_unchanged cluster-bearer-secret "${cluster_bearer}"
  install_secret_if_unchanged token-signing-key "${SESSION_SIGNING_KEY}"
  install_secret_if_unchanged vapid-private-key.pem "${VAPID_PRIVATE_KEY}"
  install_secret_if_unchanged deployment-smoke-token "${deployment_smoke_token}"

  sync_enabled=false
  if [[ -n ${PEER_URLS:-} ]]; then
    : "${PEER_ALLOWED_CIDRS:?PEER_ALLOWED_CIDRS is required when PEER_URLS is configured}"
    sync_enabled=true
  fi
  validate_single_line "${PEER_URLS:-}" || die "PEER_URLS must be a single line"
  validate_single_line "${PEER_ALLOWED_CIDRS:-127.0.0.0/8,::1/128}" || die "PEER_ALLOWED_CIDRS must be a single line"
  validate_single_line "${VAPID_PUBLIC_KEY:-}" || die "VAPID_PUBLIC_KEY must be a single line"
  validate_single_line "${APP_NAME}" || die "APP_NAME must be a single line"
  [[ -n ${APP_NAME} && ${#APP_NAME} -le 80 ]] || die "APP_NAME must contain 1 to 80 characters"
  : "${PEER_PUBLIC_URL:?PEER_PUBLIC_URL is required for API deployment}"
  validate_https_origin "${PEER_PUBLIC_URL}" ||
    die "PEER_PUBLIC_URL must be an exact HTTPS origin with a DNS host and no path"
  PEER_PUBLIC_URL=$(printf '%s' "${PEER_PUBLIC_URL}" | tr '[:upper:]' '[:lower:]')

  temporary=$(mktemp "${CONFIG_DIR}/.alert-hub.env.XXXXXX")
  printf '%s\n' \
    "APP_NAME=${APP_NAME}" \
    'ENVIRONMENT=production' \
    'LOG_LEVEL=INFO' \
    'LOG_FORMAT=json' \
    "NODE_ID=${NODE_NAME}" \
    "NODE_NAME=${NODE_NAME}" \
    "NODE_REGION=${NODE_NAME}" \
    "DEPLOYMENT_NODE_IP=${NODE_IP}" \
    "PUBLIC_API_URL=https://${PUBLIC_DOMAIN}" \
    "PRIVATE_PEER_URL=${PEER_PUBLIC_URL}" \
    'DATABASE_URL=sqlite:////data/alert-hub.db' \
    'AUTO_CREATE_SCHEMA=false' \
    'MIGRATE_ON_START=true' \
    'BOOTSTRAP_TOKEN_FILE=/data/bootstrap-token' \
    "TRUSTED_ORIGINS=https://${PUBLIC_DOMAIN}" \
    'COOKIE_SECURE=true' \
    "TRUSTED_PROXY_CIDRS=127.0.0.0/8,::1/128,${WEB_IP}/32" \
    "SYNC_ENABLED=${sync_enabled}" \
    "PEER_URLS=${PEER_URLS:-}" \
    "PEER_ALLOWED_CIDRS=${PEER_ALLOWED_CIDRS:-127.0.0.0/8,::1/128}" \
    'SIGNING_KEY_FILE=/run/secrets/token-signing-key' \
    'CLUSTER_SECRET_FILE=/run/secrets/cluster-bearer-secret' \
    'MASTER_ENCRYPTION_KEY_FILE=/run/secrets/master-encryption-key' \
    'VAPID_PRIVATE_KEY_FILE=/run/secrets/vapid-private-key.pem' \
    "VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY:-}" \
    "VAPID_SUBJECT=mailto:ops@${PUBLIC_DOMAIN}" \
    'UI_ENABLED=false' >"${temporary}"
  chown root:root "${temporary}"
  chmod 0600 "${temporary}"
  CANDIDATE_CONFIG_SHA256=$(store_config_snapshot "${temporary}")
  rm -f -- "${temporary}"
}

require_runtime_material() {
  [[ -n ${CURRENT_CONFIG_SHA256:-} ]] || die "deployment state has no runtime config checksum"
  require_active_config_checksum "${CURRENT_CONFIG_SHA256}"
  require_private_file "${SECRETS_DIR}/master-encryption-key" "${API_UID}" "master encryption key"
  require_private_file "${SECRETS_DIR}/cluster-bearer-secret" "${API_UID}" "cluster bearer secret"
  require_private_file "${SECRETS_DIR}/token-signing-key" "${API_UID}" "session signing key"
  require_private_file "${SECRETS_DIR}/vapid-private-key.pem" "${API_UID}" "VAPID private key"
  require_private_file "${DEPLOYMENT_SMOKE_TOKEN_FILE}" "${API_UID}" "deployment smoke token"
}

inspect_label() {
  docker image inspect "$1" --format "{{index .Config.Labels \"$2\"}}"
}

pull_and_verify_image() {
  local component=$1 reference=$2 expected_version=$3 expected_compatibility=$4
  local actual_component actual_version actual_compatibility schema_compatibility

  validate_image_ref "${component}" "${reference}" || die "invalid immutable ${component} image reference"
  validate_version "${expected_version}" || die "invalid expected ${component} version"
  validate_compatibility "${expected_compatibility}" || die "invalid expected ${component} compatibility"
  log "Pulling and verifying ${component} ${expected_version}"
  docker pull "${reference}" >/dev/null || die "could not pull the immutable ${component} image"
  actual_component=$(inspect_label "${reference}" org.alert-hub.component)
  actual_version=$(inspect_label "${reference}" org.opencontainers.image.version)
  actual_compatibility=$(inspect_label "${reference}" org.alert-hub.compatibility)
  [[ ${actual_component} == "${component}" ]] || die "${component} image has the wrong component label"
  [[ ${actual_version} == "${expected_version}" ]] || die "${component} image version label does not match the release manifest"
  [[ ${actual_compatibility} == "${expected_compatibility}" ]] || die "${component} image compatibility label does not match the release manifest"
  if [[ ${component} == api ]]; then
    schema_compatibility=$(inspect_label "${reference}" org.alert-hub.schema-compatibility)
    [[ ${schema_compatibility} == n-1-expand-contract ]] || die "API image does not declare N-1 schema compatibility"
  fi
}

compose() {
  local api_ref=${1:-}
  local web_ref=${2:-}
  local migrate_on_start=$3
  local runtime_app_name
  shift 3

  require_private_file "${APP_ENV_FILE}" 0 "runtime application config"
  runtime_app_name=$(state_value "${APP_ENV_FILE}" APP_NAME)
  validate_single_line "${runtime_app_name}" || die "runtime APP_NAME must be a single line"
  [[ -n ${runtime_app_name} && ${#runtime_app_name} -le 80 ]] || die "runtime APP_NAME must contain 1 to 80 characters"
  env \
    ALERT_HUB_API_IMAGE="${api_ref:-${PLACEHOLDER_API}}" \
    ALERT_HUB_WEB_IMAGE="${web_ref:-${PLACEHOLDER_WEB}}" \
    ALERT_HUB_ENV_FILE="${APP_ENV_FILE}" \
    ALERT_HUB_DATA_DIR="${DATA_DIR}" \
    ALERT_HUB_SECRETS_DIR="${SECRETS_DIR}" \
    ALERT_HUB_HOST_PORT="${HOST_PORT}" \
    ALERT_HUB_API_HOST_PORT="${API_HOST_PORT}" \
    ALERT_HUB_API_IP="${API_IP}" \
    ALERT_HUB_WEB_IP="${WEB_IP}" \
    ALERT_HUB_EDGE_SUBNET="${EDGE_SUBNET}" \
    APP_NAME="${runtime_app_name}" \
    MIGRATE_ON_START="${migrate_on_start}" \
    MONITORING_NETWORK="${MONITORING_NETWORK}" \
    docker compose --project-name alert-hub "${COMPOSE_FILES[@]}" "$@"
}

wait_container_healthy() {
  local container=$1
  local attempt status health
  for ((attempt = 1; attempt <= 45; attempt++)); do
    status=$(docker container inspect "${container}" --format '{{.State.Status}}' 2>/dev/null || true)
    health=$(docker container inspect "${container}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || true)
    if [[ ${status} == running && ${health} == healthy ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

container_has_exact_port_binding() {
  local container=$1 expected_ip=$2 expected_port=$3 output
  output=$(docker container inspect "${container}" \
    --format '{{range $containerPort, $bindings := .HostConfig.PortBindings}}{{printf "%s=" $containerPort}}{{range $bindings}}{{printf "%s:%s," .HostIp .HostPort}}{{end}}{{println}}{{end}}' \
    2>/dev/null) || return 1
  [[ ${output} == "8080/tcp=${expected_ip}:${expected_port}," ]]
}

container_has_exact_network_address() {
  local container=$1 network=$2 expected_ip=$3 actual_ip
  actual_ip=$(docker container inspect "${container}" \
    --format "{{with index .NetworkSettings.Networks \"${network}\"}}{{.IPAddress}}{{end}}" \
    2>/dev/null) || return 1
  [[ ${actual_ip} == "${expected_ip}" ]]
}

verify_target_ready() {
  local api_ref=$1 web_ref=$2

  if [[ -n ${api_ref} ]]; then
    wait_container_healthy "${API_CONTAINER}" || return 1
    container_has_exact_network_address "${API_CONTAINER}" alert-hub-edge "${API_IP}" || return 1
    container_has_exact_port_binding "${API_CONTAINER}" 127.0.0.1 "${API_HOST_PORT}" || return 1
    curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${API_HOST_PORT}/health/ready" >/dev/null || return 1
  fi
  if [[ -n ${web_ref} ]]; then
    wait_container_healthy "${WEB_CONTAINER}" || return 1
    container_has_exact_network_address "${WEB_CONTAINER}" alert-hub-edge "${WEB_IP}" || return 1
    container_has_exact_port_binding "${WEB_CONTAINER}" 127.0.0.1 "${HOST_PORT}" || return 1
    curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${HOST_PORT}/health/ready" >/dev/null || return 1
    curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${HOST_PORT}/" >/dev/null || return 1
    curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${HOST_PORT}/runtime-config.js" >/dev/null || return 1
  fi
}

cleanup_smoke_dir() {
  if [[ -n ${SMOKE_DIR:-} && ${SMOKE_DIR} == /run/alert-hub-smoke.* && -d ${SMOKE_DIR} ]]; then
    find "${SMOKE_DIR}" -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || true
    rmdir "${SMOKE_DIR}" 2>/dev/null || true
  fi
  SMOKE_DIR=""
}

verify_runtime_smoke() {
  local api_ref=$1 smoke_source smoke_token smoke_url smoke_status=0

  [[ -n ${api_ref} ]] || return 1
  log "Running database-read and authenticated ingest smoke tests"
  docker exec "${API_CONTAINER}" \
    curl --fail --silent --show-error --max-time 5 \
    http://127.0.0.1:8080/health/deep >/dev/null || return 1

  private_file_is_valid "${DEPLOYMENT_SMOKE_TOKEN_FILE}" "${API_UID}" || return 1
  smoke_source=$(
    docker exec --interactive "${API_CONTAINER}" \
      python -m alert_hub.deployment_smoke <"${DEPLOYMENT_SMOKE_TOKEN_FILE}"
  ) || return 1
  [[ ${smoke_source} =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] ||
    return 1

  SMOKE_DIR=$(mktemp -d /run/alert-hub-smoke.XXXXXX) || return 1
  chmod 0700 "${SMOKE_DIR}"
  IFS= read -r smoke_token <"${DEPLOYMENT_SMOKE_TOKEN_FILE}" || smoke_status=1
  if ((smoke_status == 0)); then
    [[ ${smoke_token} =~ ^[0-9a-f]{64}$ ]] || smoke_status=1
  fi
  if ((smoke_status == 0)); then
    printf 'header = "Authorization: Bearer %s"\n' "${smoke_token}" >"${SMOKE_DIR}/curl.conf"
    chmod 0600 "${SMOKE_DIR}/curl.conf"
  fi
  unset smoke_token

  smoke_url="http://127.0.0.1:${API_HOST_PORT}/ingest/v1/heartbeat/${smoke_source}"
  if ((smoke_status == 0)); then
    curl \
      --config "${SMOKE_DIR}/curl.conf" \
      --proto '=http' \
      --fail \
      --silent \
      --show-error \
      --max-time 10 \
      --request POST \
      --output "${SMOKE_DIR}/response.json" \
      "${smoke_url}" || smoke_status=1
  fi
  if ((smoke_status == 0)); then
    grep -Eq '"received_at"[[:space:]]*:' "${SMOKE_DIR}/response.json" || smoke_status=1
  fi
  cleanup_smoke_dir
  ((smoke_status == 0))
}

remove_service_container() {
  local container=$1
  if docker container inspect "${container}" >/dev/null 2>&1; then
    docker container rm --force "${container}" >/dev/null
  fi
}

stop_component_containers() {
  local component=$1
  if [[ ${component} == web || ${component} == all ]]; then
    remove_service_container "${WEB_CONTAINER}"
  fi
  if [[ ${component} == api || ${component} == all ]]; then
    remove_service_container "${API_CONTAINER}"
  fi
}

apply_target() {
  local component=$1 api_ref=$2 web_ref=$3 migrate_on_start=$4

  compose "${api_ref}" "${web_ref}" "${migrate_on_start}" config --quiet

  if [[ ${component} == api || ${component} == all ]]; then
    if [[ -n ${api_ref} ]]; then
      compose "${api_ref}" "${web_ref}" "${migrate_on_start}" up --detach --no-deps --force-recreate "${API_SERVICE}"
      wait_container_healthy "${API_CONTAINER}" || return 1
    else
      [[ ${component} == all ]] && remove_service_container "${WEB_CONTAINER}"
      remove_service_container "${API_CONTAINER}"
    fi
  fi

  if [[ ${component} == web || ${component} == all ]]; then
    if [[ -n ${web_ref} ]]; then
      compose "${api_ref}" "${web_ref}" "${migrate_on_start}" up --detach --no-deps --force-recreate "${WEB_SERVICE}"
    else
      remove_service_container "${WEB_CONTAINER}"
    fi
  fi

  verify_target_ready "${api_ref}" "${web_ref}" &&
    verify_runtime_smoke "${api_ref}" "${web_ref}"
}

restore_recorded_deployment() {
  local component=$1 api_ref=$2 web_ref=$3 config_checksum=$4

  stop_component_containers "${component}"
  if [[ -n ${api_ref} ]]; then
    # The old process must never be started with the failed candidate's config.
    activate_config_snapshot "${config_checksum}"
    apply_target "${component}" "${api_ref}" "${web_ref}" false
  else
    [[ -z ${web_ref} && -z ${config_checksum} ]] || die "empty deployment state is inconsistent"
    remove_active_config
  fi
}

make_database_backup() {
  local api_ref=$1
  local backup_name backup_path

  [[ -f ${DATA_DIR}/alert-hub.db ]] || return 0
  backup_name=pre-deploy-$(date -u +%Y%m%dT%H%M%SZ)-$$.db
  backup_path=${BACKUPS_DIR}/${backup_name}
  log "Creating an online SQLite backup before the API migration"
  docker run --rm \
    --network none \
    --read-only \
    --user "${API_UID}:${API_GID}" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --volume "${DATA_DIR}:/data" \
    --entrypoint python \
    "${api_ref}" \
    -c 'import sqlite3,sys; source=sqlite3.connect("file:/data/alert-hub.db?mode=ro", uri=True); target=sqlite3.connect(sys.argv[1]); source.backup(target); result=target.execute("PRAGMA integrity_check").fetchone(); target.close(); source.close(); raise SystemExit(0 if result and result[0] == "ok" else 1)' \
    "/data/backups/${backup_name}" >/dev/null
  chown "${API_UID}:${API_GID}" "${backup_path}"
  chmod 0600 "${backup_path}"
  LAST_BACKUP=${backup_path}
}

selected_refs_equal_current() {
  local component=$1 target_api_ref=$2 target_web_ref=$3
  case "${component}" in
    api) [[ ${target_api_ref} == "${CURRENT_API_REF}" ]] ;;
    web) [[ ${target_web_ref} == "${CURRENT_WEB_REF}" ]] ;;
    all) [[ ${target_api_ref} == "${CURRENT_API_REF}" && ${target_web_ref} == "${CURRENT_WEB_REF}" ]] ;;
  esac
}

selected_deployment_is_current() {
  local component=$1 target_api_ref=$2 target_web_ref=$3 target_config_checksum=$4

  selected_refs_equal_current "${component}" "${target_api_ref}" "${target_web_ref}" || return 1
  [[ ${component} == web || ${target_config_checksum} == "${CURRENT_CONFIG_SHA256}" ]]
}

require_current_peer_transport_compatible() {
  local component=$1 current_api_ref=$2 peer_transport=$3

  if [[ -n ${current_api_ref} && ${peer_transport} != "${EXPECTED_PEER_TRANSPORT}" ]]; then
    die "${component} deployment from legacy peer transport requires a separately reviewed one-time topology migration"
  fi
}

load_current_state() {
  CURRENT_API_REF=""
  CURRENT_API_VERSION=""
  CURRENT_API_COMPATIBILITY=""
  CURRENT_WEB_REF=""
  CURRENT_WEB_VERSION=""
  CURRENT_WEB_COMPATIBILITY=""
  CURRENT_PEER_TRANSPORT=${LEGACY_PEER_TRANSPORT}
  CURRENT_CONFIG_SHA256=""
  LAST_BACKUP=""

  if [[ -f ${CURRENT_FILE} ]]; then
    validate_state_file "${CURRENT_FILE}"
    [[ $(state_value "${CURRENT_FILE}" NODE_NAME) == "${NODE_NAME}" ]] || die "deployment state belongs to a different node"
    CURRENT_API_REF=$(state_value "${CURRENT_FILE}" API_REF)
    CURRENT_API_VERSION=$(state_value "${CURRENT_FILE}" API_VERSION)
    CURRENT_API_COMPATIBILITY=$(state_value "${CURRENT_FILE}" API_COMPATIBILITY)
    CURRENT_WEB_REF=$(state_value "${CURRENT_FILE}" WEB_REF)
    CURRENT_WEB_VERSION=$(state_value "${CURRENT_FILE}" WEB_VERSION)
    CURRENT_WEB_COMPATIBILITY=$(state_value "${CURRENT_FILE}" WEB_COMPATIBILITY)
    CURRENT_PEER_TRANSPORT=$(state_peer_transport "${CURRENT_FILE}")
    CURRENT_CONFIG_SHA256=$(state_value "${CURRENT_FILE}" CONFIG_SHA256)
    LAST_BACKUP=$(state_value "${CURRENT_FILE}" LAST_BACKUP)
    validate_state_values \
      "${CURRENT_API_REF}" "${CURRENT_API_VERSION}" "${CURRENT_API_COMPATIBILITY}" \
      "${CURRENT_WEB_REF}" "${CURRENT_WEB_VERSION}" "${CURRENT_WEB_COMPATIBILITY}"
    validate_state_config "${CURRENT_API_REF}" "${CURRENT_CONFIG_SHA256}"
    if [[ -n ${CURRENT_API_REF} ]]; then
      require_active_config_checksum "${CURRENT_CONFIG_SHA256}"
    elif [[ -e ${APP_ENV_FILE} || -L ${APP_ENV_FILE} ]]; then
      die "runtime config exists for an empty deployment state"
    fi
  elif docker container inspect "${API_CONTAINER}" >/dev/null 2>&1 || docker container inspect "${WEB_CONTAINER}" >/dev/null 2>&1; then
    die "containers exist without trusted deployment state; adopt them manually before automation"
  elif [[ -e ${APP_ENV_FILE} || -L ${APP_ENV_FILE} ]]; then
    die "runtime config exists without trusted deployment state; recover or remove it manually"
  fi
}

verify_target_images() {
  local api_ref=$1 api_version=$2 api_compatibility=$3
  local web_ref=$4 web_version=$5 web_compatibility=$6

  validate_state_values "${api_ref}" "${api_version}" "${api_compatibility}" "${web_ref}" "${web_version}" "${web_compatibility}"
  if [[ -n ${api_ref} ]]; then
    pull_and_verify_image api "${api_ref}" "${api_version}" "${api_compatibility}"
  fi
  if [[ -n ${web_ref} ]]; then
    pull_and_verify_image web "${web_ref}" "${web_version}" "${web_compatibility}"
  fi
}

history_matches_request() {
  local file=$1 requested=$2 component=$3
  local api_ref api_version api_compatibility web_ref web_version web_compatibility config_checksum peer_transport

  validate_state_file "${file}"
  api_ref=$(state_value "${file}" API_REF)
  api_version=$(state_value "${file}" API_VERSION)
  api_compatibility=$(state_value "${file}" API_COMPATIBILITY)
  web_ref=$(state_value "${file}" WEB_REF)
  web_version=$(state_value "${file}" WEB_VERSION)
  web_compatibility=$(state_value "${file}" WEB_COMPATIBILITY)
  peer_transport=$(state_peer_transport "${file}")
  config_checksum=$(state_value "${file}" CONFIG_SHA256)
  validate_state_values \
    "${api_ref}" "${api_version}" "${api_compatibility}" \
    "${web_ref}" "${web_version}" "${web_compatibility}"
  validate_state_config "${api_ref}" "${config_checksum}"

  case "${component}" in
    api)
      [[ ${peer_transport} == "${EXPECTED_PEER_TRANSPORT}" ]] || return 1
      [[ -n ${api_ref} && ${api_ref} != "${CURRENT_API_REF}" ]] || return 1
      [[ -z ${CURRENT_WEB_REF} || ${api_compatibility} == "${CURRENT_WEB_COMPATIBILITY}" ]] || return 1
      [[ ${requested} == previous || ${api_version} == "${requested}" ]]
      ;;
    web)
      [[ -n ${web_ref} && ${web_ref} != "${CURRENT_WEB_REF}" ]] || return 1
      [[ -n ${CURRENT_API_REF} && ${web_compatibility} == "${CURRENT_API_COMPATIBILITY}" ]] || return 1
      [[ ${requested} == previous || ${web_version} == "${requested}" ]]
      ;;
    all)
      [[ ${peer_transport} == "${EXPECTED_PEER_TRANSPORT}" ]] || return 1
      [[ ${api_ref} != "${CURRENT_API_REF}" || ${web_ref} != "${CURRENT_WEB_REF}" ]] || return 1
      [[ ${requested} == previous || ( ${api_version} == "${requested}" && ${web_version} == "${requested}" ) ]]
      ;;
  esac
}

select_rollback_state() {
  local requested=$1 component=$2
  local _mtime candidate

  SELECTED_HISTORY=""
  while IFS='|' read -r _mtime candidate; do
    [[ -n ${candidate} ]] || continue
    if history_matches_request "${candidate}" "${requested}" "${component}"; then
      SELECTED_HISTORY=${candidate}
      return 0
    fi
  done < <(find "${HISTORY_DIR}" -maxdepth 1 -type f -name '*.env' -printf '%T@|%p\n' | sort -t '|' -k1,1nr)
  return 1
}

start_registry_auth() {
  AUTH_DIR=""
  [[ -n ${GHCR_TOKEN:-} ]] || return 0
  [[ ${GITHUB_ACTOR:-} =~ ^[A-Za-z0-9-]+$ ]] || die "GITHUB_ACTOR is invalid"
  AUTH_DIR=$(mktemp -d /run/alert-hub-docker-auth.XXXXXX)
  chmod 0700 "${AUTH_DIR}"
  export DOCKER_CONFIG=${AUTH_DIR}
  printf '%s' "${GHCR_TOKEN}" | docker login ghcr.io --username "${GITHUB_ACTOR}" --password-stdin >/dev/null
}

cleanup() {
  local exit_status=$?
  cleanup_smoke_dir
  if [[ -n ${AUTH_DIR:-} && ${AUTH_DIR} == /run/alert-hub-docker-auth.* && -d ${AUTH_DIR} ]]; then
    docker logout ghcr.io >/dev/null 2>&1 || true
    find "${AUTH_DIR}" -mindepth 1 -maxdepth 2 -type f -delete 2>/dev/null || true
    find "${AUTH_DIR}" -mindepth 1 -maxdepth 2 -type d -empty -delete 2>/dev/null || true
    rmdir "${AUTH_DIR}" 2>/dev/null || true
  fi
  exit "${exit_status}"
}

deploy_release() {
  local target_api_ref target_api_version target_api_compatibility
  local target_web_ref target_web_version target_web_compatibility target_config_checksum target_peer_transport

  require_current_peer_transport_compatible \
    "${COMPONENT}" "${CURRENT_API_REF}" "${CURRENT_PEER_TRANSPORT}"

  : "${ALERT_HUB_VERSION:?ALERT_HUB_VERSION is required}"
  : "${ALERT_HUB_API_IMAGE:?ALERT_HUB_API_IMAGE is required}"
  : "${ALERT_HUB_WEB_IMAGE:?ALERT_HUB_WEB_IMAGE is required}"
  : "${ALERT_HUB_RELEASE_COMPATIBILITY:?ALERT_HUB_RELEASE_COMPATIBILITY is required}"
  validate_version "${ALERT_HUB_VERSION}" || die "ALERT_HUB_VERSION must be vX.Y.Z"
  validate_compatibility "${ALERT_HUB_RELEASE_COMPATIBILITY}" || die "release compatibility is invalid"
  validate_image_ref api "${ALERT_HUB_API_IMAGE}" || die "release manifest API reference is not an immutable Alert Hub API image"
  validate_image_ref web "${ALERT_HUB_WEB_IMAGE}" || die "release manifest web reference is not an immutable Alert Hub web image"

  target_api_ref=${CURRENT_API_REF}
  target_api_version=${CURRENT_API_VERSION}
  target_api_compatibility=${CURRENT_API_COMPATIBILITY}
  target_web_ref=${CURRENT_WEB_REF}
  target_web_version=${CURRENT_WEB_VERSION}
  target_web_compatibility=${CURRENT_WEB_COMPATIBILITY}
  target_peer_transport=${CURRENT_PEER_TRANSPORT}
  target_config_checksum=${CURRENT_CONFIG_SHA256}
  if [[ ${COMPONENT} == api || ${COMPONENT} == all ]]; then
    target_api_ref=${ALERT_HUB_API_IMAGE}
    target_api_version=${ALERT_HUB_VERSION}
    target_api_compatibility=${ALERT_HUB_RELEASE_COMPATIBILITY}
    target_peer_transport=${EXPECTED_PEER_TRANSPORT}
  fi
  if [[ ${COMPONENT} == web || ${COMPONENT} == all ]]; then
    target_web_ref=${ALERT_HUB_WEB_IMAGE}
    target_web_version=${ALERT_HUB_VERSION}
    target_web_compatibility=${ALERT_HUB_RELEASE_COMPATIBILITY}
  fi
  [[ ${COMPONENT} != web || -n ${target_api_ref} ]] || die "web cannot be deployed before an API image"

  verify_target_images \
    "${target_api_ref}" "${target_api_version}" "${target_api_compatibility}" \
    "${target_web_ref}" "${target_web_version}" "${target_web_compatibility}"

  if [[ ${COMPONENT} == api || ${COMPONENT} == all ]]; then
    : "${CLUSTER_MASTER_KEY:?CLUSTER_MASTER_KEY is required for API deployment}"
    : "${SESSION_SIGNING_KEY:?SESSION_SIGNING_KEY is required for API deployment}"
    : "${VAPID_PRIVATE_KEY:?VAPID_PRIVATE_KEY is required for API deployment}"
    write_runtime_material
    target_config_checksum=${CANDIDATE_CONFIG_SHA256}
  else
    require_runtime_material
  fi

  if selected_deployment_is_current \
    "${COMPONENT}" "${target_api_ref}" "${target_web_ref}" "${target_config_checksum}"; then
    log "Selected component already uses the requested immutable image and runtime config; verifying readiness only"
    require_runtime_material
    verify_target_ready "${target_api_ref}" "${target_web_ref}" || die "current deployment is not ready"
    verify_runtime_smoke "${target_api_ref}" "${target_web_ref}" ||
      die "current deployment failed the database/ingest smoke gate"
    return 0
  fi

  snapshot_current_state
  if [[ ${COMPONENT} == api || ${COMPONENT} == all ]]; then
    make_database_backup "${target_api_ref}"
    activate_config_snapshot "${target_config_checksum}"
  fi

  log "Deploying ${COMPONENT} component on ${NODE_NAME}"
  if ! apply_target "${COMPONENT}" "${target_api_ref}" "${target_web_ref}" true; then
    log "Candidate readiness failed; restoring the previously recorded component image and config"
    if ! restore_recorded_deployment \
      "${COMPONENT}" "${CURRENT_API_REF}" "${CURRENT_WEB_REF}" "${CURRENT_CONFIG_SHA256}"; then
      die "candidate failed and the automatic image/config rollback also failed"
    fi
    die "candidate readiness failed; the selected component was rolled back"
  fi

  write_state \
    "${target_api_ref}" "${target_api_version}" "${target_api_compatibility}" \
    "${target_web_ref}" "${target_web_version}" "${target_web_compatibility}" \
    "${target_config_checksum}" "${LAST_BACKUP}" "${target_peer_transport}"
  log "Deployment completed successfully"
}

rollback_release() {
  local requested target_api_ref target_api_version target_api_compatibility
  local target_web_ref target_web_version target_web_compatibility target_config_checksum target_peer_transport

  : "${ALERT_HUB_ROLLBACK_VERSION:?ALERT_HUB_ROLLBACK_VERSION is required}"
  : "${ALERT_HUB_CONFIRMATION:?ALERT_HUB_CONFIRMATION is required}"
  requested=${ALERT_HUB_ROLLBACK_VERSION}
  [[ ${requested} == previous ]] || validate_version "${requested}" || die "rollback version must be previous or vX.Y.Z"
  [[ ${ALERT_HUB_CONFIRMATION} == "ROLLBACK ${NODE_NAME}" ]] || die "rollback confirmation does not match this node"
  [[ -f ${CURRENT_FILE} ]] || die "there is no recorded deployment to roll back"
  require_current_peer_transport_compatible \
    "${COMPONENT}" "${CURRENT_API_REF}" "${CURRENT_PEER_TRANSPORT}"
  require_runtime_material
  select_rollback_state "${requested}" "${COMPONENT}" || die "no compatible recorded rollback target was found"

  target_api_ref=${CURRENT_API_REF}
  target_api_version=${CURRENT_API_VERSION}
  target_api_compatibility=${CURRENT_API_COMPATIBILITY}
  target_web_ref=${CURRENT_WEB_REF}
  target_web_version=${CURRENT_WEB_VERSION}
  target_web_compatibility=${CURRENT_WEB_COMPATIBILITY}
  target_peer_transport=${CURRENT_PEER_TRANSPORT}
  target_config_checksum=${CURRENT_CONFIG_SHA256}
  if [[ ${COMPONENT} == api || ${COMPONENT} == all ]]; then
    target_api_ref=$(state_value "${SELECTED_HISTORY}" API_REF)
    target_api_version=$(state_value "${SELECTED_HISTORY}" API_VERSION)
    target_api_compatibility=$(state_value "${SELECTED_HISTORY}" API_COMPATIBILITY)
    target_peer_transport=$(state_peer_transport "${SELECTED_HISTORY}")
    target_config_checksum=$(state_value "${SELECTED_HISTORY}" CONFIG_SHA256)
  fi
  if [[ ${COMPONENT} == web || ${COMPONENT} == all ]]; then
    target_web_ref=$(state_value "${SELECTED_HISTORY}" WEB_REF)
    target_web_version=$(state_value "${SELECTED_HISTORY}" WEB_VERSION)
    target_web_compatibility=$(state_value "${SELECTED_HISTORY}" WEB_COMPATIBILITY)
  fi

  verify_target_images \
    "${target_api_ref}" "${target_api_version}" "${target_api_compatibility}" \
    "${target_web_ref}" "${target_web_version}" "${target_web_compatibility}"
  snapshot_current_state
  if [[ ${COMPONENT} == api || ${COMPONENT} == all ]]; then
    activate_config_snapshot "${target_config_checksum}"
  fi
  log "Rolling back ${COMPONENT} component on ${NODE_NAME}"
  if ! apply_target "${COMPONENT}" "${target_api_ref}" "${target_web_ref}" false; then
    log "Rollback target failed readiness; restoring the starting component image and config"
    if ! restore_recorded_deployment \
      "${COMPONENT}" "${CURRENT_API_REF}" "${CURRENT_WEB_REF}" "${CURRENT_CONFIG_SHA256}"; then
      die "rollback target failed and the starting image/config could not be restored"
    fi
    die "rollback target failed readiness; the starting image was restored"
  fi

  write_state \
    "${target_api_ref}" "${target_api_version}" "${target_api_compatibility}" \
    "${target_web_ref}" "${target_web_version}" "${target_web_compatibility}" \
    "${target_config_checksum}" "${LAST_BACKUP}" "${target_peer_transport}"
  log "Rollback completed successfully"
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
operation=${1:-deploy}
[[ $# -le 1 ]] || usage
[[ ${operation} == deploy || ${operation} == rollback ]] || usage
require_commands

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
require_root_controlled_file "${script_path}" "deployment script"
[[ -d ${INSTALL_ROOT} && ! -L ${INSTALL_ROOT} ]] || die "install root must be a real directory"
require_private_file "${LOCK_FILE}" 0 "deployment lock"
exec 9<>"${LOCK_FILE}"
flock -n 9 || die "another deployment, rollback, or provisioning operation is already running"
require_root_controlled_file "${COMPOSE_FILE}" "production Compose file"
load_deploy_policy
readonly POLICY_GITHUB_REPOSITORY POLICY_NODE_NAME HOST_PORT API_HOST_PORT EDGE_SUBNET API_IP WEB_IP MONITORING_NETWORK

: "${NODE_NAME:?NODE_NAME is required}"
: "${NODE_IP:?NODE_IP is required}"
: "${PUBLIC_DOMAIN:?PUBLIC_DOMAIN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
COMPONENT=${ALERT_HUB_COMPONENT:?ALERT_HUB_COMPONENT is required}
APP_NAME=${APP_NAME:-Alert Hub}
validate_component "${COMPONENT}" || die "ALERT_HUB_COMPONENT must be api, web, or all"
[[ ${GITHUB_REPOSITORY} == "${POLICY_GITHUB_REPOSITORY}" ]] || die "workflow repository does not match the root-owned deployment policy"
[[ ${NODE_NAME} == "${POLICY_NODE_NAME}" ]] || die "workflow node does not match the root-owned deployment policy"
registry_owner=$(printf '%s' "${POLICY_GITHUB_REPOSITORY%%/*}" | tr '[:upper:]' '[:lower:]')
EXPECTED_API_REPOSITORY=ghcr.io/${registry_owner}/alert-hub-api
EXPECTED_WEB_REPOSITORY=ghcr.io/${registry_owner}/alert-hub-web
[[ ${NODE_NAME} =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "NODE_NAME is invalid"
validate_host_token "${NODE_IP}" || die "NODE_IP is invalid"
validate_domain "${PUBLIC_DOMAIN}" || die "PUBLIC_DOMAIN must be a DNS host name"
PUBLIC_DOMAIN=$(printf '%s' "${PUBLIC_DOMAIN}" | tr '[:upper:]' '[:lower:]')
preflight_vapid_material "${operation}" "${COMPONENT}"

install -d -o root -g root -m 0700 "${CONFIG_DIR}" "${STATE_DIR}" "${HISTORY_DIR}" "${CONFIG_HISTORY_DIR}"
install -d -o root -g "${API_GID}" -m 0750 "${SECRETS_DIR}"
install -d -o "${API_UID}" -g "${API_GID}" -m 0750 "${DATA_DIR}"
install -d -o "${API_UID}" -g "${API_GID}" -m 0700 "${BACKUPS_DIR}"

AUTH_DIR=""
SMOKE_DIR=""
trap cleanup EXIT
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
configure_compose_files
check_disk_preflight
validate_managed_network_if_present alert-hub-edge edge "${EDGE_SUBNET}"
validate_managed_network_if_present alert-hub-egress egress
validate_managed_network_if_present alert-hub-ingress ingress
start_registry_auth
load_current_state

if [[ ${operation} == deploy ]]; then
  deploy_release
else
  rollback_release
fi

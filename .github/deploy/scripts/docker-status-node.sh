#!/bin/bash
set -Eeuo pipefail

umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly INSTALL_ROOT=/opt/alert-hub
readonly STATE_DIR=${INSTALL_ROOT}/state
readonly CURRENT_FILE=${STATE_DIR}/current.env
readonly APP_ENV_FILE=${INSTALL_ROOT}/config/alert-hub.env
readonly LOCK_FILE=${INSTALL_ROOT}/.deploy.lock
readonly DEPLOY_POLICY_FILE=/etc/alert-hub/deploy-policy.env
readonly MONITORING_COMPOSE_FILE=/etc/alert-hub/docker-compose.production-monitoring.yml
readonly API_CONTAINER=alert-hub-api
readonly WEB_CONTAINER=alert-hub-web
readonly EXPECTED_PEER_TRANSPORT=https-peer-v1
readonly LEGACY_PEER_TRANSPORT=legacy
POLICY_NODE_NAME=""
HOST_PORT=""
API_HOST_PORT=""
API_IP=""
WEB_IP=""
MONITORING_NETWORK=""

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

state_peer_transport() {
  state_value PEER_TRANSPORT 2>/dev/null || printf '%s\n' "${LEGACY_PEER_TRANSPORT}"
}

policy_value() {
  local key=$1
  awk -F= -v wanted="${key}" '$1 == wanted {print substr($0, index($0, "=") + 1); found = 1; exit} END {if (!found) exit 1}' "${DEPLOY_POLICY_FILE}"
}

validate_monitoring_network() {
  local network_name=$1 driver scope internal masquerade inter_container subnets
  [[ ${#network_name} -le 128 && ${network_name} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
    die "deployment policy MONITORING_NETWORK is invalid"
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

load_status_policy() {
  require_root_controlled_file "${DEPLOY_POLICY_FILE}" "deployment policy"
  [[ $(stat -c '%a' -- "${DEPLOY_POLICY_FILE}") == 600 ]] || die "deployment policy must have mode 0600"
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
  POLICY_NODE_NAME=$(policy_value NODE_NAME)
  HOST_PORT=$(policy_value HOST_PORT)
  # Match the deploy engine's backward-compatible legacy-policy default.
  API_HOST_PORT=$(policy_value API_HOST_PORT 2>/dev/null || printf '18081\n')
  API_IP=$(policy_value API_IP)
  WEB_IP=$(policy_value WEB_IP)
  MONITORING_NETWORK=$(policy_value MONITORING_NETWORK 2>/dev/null || true)
  [[ ${POLICY_NODE_NAME} =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] ||
    die "deployment policy NODE_NAME is invalid"
  if [[ ! ${HOST_PORT} =~ ^[1-9][0-9]{0,4}$ ]] || ((10#${HOST_PORT} > 65535)); then
    die "deployment policy HOST_PORT is invalid"
  fi
  if [[ ! ${API_HOST_PORT} =~ ^[1-9][0-9]{0,4}$ ]] || ((10#${API_HOST_PORT} > 65535)); then
    die "deployment policy API_HOST_PORT is invalid"
  fi
  [[ ${API_HOST_PORT} != "${HOST_PORT}" ]] ||
    die "deployment policy API_HOST_PORT and HOST_PORT must be distinct"
  if [[ -n ${MONITORING_NETWORK} ]]; then
    require_root_controlled_file "${MONITORING_COMPOSE_FILE}" "production monitoring Compose override"
    validate_monitoring_network "${MONITORING_NETWORK}"
  fi
  readonly POLICY_NODE_NAME HOST_PORT API_HOST_PORT API_IP WEB_IP MONITORING_NETWORK
}

validate_state_file() {
  local peer_transport
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
  ' "${CURRENT_FILE}" || die "deployment state is malformed"
  peer_transport=$(state_peer_transport)
  [[ ${peer_transport} == "${EXPECTED_PEER_TRANSPORT}" || ${peer_transport} == "${LEGACY_PEER_TRANSPORT}" ]] ||
    die "deployment state has an unsupported peer transport"
}

container_status() {
  local container=$1
  local status health
  status=$(docker container inspect "${container}" --format '{{.State.Status}}' 2>/dev/null || true)
  health=$(docker container inspect "${container}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || true)
  printf '%s/%s\n' "${status:-absent}" "${health:-unknown}"
}

container_has_network() {
  local container=$1 network=$2
  docker container inspect "${container}" \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' 2>/dev/null |
    grep -Fxq -- "${network}"
}

container_has_exact_networks() {
  local container=$1 expected candidate output found
  local -a actual=()
  shift
  output=$(docker container inspect "${container}" \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' 2>/dev/null) || return 1
  while IFS= read -r candidate; do
    [[ -z ${candidate} ]] || actual+=("${candidate}")
  done <<<"${output}"
  ((${#actual[@]} == $#)) || return 1
  for expected in "$@"; do
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

print_fresh_status() {
  printf 'node=%s\n' "${POLICY_NODE_NAME}"
  printf 'deployed_at=not-deployed\nconfig_sha256=not-deployed\n'
  printf 'peer_transport=not-deployed\n'
  printf 'api_version=not-deployed\napi_image=not-deployed\napi_compatibility=not-deployed\napi_status=absent/unknown\n'
  printf 'web_version=not-deployed\nweb_image=not-deployed\nweb_compatibility=not-deployed\nweb_status=absent/unknown\n'
  printf 'api_networks=not-deployed\nweb_networks=not-deployed\n'
  printf 'api_listener=127.0.0.1:%s\nweb_listener=127.0.0.1:%s\n' "${API_HOST_PORT}" "${HOST_PORT}"
  printf 'api_internal_upstream=%s:8080\nweb_internal_upstream=%s:8080\n' "${API_IP}" "${WEB_IP}"
  if [[ -n ${MONITORING_NETWORK} ]]; then
    printf 'monitoring=configured-not-deployed\n'
  else
    printf 'monitoring=disabled\n'
  fi
}

[[ ${EUID} -eq 0 ]] || die "must run as root"
for command_name in awk curl date docker flock grep readlink sha256sum stat; do
  command -v "${command_name}" >/dev/null || die "required command is missing: ${command_name}"
done
script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
require_root_controlled_file "${script_path}" "status script"
require_root_controlled_file "${LOCK_FILE}" "deployment lock"
[[ $(stat -c '%a' -- "${LOCK_FILE}") == 600 ]] || die "deployment lock must have mode 0600"
exec 9<>"${LOCK_FILE}"
flock -s 9
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
load_status_policy

if [[ ! -e ${CURRENT_FILE} && ! -L ${CURRENT_FILE} ]]; then
  [[ ! -e ${APP_ENV_FILE} && ! -L ${APP_ENV_FILE} ]] ||
    die "runtime config exists without deployment state"
  ! docker container inspect "${API_CONTAINER}" >/dev/null 2>&1 ||
    die "API container exists without deployment state"
  ! docker container inspect "${WEB_CONTAINER}" >/dev/null 2>&1 ||
    die "web container exists without deployment state"
  print_fresh_status
  exit 0
fi

require_root_controlled_file "${CURRENT_FILE}" "deployment state"
[[ $(stat -c '%a' -- "${CURRENT_FILE}") == 600 ]] || die "deployment state must have mode 0600"
validate_state_file

node_name=$(state_value NODE_NAME)
[[ ${node_name} == "${POLICY_NODE_NAME}" ]] || die "deployment state belongs to a different node"
api_ref=$(state_value API_REF)
api_version=$(state_value API_VERSION)
api_compatibility=$(state_value API_COMPATIBILITY)
web_ref=$(state_value WEB_REF)
web_version=$(state_value WEB_VERSION)
web_compatibility=$(state_value WEB_COMPATIBILITY)
peer_transport=$(state_peer_transport)
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
  ! docker container inspect "${API_CONTAINER}" >/dev/null 2>&1 ||
    die "API container exists without a recorded API image"
fi
if [[ -z ${web_ref} ]]; then
  ! docker container inspect "${WEB_CONTAINER}" >/dev/null 2>&1 ||
    die "web container exists without a recorded web image"
fi

printf 'node=%s\n' "${node_name}"
printf 'deployed_at=%s\n' "${deployed_at}"
printf 'config_sha256=%s\n' "${config_sha256:-not-deployed}"
printf 'peer_transport=%s\n' "${peer_transport}"
printf 'api_version=%s\napi_image=%s\napi_compatibility=%s\napi_status=%s\n' \
  "${api_version:-not-deployed}" "${api_ref:-not-deployed}" "${api_compatibility:-not-deployed}" "$(container_status "${API_CONTAINER}")"
printf 'web_version=%s\nweb_image=%s\nweb_compatibility=%s\nweb_status=%s\n' \
  "${web_version:-not-deployed}" "${web_ref:-not-deployed}" "${web_compatibility:-not-deployed}" "$(container_status "${WEB_CONTAINER}")"
if [[ -n ${MONITORING_NETWORK} ]]; then
  if container_has_network "${API_CONTAINER}" "${MONITORING_NETWORK}"; then
    printf 'monitoring=attached\n'
  else
    printf 'monitoring=not-attached\n'
  fi
else
  printf 'monitoring=disabled\n'
fi

healthy=true
api_networks_ok=true
web_networks_ok=true
if [[ -n ${api_ref} && $(container_status "${API_CONTAINER}") != running/healthy ]]; then
  healthy=false
fi
if [[ -n ${api_ref} ]]; then
  if [[ -n ${MONITORING_NETWORK} ]]; then
    container_has_exact_networks \
      "${API_CONTAINER}" alert-hub-edge alert-hub-egress "${MONITORING_NETWORK}" || api_networks_ok=false
  else
    container_has_exact_networks "${API_CONTAINER}" alert-hub-edge alert-hub-egress || api_networks_ok=false
  fi
  container_has_exact_network_address "${API_CONTAINER}" alert-hub-edge "${API_IP}" || healthy=false
  container_has_exact_port_binding "${API_CONTAINER}" 127.0.0.1 "${API_HOST_PORT}" || healthy=false
  curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${API_HOST_PORT}/health/ready" >/dev/null || healthy=false
  [[ ${api_networks_ok} == true ]] || healthy=false
fi
if [[ -n ${web_ref} ]]; then
  container_has_exact_networks "${WEB_CONTAINER}" alert-hub-edge alert-hub-ingress || web_networks_ok=false
  container_has_exact_network_address "${WEB_CONTAINER}" alert-hub-edge "${WEB_IP}" || healthy=false
  if [[ $(container_status "${WEB_CONTAINER}") != running/healthy ]]; then
    healthy=false
  elif ! container_has_exact_port_binding "${WEB_CONTAINER}" 127.0.0.1 "${HOST_PORT}"; then
    healthy=false
  elif ! curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${HOST_PORT}/health/ready" >/dev/null; then
    healthy=false
  fi
  [[ ${web_networks_ok} == true ]] || healthy=false
fi
if [[ -n ${api_ref} ]]; then
  api_networks_status=$([[ ${api_networks_ok} == true ]] && printf expected || printf unexpected)
else
  api_networks_status=not-deployed
fi
if [[ -n ${web_ref} ]]; then
  web_networks_status=$([[ ${web_networks_ok} == true ]] && printf expected || printf unexpected)
else
  web_networks_status=not-deployed
fi
printf 'api_networks=%s\nweb_networks=%s\n' "${api_networks_status}" "${web_networks_status}"
printf 'api_listener=127.0.0.1:%s\nweb_listener=127.0.0.1:%s\n' "${API_HOST_PORT}" "${HOST_PORT}"
printf 'api_internal_upstream=%s:8080\nweb_internal_upstream=%s:8080\n' "${API_IP}" "${WEB_IP}"
[[ ${healthy} == true ]] || die "one or more recorded components are not ready"

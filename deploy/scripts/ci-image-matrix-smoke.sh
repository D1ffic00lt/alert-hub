#!/usr/bin/env bash
set -Eeuo pipefail

api_image=${1:-alert-hub-api:ci}
web_image=${2:-alert-hub-web:ci}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
if [[ -n ${PYTHON:-} ]]; then
  port_python=${PYTHON}
elif [[ -x ${repo_root}/.venv/bin/python ]]; then
  port_python=${repo_root}/.venv/bin/python
else
  port_python=python3
fi
run_suffix=$$
project=alert-hub-matrix-${run_suffix}
failure_project=alert-hub-matrix-failure-${run_suffix}
smoke_root=$(mktemp -d /tmp/alert-hub-image-matrix.XXXXXX)
compose_file=${repo_root}/docker-compose.split.yml
edge_octet=$((20 + run_suffix % 200))
edge_subnet=10.254.${edge_octet}.0/29
api_ip=10.254.${edge_octet}.2
web_ip=10.254.${edge_octet}.3
umask 077

reserve_loopback_port() {
  "${port_python}" -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()'
}

host_port=$(reserve_loopback_port)
failure_host_port=$(reserve_loopback_port)
while [[ ${failure_host_port} == "${host_port}" ]]; do
  failure_host_port=$(reserve_loopback_port)
done

project_container_id() {
  local compose_project service ids
  compose_project=$1
  service=$2
  ids=$(docker container ls --all --quiet \
    --filter "label=com.docker.compose.project=${compose_project}" \
    --filter "label=com.docker.compose.service=${service}")
  if [[ -z ${ids} || ${ids} == *$'\n'* ]]; then
    printf 'Expected exactly one %s container in Compose project %s, got: %s\n' \
      "${service}" "${compose_project}" "${ids:-none}" >&2
    return 1
  fi
  printf '%s\n' "${ids}"
}

compose() {
  ALERT_HUB_API_IMAGE=${api_image} \
    ALERT_HUB_WEB_IMAGE=${web_image} \
    APP_NAME='Alert Hub Matrix' \
    ALERT_HUB_ENV_FILE=${smoke_root}/app.env \
    ALERT_HUB_DATA_VOLUME=${project}-data \
    ALERT_HUB_SECRETS_DIR=${smoke_root}/secrets \
    ALERT_HUB_HOST_PORT=${host_port} \
    ALERT_HUB_EDGE_SUBNET=${edge_subnet} \
    ALERT_HUB_API_IP=${api_ip} \
    ALERT_HUB_WEB_IP=${web_ip} \
    ALERT_HUB_RESTART_POLICY=no \
    docker compose --project-name "${project}" --file "${compose_file}" "$@"
}

failure_compose() {
  ALERT_HUB_API_IMAGE=${api_image} \
    ALERT_HUB_WEB_IMAGE=${web_image} \
    APP_NAME='Alert Hub Matrix' \
    ALERT_HUB_ENV_FILE=${smoke_root}/app.env \
    ALERT_HUB_DATA_VOLUME=${failure_project}-data \
    ALERT_HUB_SECRETS_DIR=${smoke_root}/secrets \
    ALERT_HUB_HOST_PORT=${failure_host_port} \
    ALERT_HUB_EDGE_SUBNET=10.253.${edge_octet}.0/29 \
    ALERT_HUB_API_IP=10.253.${edge_octet}.2 \
    ALERT_HUB_WEB_IP=10.253.${edge_octet}.3 \
    ALERT_HUB_RESTART_POLICY=no \
    MIGRATE_ON_START=invalid \
    docker compose --project-name "${failure_project}" --file "${compose_file}" "$@"
}

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  failure_compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [[ ${smoke_root} == /tmp/alert-hub-image-matrix.* ]]; then
    rm -rf -- "${smoke_root}"
  fi
}
trap cleanup EXIT

api_component=$(docker image inspect "${api_image}" \
  --format '{{index .Config.Labels "org.alert-hub.component"}}')
web_component=$(docker image inspect "${web_image}" \
  --format '{{index .Config.Labels "org.alert-hub.component"}}')
api_compatibility=$(docker image inspect "${api_image}" \
  --format '{{index .Config.Labels "org.alert-hub.compatibility"}}')
web_compatibility=$(docker image inspect "${web_image}" \
  --format '{{index .Config.Labels "org.alert-hub.compatibility"}}')
[[ ${api_component} == api && ${web_component} == web ]]
[[ ${api_compatibility} =~ ^(dev|openapi-sha256:[0-9a-f]{64})$ ]]
[[ ${api_compatibility} == "${web_compatibility}" ]] || {
  printf 'Refusing incompatible API/Web pair: %s != %s\n' \
    "${api_compatibility}" "${web_compatibility}" >&2
  exit 1
}

# The backend-only image is exercised before any frontend container exists.
bash "${script_dir}/ci-container-smoke.sh" "${api_image}"

install -d -m 0755 "${smoke_root}/secrets"
openssl rand -base64 48 >"${smoke_root}/secrets/token-signing-key"
openssl rand -base64 48 >"${smoke_root}/secrets/cluster-bearer-secret"
openssl rand -hex 32 >"${smoke_root}/secrets/master-encryption-key"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "${smoke_root}/secrets/vapid-private-key.pem" 2>/dev/null
chmod 0444 "${smoke_root}/secrets/"*

cat >"${smoke_root}/app.env" <<EOF
APP_NAME=Alert Hub Matrix
ENVIRONMENT=production
LOG_LEVEL=INFO
LOG_FORMAT=json
NODE_ID=matrix-node
NODE_NAME=Matrix node
NODE_REGION=ci
PUBLIC_API_URL=https://matrix.example.invalid
PRIVATE_PEER_URL=http://${api_ip}:8080
TRUSTED_ORIGINS=https://matrix.example.invalid
TRUSTED_PROXY_CIDRS=127.0.0.0/8,::1/128,${web_ip}/32
PEER_ALLOWED_CIDRS=127.0.0.0/8,::1/128
COOKIE_SECURE=true
DATABASE_URL=sqlite:////data/alert-hub.db
AUTO_CREATE_SCHEMA=false
BOOTSTRAP_TOKEN_FILE=/data/bootstrap-token
SIGNING_KEY_FILE=/run/secrets/token-signing-key
CLUSTER_SECRET_FILE=/run/secrets/cluster-bearer-secret
MASTER_ENCRYPTION_KEY_FILE=/run/secrets/master-encryption-key
VAPID_PRIVATE_KEY_FILE=/run/secrets/vapid-private-key.pem
VAPID_SUBJECT=mailto:ci@example.invalid
HEARTBEAT_SCAN_SECONDS=0
SYNC_ENABLED=false
MIGRATE_ON_START=true
EOF
chmod 0600 "${smoke_root}/app.env"

compose config --quiet
compose up --detach --no-build --wait

api_container=$(project_container_id "${project}" alert-hub)
web_container=$(project_container_id "${project}" alert-hub-web)

docker container exec "${api_container}" sh -c \
  'command -v python >/dev/null && ! command -v nginx >/dev/null && ! command -v node >/dev/null && ! command -v npm >/dev/null && test ! -d /usr/share/nginx/html'
docker container exec "${web_container}" sh -c \
  'command -v nginx >/dev/null && ! command -v python >/dev/null && ! command -v node >/dev/null && ! command -v npm >/dev/null && ! command -v alert-hub >/dev/null && test ! -e /data'
[[ $(docker container inspect "${web_container}" --format '{{len .Mounts}}') == 0 ]]

api_port_bindings=$(docker container inspect "${api_container}" \
  --format '{{json (index .NetworkSettings.Ports "8080/tcp")}}')
[[ ${api_port_bindings} == null || ${api_port_bindings} == '<no value>' ]]
web_port=$(docker container port "${web_container}" 8080/tcp)
[[ ${web_port} == "127.0.0.1:${host_port}" ]]
base_url=http://127.0.0.1:${host_port}

curl --fail --silent --show-error "${base_url}/health/ready" >"${smoke_root}/ready.json"
curl --fail --silent --show-error "${base_url}/" >"${smoke_root}/index.html"
curl --fail --silent --show-error "${base_url}/runtime-config.js" \
  >"${smoke_root}/runtime-config.js"
curl --fail --silent --show-error "${base_url}/manifest.webmanifest" \
  >"${smoke_root}/manifest.json"
curl --fail --silent --show-error "${base_url}/api/openapi.json" \
  >"${smoke_root}/openapi.json"
grep -F 'runtime-config.js' "${smoke_root}/index.html" >/dev/null
grep -F 'Alert Hub Matrix' "${smoke_root}/runtime-config.js" >/dev/null
grep -F '"name":"Alert Hub Matrix"' "${smoke_root}/manifest.json" >/dev/null
grep -F '"/api/v1/incidents"' "${smoke_root}/openapi.json" >/dev/null

# Stopping only API must withdraw every server-origin UI response while the web
# container itself stays available to recover without an image restart.
compose stop alert-hub
api_down=false
for _attempt in $(seq 1 20); do
  root_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --max-time 3 "${base_url}/" || true)
  ready_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --max-time 3 "${base_url}/health/ready" || true)
  if [[ ${root_status} == 503 && ${ready_status} != 200 ]]; then
    api_down=true
    break
  fi
  sleep 1
done
[[ ${api_down} == true ]] || {
  printf 'Web continued serving a ready UI after API stopped\n' >&2
  exit 1
}
[[ $(docker container inspect "${web_container}" --format '{{.State.Running}}') == true ]]

compose start alert-hub
recovered=false
for _attempt in $(seq 1 60); do
  if curl --fail --silent --show-error --max-time 3 \
    "${base_url}/health/ready" >/dev/null 2>&1; then
    recovered=true
    break
  fi
  sleep 1
done
[[ ${recovered} == true ]]
curl --fail --silent --show-error "${base_url}/" >/dev/null

# Each component can be recreated independently when its compatibility label
# matches the running peer.
api_before=$(project_container_id "${project}" alert-hub)
compose up --detach --no-deps --no-build --force-recreate alert-hub-web
[[ $(project_container_id "${project}" alert-hub) == "${api_before}" ]]
web_container=$(project_container_id "${project}" alert-hub-web)
web_port=$(docker container port "${web_container}" 8080/tcp)
[[ ${web_port} == "127.0.0.1:${host_port}" ]]
compose up --detach --no-deps --no-build --force-recreate alert-hub
web_after_web_update=$(project_container_id "${project}" alert-hub-web)
recovered=false
for _attempt in $(seq 1 60); do
  if curl --fail --silent --show-error --max-time 3 \
    "${base_url}/health/ready" >/dev/null 2>&1; then
    recovered=true
    break
  fi
  sleep 1
done
[[ ${recovered} == true ]]
[[ $(project_container_id "${project}" alert-hub-web) == "${web_after_web_update}" ]]

# A failed API entrypoint must never let the dependent web service start.
failure_compose up --detach --no-build >/dev/null 2>&1 || true
sleep 5
failure_web=$(docker container ls --all --quiet \
  --filter "label=com.docker.compose.project=${failure_project}" \
  --filter "label=com.docker.compose.service=alert-hub-web")
if [[ -n ${failure_web} ]]; then
  [[ $(docker container inspect "${failure_web}" --format '{{.State.Running}}') != true ]]
fi

printf '%s\n' \
  'Image matrix smoke passed: isolated API/Web runtimes, compatible pair, failure gating, and independent recovery.'

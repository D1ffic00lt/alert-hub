#!/usr/bin/env bash
set -Eeuo pipefail

image=${1:-alert-hub-api:ci}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
if [[ -n ${PYTHON:-} ]]; then
  smoke_python=${PYTHON}
elif [[ -x ${repo_root}/.venv/bin/python ]]; then
  smoke_python=${repo_root}/.venv/bin/python
else
  smoke_python=python3
fi
run_suffix=$$
container_name=alert-hub-ci-smoke-${run_suffix}
network_name=alert-hub-ci-smoke-${run_suffix}
smoke_root=$(mktemp -d /tmp/alert-hub-container-smoke.XXXXXX)
base_url=http://127.0.0.1:8080
public_origin=https://ci.example.invalid
umask 077

cleanup() {
  if [[ ${container_name} =~ ^alert-hub-ci-smoke-[0-9]+$ ]]; then
    docker container rm --force "${container_name}" >/dev/null 2>&1 || true
  fi
  if [[ ${network_name} =~ ^alert-hub-ci-smoke-[0-9]+$ ]]; then
    docker network rm "${network_name}" >/dev/null 2>&1 || true
  fi
  if [[ ${smoke_root} == /tmp/alert-hub-container-smoke.* ]]; then
    rm -rf -- "${smoke_root}"
  fi
}
trap cleanup EXIT

install -d -m 0777 "${smoke_root}/data"
install -d -m 0755 "${smoke_root}/secrets"
chmod 0755 "${smoke_root}"
openssl rand -base64 48 >"${smoke_root}/secrets/token-signing-key"
openssl rand -base64 48 >"${smoke_root}/secrets/cluster-bearer-secret"
openssl rand -hex 32 >"${smoke_root}/secrets/master-encryption-key"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "${smoke_root}/secrets/vapid-private-key.pem" 2>/dev/null
chmod 0444 "${smoke_root}/secrets/"*

configured_user=$(docker image inspect "${image}" --format '{{.Config.User}}')
[[ ${configured_user} == "10001:10001" ]] || {
  printf 'Image must configure the non-root 10001:10001 runtime user, got %s\n' \
    "${configured_user}" >&2
  exit 1
}
component=$(docker image inspect "${image}" \
  --format '{{index .Config.Labels "org.alert-hub.component"}}')
[[ ${component} == api ]] || {
  printf 'Expected component label api, got %s\n' "${component}" >&2
  exit 1
}
compatibility=$(docker image inspect "${image}" \
  --format '{{index .Config.Labels "org.alert-hub.compatibility"}}')
[[ -n ${compatibility} && ${compatibility} != '<no value>' ]]

docker network create --internal "${network_name}" >/dev/null
docker run --detach \
  --name "${container_name}" \
  --network "${network_name}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /run/alert-hub:rw,noexec,nosuid,nodev,size=4m,uid=10001,gid=10001,mode=0755 \
  --volume "${smoke_root}/data:/data" \
  --volume "${smoke_root}/secrets:/run/secrets:ro" \
  --env ENVIRONMENT=production \
  --env APP_NAME="Alert Hub CI" \
  --env NODE_ID=ci-smoke-node \
  --env NODE_NAME="CI smoke node" \
  --env NODE_REGION=ci \
  --env PUBLIC_API_URL="${public_origin}" \
  --env TRUSTED_ORIGINS="${public_origin}" \
  --env SIGNING_KEY_FILE=/run/secrets/token-signing-key \
  --env CLUSTER_SECRET_FILE=/run/secrets/cluster-bearer-secret \
  --env MASTER_ENCRYPTION_KEY_FILE=/run/secrets/master-encryption-key \
  --env VAPID_PRIVATE_KEY_FILE=/run/secrets/vapid-private-key.pem \
  --env VAPID_SUBJECT=mailto:ci@example.invalid \
  --env BOOTSTRAP_TOKEN_FILE=/data/bootstrap-token \
  --env HEARTBEAT_SCAN_SECONDS=0 \
  --env SYNC_ENABLED=false \
  --env MIGRATE_ON_START=true \
  "${image}" >/dev/null

container_curl() {
  docker container exec --interactive "${container_name}" curl "$@"
}

write_container_secret() {
  local destination=$1
  docker container exec --interactive "${container_name}" \
    sh -c 'umask 077; cat >"$1"' _ "${destination}"
}

ready=false
for _attempt in $(seq 1 90); do
  if container_curl --fail --silent --show-error "${base_url}/health/ready" \
    >"${smoke_root}/ready.json" 2>/dev/null; then
    ready=true
    break
  fi
  if [[ $(docker container inspect "${container_name}" --format '{{.State.Running}}') != true ]]; then
    printf 'Container stopped before readiness\n' >&2
    docker container logs "${container_name}" >&2
    exit 1
  fi
  sleep 1
done
if [[ ${ready} != true ]]; then
  printf 'Container did not become ready within 90 seconds\n' >&2
  docker container logs "${container_name}" >&2
  exit 1
fi

"${smoke_python}" - "${smoke_root}/ready.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload == {"status": "ok", "node_id": "ci-smoke-node", "database": "ok"}
PY

runtime_user=$(docker container exec "${container_name}" id -u)
[[ ${runtime_user} == 10001 ]] || {
  printf 'Running container UID must be 10001, got %s\n' "${runtime_user}" >&2
  exit 1
}
[[ $(docker container inspect "${container_name}" --format '{{.HostConfig.ReadonlyRootfs}}') == true ]]

for _attempt in $(seq 1 20); do
  [[ -s ${smoke_root}/data/bootstrap-token ]] && break
  sleep 1
done
[[ -s ${smoke_root}/data/bootstrap-token ]] || {
  printf 'Bootstrap token was not created in the durable data mount\n' >&2
  exit 1
}
# The runtime deliberately creates this secret as 0600 under UID 10001. Read it
# as that container user: a Linux host runner must not be able to read the bind-
# mounted file merely because Docker Desktop makes that work on macOS.
bootstrap_token=$(docker container exec "${container_name}" cat /data/bootstrap-token)
[[ -n ${bootstrap_token} ]]
smoke_password=$(openssl rand -base64 24)
BOOTSTRAP_TOKEN=${bootstrap_token} SMOKE_PASSWORD=${smoke_password} \
  "${smoke_python}" -c 'import json, os; print(json.dumps({"bootstrap_token": os.environ["BOOTSTRAP_TOKEN"], "username": "ci-admin", "password": os.environ["SMOKE_PASSWORD"], "device_name": "container-smoke"}))' \
  >"${smoke_root}/bootstrap-request.json"

container_curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "${base_url}/api/v1/auth/bootstrap" \
  <"${smoke_root}/bootstrap-request.json" \
  >"${smoke_root}/bootstrap-response.json"
access_token=$("${smoke_python}" -c 'import json, sys; print(json.load(open(sys.argv[1]))["access_token"])' \
  "${smoke_root}/bootstrap-response.json")
[[ -n ${access_token} ]]
umask 077
printf 'header = "Authorization: Bearer %s"\n' "${access_token}" \
  >"${smoke_root}/admin-curl.conf"
write_container_secret /tmp/admin-curl.conf <"${smoke_root}/admin-curl.conf"
[[ $(docker container exec "${container_name}" stat -c '%a' /tmp/admin-curl.conf) == 600 ]]

printf '%s\n' '{"name":"CI generic source","kind":"generic_json","region":"ci"}' \
  >"${smoke_root}/source-request.json"
container_curl --fail --silent --show-error \
  --config /tmp/admin-curl.conf \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "${base_url}/api/v1/sources" \
  <"${smoke_root}/source-request.json" \
  >"${smoke_root}/source-response.json"
source_id=$("${smoke_python}" -c 'import json, sys; print(json.load(open(sys.argv[1]))["id"])' \
  "${smoke_root}/source-response.json")
source_token=$("${smoke_python}" -c 'import json, sys; print(json.load(open(sys.argv[1]))["token"])' \
  "${smoke_root}/source-response.json")
[[ -n ${source_id} && -n ${source_token} ]]
printf 'header = "Authorization: Bearer %s"\n' "${source_token}" \
  >"${smoke_root}/source-curl.conf"
write_container_secret /tmp/source-curl.conf <"${smoke_root}/source-curl.conf"

printf '%s\n' \
  '{"external_event_id":"container-smoke-1","dedup_key":"container-smoke","status":"firing","title":"Container smoke incident","severity":"warning","starts_at":"2026-09-01T12:00:00Z"}' \
  >"${smoke_root}/event.json"
for attempt in first duplicate; do
  container_curl --fail --silent --show-error \
    --config /tmp/source-curl.conf \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    "${base_url}/ingest/v1/events/${source_id}" \
    <"${smoke_root}/event.json" \
    >"${smoke_root}/ingest-${attempt}.json"
done
"${smoke_python}" - "${smoke_root}/ingest-first.json" "${smoke_root}/ingest-duplicate.json" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1], encoding="utf-8"))
duplicate = json.load(open(sys.argv[2], encoding="utf-8"))
assert first["accepted"] == 1 and first["duplicates"] == 0, first
assert duplicate["accepted"] == 0 and duplicate["duplicates"] == 1, duplicate
assert first["incident_ids"] == duplicate["incident_ids"], (first, duplicate)
PY
incident_id=$("${smoke_python}" -c 'import json, sys; print(json.load(open(sys.argv[1]))["incident_ids"][0])' \
  "${smoke_root}/ingest-first.json")

printf '%s\n' \
  '{"external_event_id":"container-smoke-2","dedup_key":"container-smoke","status":"resolved","title":"Container smoke incident","severity":"warning","starts_at":"2026-09-01T12:00:00Z","ends_at":"2026-09-01T12:05:00Z"}' \
  >"${smoke_root}/resolved-event.json"
container_curl --fail --silent --show-error \
  --config /tmp/source-curl.conf \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "${base_url}/ingest/v1/events/${source_id}" \
  <"${smoke_root}/resolved-event.json" \
  >"${smoke_root}/ingest-resolved.json"
"${smoke_python}" - "${smoke_root}/ingest-resolved.json" "${incident_id}" <<'PY'
import json
import sys

resolved = json.load(open(sys.argv[1], encoding="utf-8"))
assert resolved["accepted"] == 1 and resolved["duplicates"] == 0, resolved
assert resolved["incident_ids"] == [sys.argv[2]], resolved
PY

container_curl --fail --silent --show-error \
  --config /tmp/admin-curl.conf \
  "${base_url}/api/v1/incidents?limit=10" >"${smoke_root}/incidents.json"
"${smoke_python}" - "${smoke_root}/incidents.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["total"] == 1, payload
assert payload["items"][0]["title"] == "Container smoke incident", payload
assert payload["items"][0]["status"] == "resolved", payload
PY

container_curl --fail --silent --show-error \
  --config /tmp/admin-curl.conf \
  "${base_url}/api/v1/incidents/${incident_id}" >"${smoke_root}/incident-detail.json"
"${smoke_python}" - "${smoke_root}/incident-detail.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["status"] == "resolved", payload
assert [event["event_type"] for event in payload["timeline"]] == ["firing", "resolved"], payload
PY

container_curl --fail --silent --show-error "${base_url}/health/deep" \
  >"${smoke_root}/deep.json"
"${smoke_python}" - "${smoke_root}/deep.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["status"] == "ok" and payload["nodes_known"] >= 1, payload
assert payload["open_incidents"] == 0, payload
PY

container_curl --fail --silent --show-error "${base_url}/api/openapi.json" \
  >"${smoke_root}/openapi.json"
"${smoke_python}" - "${smoke_root}/openapi.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert "/api/v1/incidents" in payload["paths"]
assert "/ingest/v1/events/{source_id}" in payload["paths"]
PY

docker container exec "${container_name}" sh -c \
  'command -v python >/dev/null && ! command -v nginx >/dev/null && ! command -v node >/dev/null && ! command -v npm >/dev/null && test ! -d /app/frontend'
root_status=$(container_curl --silent --output /dev/null --write-out '%{http_code}' "${base_url}/")
runtime_status=$(container_curl --silent --output /dev/null --write-out '%{http_code}' \
  "${base_url}/runtime-config.js")
[[ ${root_status} == 404 && ${runtime_status} == 404 ]] || {
  printf 'API-only image unexpectedly serves frontend paths (%s, %s)\n' \
    "${root_status}" "${runtime_status}" >&2
  exit 1
}
container_curl --fail --silent --show-error "${base_url}/metrics" \
  | grep -F 'alert_hub_build_info' >/dev/null

printf '%s\n' \
  'API image smoke passed: non-root/read-only runtime, health, API, dedupe, boundaries, and metrics.'

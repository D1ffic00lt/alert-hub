#!/usr/bin/env bash
set -Eeuo pipefail

api_image=${1:-alert-hub-api:ci}
alertmanager_image=quay.io/prometheus/alertmanager:v0.32.1@sha256:51a825c2a40acc3e338fdd00d622e01ec090f72be2b3ea46be0839cd47a4d286
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
if [[ -n ${PYTHON:-} ]]; then
  smoke_python=${PYTHON}
elif [[ -x ${repo_root}/backend/.venv/bin/python ]]; then
  smoke_python=${repo_root}/backend/.venv/bin/python
else
  smoke_python=python3
fi
run_suffix=$$
hub_name=alert-hub-am-recovery-${run_suffix}
primary_name=alert-hub-am-primary-${run_suffix}
recovery_name=alert-hub-am-shadow-${run_suffix}
network_name=alert-hub-am-recovery-${run_suffix}
smoke_root=$(mktemp -d /tmp/alert-hub-am-recovery.XXXXXX)
base_url=http://127.0.0.1:8080
public_origin=https://ci.example.invalid
umask 077

cleanup() {
  local exit_code=$?
  set +e
  if ((exit_code != 0)); then
    for failed_container in "${hub_name}" "${primary_name}" "${recovery_name}"; do
      docker container logs "${failed_container}" >&2 2>/dev/null || true
    done
  fi
  for disposable_container in "${hub_name}" "${primary_name}" "${recovery_name}"; do
    if [[ ${disposable_container} =~ ^alert-hub-am-(recovery|primary|shadow)-[0-9]+$ ]]; then
      docker container rm --force "${disposable_container}" >/dev/null 2>&1 || true
    fi
  done
  if [[ ${network_name} =~ ^alert-hub-am-recovery-[0-9]+$ ]]; then
    docker network rm "${network_name}" >/dev/null 2>&1 || true
  fi
  if [[ ${smoke_root} == /tmp/alert-hub-am-recovery.* ]]; then
    rm -rf -- "${smoke_root}"
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

hub_curl() {
  docker container exec --interactive "${hub_name}" curl "$@"
}

write_hub_secret() {
  local destination=$1
  docker container exec --interactive "${hub_name}" \
    sh -c 'umask 077; cat >"$1"' _ "${destination}"
}

wait_for_child_status() {
  local expected_status=$1
  local ready=false
  for _attempt in $(seq 1 40); do
    hub_curl --fail --silent --show-error \
      --config /tmp/admin-curl.conf \
      "${base_url}/api/v1/incidents?source_id=${source_id}&alertname=ChildEndpointDown" \
      >"${smoke_root}/child-incident.json"
    if EXPECTED_STATUS=${expected_status} "${smoke_python}" - \
      "${smoke_root}/child-incident.json" <<'PY'
import json
import os
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
items = payload["items"]
expected = os.environ["EXPECTED_STATUS"]
if len(items) == 1 and items[0]["status"] == expected:
    raise SystemExit(0)
raise SystemExit(1)
PY
    then
      ready=true
      break
    fi
    sleep 1
  done
  if [[ ${ready} != true ]]; then
    printf 'Child incident did not reach status %s\n' "${expected_status}" >&2
    cat "${smoke_root}/child-incident.json" >&2
    return 1
  fi
}

install -d -m 0777 \
  "${smoke_root}/data" \
  "${smoke_root}/primary-data" \
  "${smoke_root}/recovery-data"
install -d -m 0755 \
  "${smoke_root}/secrets" \
  "${smoke_root}/primary" \
  "${smoke_root}/recovery"
chmod 0755 "${smoke_root}"
openssl rand -base64 48 >"${smoke_root}/secrets/token-signing-key"
openssl rand -base64 48 >"${smoke_root}/secrets/cluster-bearer-secret"
openssl rand -hex 32 >"${smoke_root}/secrets/master-encryption-key"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "${smoke_root}/secrets/vapid-private-key.pem" 2>/dev/null
chmod 0444 "${smoke_root}/secrets/"*

docker pull "${alertmanager_image}" >/dev/null
docker network create "${network_name}" >/dev/null
docker run --detach \
  --name "${hub_name}" \
  --network "${network_name}" \
  --network-alias alert-hub \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /run/alert-hub:rw,noexec,nosuid,nodev,size=4m,uid=10001,gid=10001,mode=0755 \
  --volume "${smoke_root}/data:/data" \
  --volume "${smoke_root}/secrets:/run/secrets:ro" \
  --env ENVIRONMENT=production \
  --env APP_NAME="Alert Hub Alertmanager CI" \
  --env NODE_ID=ci-alertmanager-node \
  --env NODE_NAME="CI Alertmanager node" \
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
  "${api_image}" >/dev/null

hub_ready=false
for _attempt in $(seq 1 90); do
  if hub_curl --fail --silent --show-error "${base_url}/health/ready" >/dev/null 2>&1; then
    hub_ready=true
    break
  fi
  sleep 1
done
[[ ${hub_ready} == true ]] || {
  printf 'Alert Hub did not become ready\n' >&2
  exit 1
}

bootstrap_token=$(docker container exec "${hub_name}" cat /data/bootstrap-token)
smoke_password=$(openssl rand -base64 24)
BOOTSTRAP_TOKEN=${bootstrap_token} SMOKE_PASSWORD=${smoke_password} \
  "${smoke_python}" -c 'import json, os; print(json.dumps({"bootstrap_token": os.environ["BOOTSTRAP_TOKEN"], "username": "ci-admin", "password": os.environ["SMOKE_PASSWORD"], "device_name": "alertmanager-smoke"}))' \
  >"${smoke_root}/bootstrap-request.json"
hub_curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "${base_url}/api/v1/auth/bootstrap" \
  <"${smoke_root}/bootstrap-request.json" \
  >"${smoke_root}/bootstrap-response.json"
access_token=$("${smoke_python}" -c 'import json, sys; print(json.load(open(sys.argv[1]))["access_token"])' \
  "${smoke_root}/bootstrap-response.json")
printf 'header = "Authorization: Bearer %s"\n' "${access_token}" \
  >"${smoke_root}/admin-curl.conf"
write_hub_secret /tmp/admin-curl.conf <"${smoke_root}/admin-curl.conf"

printf '%s\n' '{"name":"CI Alertmanager source","kind":"alertmanager","region":"ci"}' \
  >"${smoke_root}/source-request.json"
hub_curl --fail --silent --show-error \
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

cat >"${smoke_root}/primary/alertmanager.yml" <<EOF
route:
  receiver: alert-hub-primary
  group_by: ['...']
  group_wait: 0s
  group_interval: 1s
  repeat_interval: 1h
receivers:
  - name: alert-hub-primary
    webhook_configs:
      - url: http://alert-hub:8080/ingest/v1/alertmanager/${source_id}
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials: ${source_token}
inhibit_rules:
  - source_matchers:
      - 'alertname="AggregateOutage"'
    target_matchers:
      - 'alertname="ChildEndpointDown"'
    equal:
      - target_server
EOF
cat >"${smoke_root}/recovery/alertmanager.yml" <<EOF
route:
  receiver: alert-hub-recoveries
  group_by: ['...']
  group_wait: 0s
  group_interval: 1s
  repeat_interval: 1h
receivers:
  - name: alert-hub-recoveries
    webhook_configs:
      - url: http://alert-hub:8080/ingest/v1/alertmanager/${source_id}/recoveries
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials: ${source_token}
EOF
chmod 0444 \
  "${smoke_root}/primary/alertmanager.yml" \
  "${smoke_root}/recovery/alertmanager.yml"

docker run --detach \
  --name "${primary_name}" \
  --network "${network_name}" \
  --network-alias primary-alertmanager \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --volume "${smoke_root}/primary/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
  --volume "${smoke_root}/primary-data:/alertmanager" \
  "${alertmanager_image}" \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/alertmanager \
  --web.listen-address=:9093 >/dev/null
docker run --detach \
  --name "${recovery_name}" \
  --network "${network_name}" \
  --network-alias recovery-alertmanager \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --volume "${smoke_root}/recovery/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
  --volume "${smoke_root}/recovery-data:/alertmanager" \
  "${alertmanager_image}" \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/alertmanager \
  --web.listen-address=:9093 >/dev/null

for alertmanager_host in primary-alertmanager recovery-alertmanager; do
  ready=false
  for _attempt in $(seq 1 60); do
    if hub_curl --fail --silent --show-error \
      "http://${alertmanager_host}:9093/-/ready" >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ ${ready} == true ]] || {
    printf '%s did not become ready\n' "${alertmanager_host}" >&2
    exit 1
  }
done

hub_curl --fail --silent --show-error \
  http://primary-alertmanager:9093/api/v2/status >"${smoke_root}/am-status.json"
"${smoke_python}" - "${smoke_root}/am-status.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["versionInfo"]["version"] == "0.32.1", payload
PY

"${smoke_python}" - "${smoke_root}" <<'PY'
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

root = Path(sys.argv[1])
now = datetime.now(UTC).replace(microsecond=0)
starts_at = now - timedelta(minutes=1)
firing_ends_at = now + timedelta(hours=1)
resolved_at = now - timedelta(seconds=1)

child = {
    "labels": {
        "alertname": "ChildEndpointDown",
        "target_server": "edge-one",
        "severity": "critical",
    },
    "annotations": {"summary": "Child endpoint is down"},
    "startsAt": starts_at.isoformat().replace("+00:00", "Z"),
    "endsAt": firing_ends_at.isoformat().replace("+00:00", "Z"),
    "generatorURL": "https://prometheus.example.invalid/graph",
}
aggregate = {
    "labels": {
        "alertname": "AggregateOutage",
        "target_server": "edge-one",
        "severity": "critical",
    },
    "annotations": {"summary": "Aggregate outage"},
    "startsAt": now.isoformat().replace("+00:00", "Z"),
    "endsAt": firing_ends_at.isoformat().replace("+00:00", "Z"),
    "generatorURL": "https://prometheus.example.invalid/graph",
}
resolved = {**child, "endsAt": resolved_at.isoformat().replace("+00:00", "Z")}
for name, payload in {
    "child-firing.json": [child],
    "aggregate-firing.json": [aggregate],
    "child-resolved.json": [resolved],
}.items():
    (root / name).write_text(json.dumps(payload), encoding="utf-8")
PY

for alertmanager_host in primary-alertmanager recovery-alertmanager; do
  hub_curl --fail --silent --show-error \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    "http://${alertmanager_host}:9093/api/v2/alerts" \
    <"${smoke_root}/child-firing.json" >/dev/null
done
wait_for_child_status open

for alertmanager_host in primary-alertmanager recovery-alertmanager; do
  hub_curl --fail --silent --show-error \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    "http://${alertmanager_host}:9093/api/v2/alerts" \
    <"${smoke_root}/aggregate-firing.json" >/dev/null
done

inhibited=false
for _attempt in $(seq 1 30); do
  hub_curl --fail --silent --show-error \
    http://primary-alertmanager:9093/api/v2/alerts \
    >"${smoke_root}/primary-alerts.json"
  if "${smoke_python}" - "${smoke_root}/primary-alerts.json" <<'PY'
import json
import sys

alerts = json.load(open(sys.argv[1], encoding="utf-8"))
for alert in alerts:
    if alert.get("labels", {}).get("alertname") != "ChildEndpointDown":
        continue
    status = alert.get("status", {})
    if status.get("state") == "suppressed" and status.get("inhibitedBy"):
        raise SystemExit(0)
raise SystemExit(1)
PY
  then
    inhibited=true
    break
  fi
  sleep 1
done
[[ ${inhibited} == true ]] || {
  printf 'Primary Alertmanager never reported the child as inhibited\n' >&2
  cat "${smoke_root}/primary-alerts.json" >&2
  exit 1
}

# Alertmanager 0.32.1 drops this recovery in its mute stage. Prove the incident
# remains open before the uninhibited shadow receives the same resolution.
hub_curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  http://primary-alertmanager:9093/api/v2/alerts \
  <"${smoke_root}/child-resolved.json" >/dev/null
sleep 5
wait_for_child_status open

hub_curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  http://recovery-alertmanager:9093/api/v2/alerts \
  <"${smoke_root}/child-resolved.json" >/dev/null
wait_for_child_status resolved

child_incident_id=$("${smoke_python}" -c 'import json, sys; print(json.load(open(sys.argv[1]))["items"][0]["id"])' \
  "${smoke_root}/child-incident.json")
hub_curl --fail --silent --show-error \
  --config /tmp/admin-curl.conf \
  "${base_url}/api/v1/incidents/${child_incident_id}" \
  >"${smoke_root}/child-detail.json"
"${smoke_python}" - "${smoke_root}/child-detail.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["status"] == "resolved", payload
assert [event["event_type"] for event in payload["timeline"]] == [
    "firing",
    "resolved",
], payload
PY

printf 'Alertmanager 0.32.1 inhibited-recovery lifecycle passed.\n'

#!/usr/bin/env bash
set -Eeuo pipefail

image=${1:-alert-hub-api:ci}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
compose_file=${repo_root}/deploy/docker-compose.ci-three-node.yaml
if [[ -n ${PYTHON:-} ]]; then
  smoke_python=${PYTHON}
elif [[ -x ${repo_root}/.venv/bin/python ]]; then
  smoke_python=${repo_root}/.venv/bin/python
else
  smoke_python=python3
fi

run_identity=${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-0}-${RANDOM}
project=alert-hub-ci-three-node-${run_identity}
[[ ${project} =~ ^[a-z0-9][a-z0-9-]+$ ]] || {
  printf 'Unsafe Compose project name: %s\n' "${project}" >&2
  exit 2
}

test_root=$(mktemp -d /tmp/alert-hub-three-node.XXXXXX)
chmod 0755 "${test_root}"
umask 077
export ALERT_HUB_CI_ROOT=${test_root}
export ALERT_HUB_API_IMAGE=${image}
compose=(docker compose --project-name "${project}" --file "${compose_file}")
compose_started=false
source_sync_attempts=${SOURCE_SYNC_ATTEMPTS:-120}
[[ ${source_sync_attempts} =~ ^[0-9]+$ && ${source_sync_attempts} -ge 1 ]] || {
  printf 'SOURCE_SYNC_ATTEMPTS must be a positive integer\n' >&2
  exit 2
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [[ ${status} -ne 0 && ${compose_started} == true ]]; then
    printf 'Controlled three-node Docker CI substitute failed; container diagnostics follow.\n' >&2
    "${compose[@]}" ps --all >&2
    "${compose[@]}" logs --no-color --tail 40 >&2
    local network_id
    network_id=$(docker network ls --quiet \
      --filter "label=com.docker.compose.project=${project}" \
      --filter 'label=com.docker.compose.network=cluster' | head -n 1)
    if [[ -n ${network_id} ]]; then
      docker network inspect "${network_id}" >&2
    fi
  fi
  if [[ ${project} =~ ^alert-hub-ci-three-node-[a-z0-9-]+$ ]]; then
    "${compose[@]}" down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1
  fi
  if [[ ${test_root} == /tmp/alert-hub-three-node.* ]]; then
    rm -rf -- "${test_root}"
  fi
  exit "${status}"
}
trap cleanup EXIT

emit_sync_diagnostics() {
  local node output
  for node in node-ru node-nl node-de; do
    output=${test_root}/deep-${node}.json
    if node_curl "${node}" --fail --silent --show-error \
      http://127.0.0.1:8080/health/deep >"${output}" 2>/dev/null; then
      "${smoke_python}" - "${output}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
peers = payload.get("peers", {})
for item in peers.get("items", {}).values():
    error = item.get("last_error")
    if error:
        item["last_error"] = str(error).splitlines()[0]
print(
    json.dumps(
        {
            "node_id": payload.get("node_id"),
            "cluster_events": payload.get("cluster_events"),
            "nodes_known": payload.get("nodes_known"),
            "peers": peers,
        },
        sort_keys=True,
    )
)
PY
    fi
  done
}

node_curl() {
  local node=$1
  shift
  "${compose[@]}" exec --no-TTY "${node}" \
    curl --connect-timeout 2 --max-time 5 "$@"
}

write_private_config() {
  local node=$1
  local path=$2
  # The container shell expands $1 after exec.
  # shellcheck disable=SC2016
  "${compose[@]}" exec --no-TTY "${node}" \
    sh -c 'umask 077; cat >"$1"; test "$(stat -c %a "$1")" = 600' _ "${path}"
}

install_bearer_config() {
  local node=$1
  local path=$2
  local token=$3
  printf 'header = "Authorization: Bearer %s"\n' "${token}" \
    | write_private_config "${node}" "${path}"
}

phase() {
  printf 'three-node-ci: %s\n' "$1"
}

wait_node() {
  local node=$1
  local output=${test_root}/ready-${node}.json
  local attempt
  for ((attempt = 1; attempt <= 120; attempt += 1)); do
    if node_curl "${node}" --fail --silent --show-error \
      http://127.0.0.1:8080/health/ready >"${output}" 2>/dev/null; then
      "${smoke_python}" - "${output}" "${node}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload == {"status": "ok", "node_id": sys.argv[2], "database": "ok"}, payload
PY
      return
    fi
    if [[ $("${compose[@]}" ps --quiet "${node}") == "" ]]; then
      printf 'Node %s disappeared before readiness\n' "${node}" >&2
      return 1
    fi
    sleep 1
  done
  printf 'Node %s did not become ready within 120 seconds\n' "${node}" >&2
  return 1
}

wait_webhook_sink() {
  local output=${test_root}/ready-webhook-sink.json
  local attempt
  for ((attempt = 1; attempt <= 60; attempt += 1)); do
    if node_curl webhook-sink --fail --silent --show-error \
      http://127.0.0.1:8081/health >"${output}" 2>/dev/null; then
      "${smoke_python}" - "${output}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload == {"status": "ok"}, payload
PY
      return
    fi
    if [[ $("${compose[@]}" ps --quiet webhook-sink) == "" ]]; then
      printf 'Webhook sink disappeared before readiness\n' >&2
      return 1
    fi
    sleep 1
  done
  printf 'Webhook sink did not become ready within 60 seconds\n' >&2
  return 1
}

assert_ingest() {
  local response=$1
  local accepted=$2
  local duplicates=$3
  "${smoke_python}" - "${response}" "${accepted}" "${duplicates}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["accepted"] == int(sys.argv[2]), payload
assert payload["duplicates"] == int(sys.argv[3]), payload
assert len(payload["incident_ids"]) == 1, payload
PY
}

capture_projection() {
  local node=$1
  node_curl "${node}" --fail --silent --show-error --config /tmp/admin-curl.conf \
    http://127.0.0.1:8080/api/v1/cluster/status \
    >"${test_root}/${node}-cluster.json"
  node_curl "${node}" --fail --silent --show-error --config /tmp/admin-curl.conf \
    'http://127.0.0.1:8080/api/v1/incidents?limit=10' \
    >"${test_root}/${node}-incidents.json"
  node_curl "${node}" --fail --silent --show-error --config /tmp/admin-curl.conf \
    "http://127.0.0.1:8080/api/v1/incidents/${incident_id}" \
    >"${test_root}/${node}-detail.json"
}

projection_matches() {
  local expected_status=$1
  local expected_types=$2
  "${smoke_python}" - "${test_root}" "${incident_id}" "${expected_status}" \
    "${expected_types}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
incident_id = sys.argv[2]
expected_status = sys.argv[3]
expected_types = sys.argv[4].split(",")
nodes = ("node-ru", "node-nl", "node-de")

clusters = [json.loads((root / f"{node}-cluster.json").read_text()) for node in nodes]
cursor = clusters[0]["cursor"]
assert all(item["cursor"] == cursor for item in clusters), clusters
assert {"node-ru", "node-nl", "node-de"} <= set(cursor), cursor
assert all(item["cluster_event_count"] == clusters[0]["cluster_event_count"] for item in clusters)

canonical = []
for node in nodes:
    listing = json.loads((root / f"{node}-incidents.json").read_text())
    detail = json.loads((root / f"{node}-detail.json").read_text())
    assert listing["total"] == 1, (node, listing)
    assert listing["items"][0]["id"] == incident_id, (node, listing)
    assert detail["id"] == incident_id and detail["status"] == expected_status, (node, detail)
    timeline = detail["timeline"]
    assert [event["event_type"] for event in timeline] == expected_types, (node, timeline)
    event_keys = [event["event_key"] for event in timeline]
    assert len(event_keys) == len(set(event_keys)) == len(expected_types), (node, timeline)
    canonical.append(
        {
            "id": detail["id"],
            "source_id": detail["source_id"],
            "fingerprint": detail["fingerprint"],
            "title": detail["title"],
            "severity": detail["severity"],
            "status": detail["status"],
            "starts_at": detail["starts_at"],
            "last_event_at": detail["last_event_at"],
            "resolved_at": detail["resolved_at"],
            "labels": detail["labels"],
            "timeline": [
                {
                    "event_key": event["event_key"],
                    "event_type": event["event_type"],
                    "occurred_at": event["occurred_at"],
                    "external_event_id": event["payload"].get("external_event_id"),
                }
                for event in timeline
            ],
        }
    )
assert canonical[1:] == canonical[:-1], canonical
PY
}

wait_full_convergence() {
  local expected_status=$1
  local expected_types=$2
  local attempt node
  for ((attempt = 1; attempt <= 160; attempt += 1)); do
    if {
      for node in node-ru node-nl node-de; do
        capture_projection "${node}" || break
      done
    } 2>/dev/null && projection_matches "${expected_status}" "${expected_types}" 2>/dev/null; then
      return
    fi
    sleep 1
  done
  printf 'Three nodes did not converge to status=%s timeline=%s within 160 seconds\n' \
    "${expected_status}" "${expected_types}" >&2
  return 1
}

wait_two_node_projection() {
  local expected_types=$1
  local attempt node
  for ((attempt = 1; attempt <= 120; attempt += 1)); do
    local matched=true
    for node in node-nl node-de; do
      if ! node_curl "${node}" --fail --silent --show-error --config /tmp/admin-curl.conf \
        "http://127.0.0.1:8080/api/v1/incidents/${incident_id}" \
        >"${test_root}/${node}-pair-detail.json" 2>/dev/null; then
        matched=false
        break
      fi
    done
    if [[ ${matched} == true ]] && "${smoke_python}" - \
      "${test_root}" "${expected_types}" 2>/dev/null <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected = sys.argv[2].split(",")
details = [json.loads((root / f"{node}-pair-detail.json").read_text()) for node in ("node-nl", "node-de")]
assert all(item["status"] == "resolved" for item in details), details
assert all([event["event_type"] for event in item["timeline"]] == expected for item in details), details
assert [event["event_key"] for event in details[0]["timeline"]] == [
    event["event_key"] for event in details[1]["timeline"]
], details
PY
    then
      return
    fi
    sleep 1
  done
  printf 'NL and DE did not converge to timeline=%s within 120 seconds\n' \
    "${expected_types}" >&2
  return 1
}

notification_configuration_matches() {
  "${smoke_python}" - "${test_root}" "${notification_channel_id}" \
    "${notification_route_id}" "${source_id}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
channel_id = sys.argv[2]
route_id = sys.argv[3]
source_id = sys.argv[4]
expected_nodes = {"node-ru", "node-nl", "node-de"}
clusters = []

for node in sorted(expected_nodes):
    channels = json.loads((root / f"notification-channels-{node}.json").read_text())
    routes = json.loads((root / f"notification-routes-{node}.json").read_text())
    cluster = json.loads((root / f"notification-cluster-{node}.json").read_text())
    channel = next(item for item in channels if item["id"] == channel_id)
    route = next(item for item in routes if item["id"] == route_id)
    nodes = {item["id"]: item for item in cluster["nodes"]}
    assert set(nodes) == expected_nodes, (node, cluster)
    assert all("notify" in item["enabled_roles"] for item in nodes.values()), (node, nodes)
    assert channel["kind"] == "generic_webhook" and channel["enabled"] is True, channel
    assert set(channel["eligible_node_ids"]) == expected_nodes, channel
    assert channel["configured_fields"] == ["headers", "url"], channel
    assert route["enabled"] is True and route["source_filter"] == [source_id], route
    assert route["channel_ids"] == [channel_id], route
    assert route["label_matchers"] == [
        {"name": "notification_evidence", "operator": "equals", "value": "true"}
    ], route
    clusters.append(cluster)
assert all(item["cursor"] == clusters[0]["cursor"] for item in clusters), clusters
assert all(
    item["cluster_event_count"] == clusters[0]["cluster_event_count"] for item in clusters
), clusters
PY
}

emit_notification_diagnostics() {
  local node
  printf 'Notification ownership diagnostics follow.\n' >&2
  for node in node-ru node-nl node-de; do
    if node_curl "${node}" --fail --silent --show-error --config /tmp/admin-curl.conf \
      http://127.0.0.1:8080/api/v1/channels \
      >"${test_root}/notification-diagnostic-${node}.json" 2>/dev/null; then
      printf '%s channels: ' "${node}" >&2
      cat "${test_root}/notification-diagnostic-${node}.json" >&2
      printf '\n' >&2
    fi
    node_curl "${node}" --fail --silent --show-error \
      http://127.0.0.1:8080/metrics 2>/dev/null \
      | sed -n '/^alert_hub_outbox_pending /p' >&2 || true
  done
  "${compose[@]}" logs --no-color --tail 100 webhook-sink >&2 || true
  emit_sync_diagnostics >&2 || true
}

wait_notification_configuration() {
  local attempt node
  for ((attempt = 1; attempt <= 120; attempt += 1)); do
    local captured=true
    for node in node-ru node-nl node-de; do
      if ! node_curl "${node}" --fail --silent --show-error \
        --config /tmp/admin-curl.conf \
        http://127.0.0.1:8080/api/v1/channels \
        >"${test_root}/notification-channels-${node}.json" 2>/dev/null \
        || ! node_curl "${node}" --fail --silent --show-error \
          --config /tmp/admin-curl.conf \
          http://127.0.0.1:8080/api/v1/routes \
          >"${test_root}/notification-routes-${node}.json" 2>/dev/null \
        || ! node_curl "${node}" --fail --silent --show-error \
          --config /tmp/admin-curl.conf \
          http://127.0.0.1:8080/api/v1/cluster/status \
          >"${test_root}/notification-cluster-${node}.json" 2>/dev/null; then
        captured=false
        break
      fi
    done
    if [[ ${captured} == true ]] && notification_configuration_matches 2>/dev/null; then
      return
    fi
    sleep 1
  done
  printf 'Notification channel and route did not replicate within 120 seconds\n' >&2
  emit_notification_diagnostics
  return 1
}

notification_receipts_match() {
  "${smoke_python}" - "${test_root}" "${notification_channel_id}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
channel_id = sys.argv[2]
for node in ("node-ru", "node-nl", "node-de"):
    channels = json.loads((root / f"notification-receipts-{node}.json").read_text())
    channel = next(item for item in channels if item["id"] == channel_id)
    assert channel["deliveries_24h"] == 1, (node, channel)
    assert channel["delivered_24h"] == 1, (node, channel)
    assert channel["success_rate"] == 100.0, (node, channel)
    assert channel["health"] == "healthy", (node, channel)
PY
}

wait_notification_receipts() {
  local attempt node
  for ((attempt = 1; attempt <= 60; attempt += 1)); do
    local captured=true
    for node in node-ru node-nl node-de; do
      if ! node_curl "${node}" --fail --silent --show-error \
        --config /tmp/admin-curl.conf \
        http://127.0.0.1:8080/api/v1/channels \
        >"${test_root}/notification-receipts-${node}.json" 2>/dev/null; then
        captured=false
        break
      fi
    done
    if [[ ${captured} == true ]] && notification_receipts_match 2>/dev/null; then
      return
    fi
    sleep 1
  done
  printf 'Successful delivery receipt did not replicate to every node within 60 seconds\n' >&2
  emit_notification_diagnostics
  return 1
}

notification_outboxes_idle() {
  "${smoke_python}" - "${test_root}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for node in ("node-ru", "node-nl", "node-de"):
    samples = [
        line.split()
        for line in (root / f"notification-metrics-{node}.txt").read_text().splitlines()
        if line.startswith("alert_hub_outbox_pending ")
    ]
    assert len(samples) == 1 and float(samples[0][1]) == 0.0, (node, samples)
PY
}

wait_notification_outboxes_idle() {
  local attempt node
  for ((attempt = 1; attempt <= 30; attempt += 1)); do
    local captured=true
    for node in node-ru node-nl node-de; do
      if ! node_curl "${node}" --fail --silent --show-error \
        http://127.0.0.1:8080/metrics \
        >"${test_root}/notification-metrics-${node}.txt" 2>/dev/null; then
        captured=false
        break
      fi
    done
    if [[ ${captured} == true ]] && notification_outboxes_idle 2>/dev/null; then
      return
    fi
    sleep 1
  done
  printf 'Notification outboxes did not become idle after the failover window\n' >&2
  emit_notification_diagnostics
  return 1
}

webhook_post_count() {
  local output=${test_root}/webhook-sink.log
  "${compose[@]}" logs --no-color webhook-sink >"${output}"
  "${smoke_python}" - "${output}" <<'PY'
import json
import sys

received = []
for line in open(sys.argv[1], encoding="utf-8"):
    start = line.find("{")
    if start < 0:
        continue
    try:
        payload = json.loads(line[start:])
    except json.JSONDecodeError:
        continue
    if payload.get("event") == "ci_webhook_received" and payload.get("path") == "/hook":
        received.append(payload)
assert all(
    item.get("method") == "POST"
    and item.get("status") == 204
    and isinstance(item.get("event_id"), str)
    and item["event_id"]
    for item in received
), received
print(len(received))
PY
}

docker image inspect "${image}" >/dev/null
configured_user=$(docker image inspect "${image}" --format '{{.Config.User}}')
[[ ${configured_user} == 10001:10001 ]] || {
  printf 'Image must configure runtime user 10001:10001, got %s\n' "${configured_user}" >&2
  exit 1
}

existing_subnets=${test_root}/existing-subnets.txt
: >"${existing_subnets}"
while IFS= read -r network_id; do
  [[ -n ${network_id} ]] || continue
  docker network inspect "${network_id}" \
    --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' >>"${existing_subnets}"
done < <(docker network ls --quiet)

for ((offset = 0; offset < 200; offset += 1)); do
  third_octet=$(((RANDOM + offset) % 250 + 1))
  candidate=10.253.${third_octet}.0/28
  if "${smoke_python}" - "${candidate}" "${existing_subnets}" <<'PY'
import ipaddress
import pathlib
import sys

candidate = ipaddress.ip_network(sys.argv[1])
for value in pathlib.Path(sys.argv[2]).read_text().split():
    try:
        existing = ipaddress.ip_network(value, strict=False)
    except ValueError:
        continue
    if candidate.overlaps(existing):
        raise SystemExit(1)
PY
  then
    export ALERT_HUB_CI_SUBNET=${candidate}
    break
  fi
done
[[ -n ${ALERT_HUB_CI_SUBNET:-} ]] || {
  printf 'Unable to reserve a non-overlapping internal Docker subnet\n' >&2
  exit 1
}
subnet_prefix=${ALERT_HUB_CI_SUBNET%.0/28}
export ALERT_HUB_CI_RU_IP=${subnet_prefix}.2
export ALERT_HUB_CI_NL_IP=${subnet_prefix}.3
export ALERT_HUB_CI_DE_IP=${subnet_prefix}.4
export ALERT_HUB_CI_SINK_IP=${subnet_prefix}.5

install -d -m 0777 \
  "${test_root}/node-ru" "${test_root}/node-nl" "${test_root}/node-de"
install -d -m 0755 "${test_root}/secrets"
openssl rand -base64 48 >"${test_root}/secrets/token-signing-key"
openssl rand -base64 48 >"${test_root}/secrets/cluster-bearer-secret"
openssl rand -hex 32 >"${test_root}/secrets/master-encryption-key"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "${test_root}/secrets/vapid-private-key.pem" 2>/dev/null
chmod 0444 "${test_root}/secrets/"*

"${compose[@]}" config --quiet
phase 'starting isolated nodes'
"${compose[@]}" up --detach --no-build
compose_started=true

phase 'checking runtime isolation and readiness'
wait_webhook_sink
webhook_container=$("${compose[@]}" ps --quiet webhook-sink)
[[ $(docker container inspect "${webhook_container}" --format '{{.HostConfig.ReadonlyRootfs}}') == true ]]
[[ $(docker container inspect "${webhook_container}" --format '{{.Config.User}}') == 10001:10001 ]]
[[ $(docker container inspect "${webhook_container}" --format '{{json .HostConfig.PortBindings}}') == null ]]
for node in node-ru node-nl node-de; do
  wait_node "${node}"
  for ui_path in / /sw.js /runtime-config.js /manifest.webmanifest; do
    ui_status=$(node_curl "${node}" --silent --output /dev/null --write-out '%{http_code}' \
      "http://127.0.0.1:8080${ui_path}")
    [[ ${ui_status} == 404 ]] || {
      printf 'UI-disabled node %s exposed %s with HTTP %s\n' \
        "${node}" "${ui_path}" "${ui_status}" >&2
      exit 1
    }
  done
  container_id=$("${compose[@]}" ps --quiet "${node}")
  [[ $(docker container inspect "${container_id}" --format '{{.HostConfig.ReadonlyRootfs}}') == true ]]
  [[ $(docker container inspect "${container_id}" --format '{{.Config.User}}') == 10001:10001 ]]
  [[ $(docker container inspect "${container_id}" --format '{{json .HostConfig.PortBindings}}') == null ]]
  data_source=$(docker container inspect "${container_id}" \
    --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')
  [[ ${data_source} == "${test_root}/${node}" ]]
  case ${node} in
    node-ru) expected_ip=${ALERT_HUB_CI_RU_IP} ;;
    node-nl) expected_ip=${ALERT_HUB_CI_NL_IP} ;;
    node-de) expected_ip=${ALERT_HUB_CI_DE_IP} ;;
  esac
  actual_ip=$(docker container inspect "${container_id}" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  [[ ${actual_ip} == "${expected_ip}" ]]
done

for ((attempt = 1; attempt <= 30; attempt += 1)); do
  [[ -s ${test_root}/node-ru/bootstrap-token ]] && break
  sleep 1
done
[[ -s ${test_root}/node-ru/bootstrap-token ]]
# Keep the generated 0600 secret private to the non-root container UID. Linux
# bind mounts preserve that ownership, so consume it through the owning node.
bootstrap_token=$("${compose[@]}" exec --no-TTY node-ru cat /data/bootstrap-token)
[[ -n ${bootstrap_token} ]]
admin_password=$(openssl rand -base64 24)
BOOTSTRAP_TOKEN=${bootstrap_token} ADMIN_PASSWORD=${admin_password} \
  "${smoke_python}" -c 'import json, os; print(json.dumps({"bootstrap_token": os.environ["BOOTSTRAP_TOKEN"], "username": "ci-admin", "password": os.environ["ADMIN_PASSWORD"], "device_name": "controlled-three-node-ci"}))' \
  >"${test_root}/bootstrap-request.json"
node_curl node-ru --fail --silent --show-error \
  --header 'Content-Type: application/json' --data-binary @- \
  http://127.0.0.1:8080/api/v1/auth/bootstrap \
  <"${test_root}/bootstrap-request.json" >"${test_root}/bootstrap-response.json"
access_token=$("${smoke_python}" -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["access_token"])' \
  "${test_root}/bootstrap-response.json")
[[ -n ${access_token} ]]
for node in node-ru node-nl node-de; do
  install_bearer_config "${node}" /tmp/admin-curl.conf "${access_token}"
done

printf '%s\n' \
  '{"name":"Controlled three-node source","kind":"generic_json","region":"ci"}' \
  >"${test_root}/source-request.json"
node_curl node-ru --fail --silent --show-error --config /tmp/admin-curl.conf \
  --header 'Content-Type: application/json' --data-binary @- \
  http://127.0.0.1:8080/api/v1/sources \
  <"${test_root}/source-request.json" >"${test_root}/source-response.json"
source_id=$("${smoke_python}" -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["id"])' \
  "${test_root}/source-response.json")
source_token=$("${smoke_python}" -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["token"])' \
  "${test_root}/source-response.json")
[[ -n ${source_id} && -n ${source_token} ]]
for node in node-ru node-nl node-de; do
  install_bearer_config "${node}" /tmp/source-curl.conf "${source_token}"
done

phase 'waiting for bootstrap and source replication'
for node in node-nl node-de; do
  source_synced=false
  for ((attempt = 1; attempt <= source_sync_attempts; attempt += 1)); do
    if node_curl "${node}" --fail --silent --show-error --config /tmp/admin-curl.conf \
      http://127.0.0.1:8080/api/v1/sources >"${test_root}/sources-${node}.json" 2>/dev/null \
      && "${smoke_python}" - "${test_root}/sources-${node}.json" "${source_id}" <<'PY'
import json
import sys

sources = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(sources) == 1 and sources[0]["id"] == sys.argv[2], sources
PY
    then
      source_synced=true
      break
    fi
    sleep 1
  done
  [[ ${source_synced} == true ]] || {
    printf 'Source configuration did not replicate to %s after %s attempts\n' \
      "${node}" "${source_sync_attempts}" >&2
    emit_sync_diagnostics >&2
    exit 1
  }
done

network_id=$(docker network ls --quiet \
  --filter "label=com.docker.compose.project=${project}" \
  --filter 'label=com.docker.compose.network=cluster')
[[ -n ${network_id} && ${network_id} != *$'\n'* ]]
ru_container=$("${compose[@]}" ps --quiet node-ru)
de_container=$("${compose[@]}" ps --quiet node-de)
docker network disconnect "${network_id}" "${ru_container}"
docker network disconnect "${network_id}" "${de_container}"
wait_node node-ru
wait_node node-de

phase 'ingesting duplicate firing and out-of-order resolution during partition'
printf '%s\n' \
  '{"external_event_id":"occurrence-1-firing","dedup_key":"controlled-partition","status":"firing","title":"Controlled partition incident","description":"Docker CI substitute","severity":"critical","starts_at":"2026-09-01T10:00:00Z","labels":{"service":"controlled-ci"}}' \
  >"${test_root}/firing.json"
for node in node-ru node-nl; do
  node_curl "${node}" --fail --silent --show-error --config /tmp/source-curl.conf \
    --header 'Content-Type: application/json' --data-binary @- \
    "http://127.0.0.1:8080/ingest/v1/events/${source_id}" \
    <"${test_root}/firing.json" >"${test_root}/firing-${node}.json"
  assert_ingest "${test_root}/firing-${node}.json" 1 0
done

printf '%s\n' \
  '{"external_event_id":"occurrence-1-resolved","dedup_key":"controlled-partition","status":"resolved","title":"Controlled partition incident","description":"Docker CI substitute","severity":"critical","starts_at":"2026-09-01T10:00:00Z","ends_at":"2026-09-01T10:05:00Z","labels":{"service":"controlled-ci"}}' \
  >"${test_root}/resolved.json"
node_curl node-de --fail --silent --show-error --config /tmp/source-curl.conf \
  --header 'Content-Type: application/json' --data-binary @- \
  "http://127.0.0.1:8080/ingest/v1/events/${source_id}" \
  <"${test_root}/resolved.json" >"${test_root}/resolved-node-de.json"
assert_ingest "${test_root}/resolved-node-de.json" 1 0
incident_id=$("${smoke_python}" -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["incident_ids"][0])' \
  "${test_root}/resolved-node-de.json")

node_curl node-de --fail --silent --show-error --config /tmp/admin-curl.conf \
  "http://127.0.0.1:8080/api/v1/incidents/${incident_id}" \
  >"${test_root}/de-out-of-order.json"
"${smoke_python}" - "${test_root}/de-out-of-order.json" <<'PY'
import json
import sys

detail = json.load(open(sys.argv[1], encoding="utf-8"))
assert detail["status"] == "resolved", detail
assert [event["event_type"] for event in detail["timeline"]] == ["resolved"], detail
PY

docker network connect --ip "${ALERT_HUB_CI_DE_IP}" --alias node-de \
  "${network_id}" "${de_container}"
phase 'waiting for NL and DE recovery'
wait_two_node_projection firing,resolved

phase 'stopping DE and ingesting on surviving NL'
"${compose[@]}" stop --timeout 5 node-de
[[ $(docker container inspect "${de_container}" --format '{{.State.Running}}') == false ]]
wait_node node-nl

printf '%s\n' \
  '{"external_event_id":"occurrence-1-survivor-resolved","dedup_key":"controlled-partition","status":"resolved","title":"Controlled partition incident","description":"Accepted while DE is stopped","severity":"critical","starts_at":"2026-09-01T10:00:00Z","ends_at":"2026-09-01T10:06:00Z","labels":{"service":"controlled-ci"}}' \
  >"${test_root}/survivor.json"
node_curl node-nl --fail --silent --show-error --config /tmp/source-curl.conf \
  --header 'Content-Type: application/json' --data-binary @- \
  "http://127.0.0.1:8080/ingest/v1/events/${source_id}" \
  <"${test_root}/survivor.json" >"${test_root}/survivor-node-nl.json"
assert_ingest "${test_root}/survivor-node-nl.json" 1 0

"${compose[@]}" start node-de
wait_node node-de
install_bearer_config node-de /tmp/admin-curl.conf "${access_token}"
phase 'waiting for restarted DE to catch survivor event'
wait_two_node_projection firing,resolved,resolved

docker network connect --ip "${ALERT_HUB_CI_RU_IP}" --alias node-ru \
  "${network_id}" "${ru_container}"
"${compose[@]}" restart --timeout 5 node-ru
wait_node node-ru
install_bearer_config node-ru /tmp/admin-curl.conf "${access_token}"
install_bearer_config node-ru /tmp/source-curl.conf "${source_token}"
phase 'waiting for exact three-node cursor and projection convergence'
wait_full_convergence resolved firing,resolved,resolved

phase 're-firing after recovery and checking a new occurrence'
printf '%s\n' \
  '{"external_event_id":"occurrence-2-firing","dedup_key":"controlled-partition","status":"firing","title":"Controlled partition incident","description":"New occurrence after recovery","severity":"critical","starts_at":"2026-09-01T11:00:00Z","labels":{"service":"controlled-ci"}}' \
  >"${test_root}/refire.json"
node_curl node-ru --fail --silent --show-error --config /tmp/source-curl.conf \
  --header 'Content-Type: application/json' --data-binary @- \
  "http://127.0.0.1:8080/ingest/v1/events/${source_id}" \
  <"${test_root}/refire.json" >"${test_root}/refire-node-ru.json"
assert_ingest "${test_root}/refire-node-ru.json" 1 0
wait_full_convergence open firing,resolved,resolved,firing

phase 'creating controlled generic webhook channel and route'
printf '%s\n' \
  '{"name":"Controlled ownership evidence webhook","kind":"generic_webhook","enabled":true,"config":{"url":"http://webhook-sink:8081/hook"},"eligible_node_ids":["node-ru","node-nl","node-de"]}' \
  >"${test_root}/notification-channel-request.json"
node_curl node-ru --fail --silent --show-error --config /tmp/admin-curl.conf \
  --header 'Content-Type: application/json' --data-binary @- \
  http://127.0.0.1:8080/api/v1/channels \
  <"${test_root}/notification-channel-request.json" \
  >"${test_root}/notification-channel-response.json"
notification_channel_id=$("${smoke_python}" -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["id"])' \
  "${test_root}/notification-channel-response.json")
[[ -n ${notification_channel_id} ]]

"${smoke_python}" -c \
  'import json, sys; print(json.dumps({"name": "Controlled ownership evidence route", "enabled": True, "priority": -100, "source_filter": [sys.argv[1]], "label_matchers": [{"name": "notification_evidence", "operator": "equals", "value": "true"}], "channel_ids": [sys.argv[2]], "continue_matching": False}))' \
  "${source_id}" "${notification_channel_id}" \
  >"${test_root}/notification-route-request.json"
node_curl node-ru --fail --silent --show-error --config /tmp/admin-curl.conf \
  --header 'Content-Type: application/json' --data-binary @- \
  http://127.0.0.1:8080/api/v1/routes \
  <"${test_root}/notification-route-request.json" \
  >"${test_root}/notification-route-response.json"
notification_route_id=$("${smoke_python}" -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["id"])' \
  "${test_root}/notification-route-response.json")
[[ -n ${notification_route_id} ]]

phase 'waiting for notification configuration replication'
wait_notification_configuration

phase 'ingesting one logical notification event concurrently on all connected nodes'
printf '%s\n' \
  '{"external_event_id":"notification-ownership-firing","dedup_key":"notification-ownership-evidence","status":"firing","title":"Connected cluster notification ownership","description":"Controlled Docker CI provider-call evidence","severity":"critical","starts_at":"2026-09-01T12:00:00Z","labels":{"service":"controlled-ci","notification_evidence":"true"}}' \
  | write_private_config node-ru /tmp/notification-evidence.json
# The inner shell expands its positional source id and launches the three requests together.
# shellcheck disable=SC2016
"${compose[@]}" exec --no-TTY node-ru sh -c '
set -eu
source_id=$1
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
  --config /tmp/source-curl.conf --header "Content-Type: application/json" \
  --data-binary @/tmp/notification-evidence.json \
  "http://node-ru:8080/ingest/v1/events/${source_id}" \
  >/tmp/notification-evidence-node-ru.json &
ru_pid=$!
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
  --config /tmp/source-curl.conf --header "Content-Type: application/json" \
  --data-binary @/tmp/notification-evidence.json \
  "http://node-nl:8080/ingest/v1/events/${source_id}" \
  >/tmp/notification-evidence-node-nl.json &
nl_pid=$!
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error \
  --config /tmp/source-curl.conf --header "Content-Type: application/json" \
  --data-binary @/tmp/notification-evidence.json \
  "http://node-de:8080/ingest/v1/events/${source_id}" \
  >/tmp/notification-evidence-node-de.json &
de_pid=$!
status=0
wait "${ru_pid}" || status=1
wait "${nl_pid}" || status=1
wait "${de_pid}" || status=1
if [ "${status}" -ne 0 ]; then
  exit "${status}"
fi
for node in node-ru node-nl node-de; do
  printf "%s\t" "${node}"
  tr -d "\r\n" <"/tmp/notification-evidence-${node}.json"
  printf "\n"
done
' _ "${source_id}" >"${test_root}/notification-ingest-results.ndjson"

notification_incident_id=$(
  "${smoke_python}" - "${test_root}/notification-ingest-results.ndjson" <<'PY'
import json
import sys

results = {}
for line in open(sys.argv[1], encoding="utf-8"):
    node, raw = line.rstrip("\n").split("\t", 1)
    results[node] = json.loads(raw)
assert set(results) == {"node-ru", "node-nl", "node-de"}, results
for node, payload in results.items():
    assert payload["accepted"] == 1 and payload["duplicates"] == 0, (node, payload)
    assert len(payload["incident_ids"]) == 1, (node, payload)
incident_ids = {payload["incident_ids"][0] for payload in results.values()}
assert len(incident_ids) == 1, results
print(incident_ids.pop())
PY
)
[[ -n ${notification_incident_id} ]]

phase 'waiting for the owner receipt to replicate'
wait_notification_receipts
if ! initial_webhook_count=$(webhook_post_count); then
  printf 'Webhook sink log was not valid controlled delivery evidence\n' >&2
  emit_notification_diagnostics
  exit 1
fi
[[ ${initial_webhook_count} == 1 ]] || {
  printf 'Expected exactly one provider POST, observed %s\n' \
    "${initial_webhook_count}" >&2
  emit_notification_diagnostics
  exit 1
}

phase 'checking receipt suppression beyond every secondary failover delay'
# Three candidates have ranks 0..2 and the CI failover base is three seconds.
sleep 8
wait_notification_outboxes_idle
wait_notification_receipts
if ! final_webhook_count=$(webhook_post_count); then
  printf 'Webhook sink log became invalid after the failover window\n' >&2
  emit_notification_diagnostics
  exit 1
fi
[[ ${final_webhook_count} == 1 ]] || {
  printf 'Replicated receipt failed to suppress a secondary provider POST: observed %s\n' \
    "${final_webhook_count}" >&2
  emit_notification_diagnostics
  exit 1
}

for node in node-ru node-nl node-de; do
  [[ -s ${test_root}/${node}/alert-hub.db ]]
done

printf '%s\n' \
  'Controlled three-node Docker CI substitute passed: partition, process loss, restart, cursor convergence, deterministic projection, dedupe, re-fire, single-owner webhook delivery, and replicated-receipt suppression.'

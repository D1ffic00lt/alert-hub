#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only, deliberately sanitized host inventory. It reports capabilities and
# counts only: no IP addresses, hostnames, container names, environment, or
# configuration contents leave the host.

printf 'os='
awk -F= '$1 == "PRETTY_NAME" {gsub(/^"|"$/, "", $2); print $2}' /etc/os-release
printf 'arch='
uname -m
printf 'user='
id -un

# This deliberately probes unrestricted passwordless sudo only. A correctly
# configured narrow docker-*-node.sh sudoers policy is expected to report no.
printf 'sudo_unrestricted_nopasswd='
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  printf 'yes\n'
else
  printf 'no\n'
fi

printf 'docker_server='
if command -v docker >/dev/null 2>&1 \
  && docker version --format '{{.Server.Version}}' 2>/dev/null; then
  :
else
  printf 'unavailable\n'
fi

printf 'compose='
if command -v docker >/dev/null 2>&1 \
  && docker compose version --short 2>/dev/null; then
  :
else
  printf 'unavailable\n'
fi

for service in docker nginx caddy prometheus alertmanager grafana-server; do
  printf 'service_%s=' "${service}"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active "${service}" 2>/dev/null || true
  else
    printf 'no-systemd\n'
  fi
done

printf 'root_free_kb='
df -Pk / | awk 'NR == 2 {print $4}'
printf 'alert_hub_present='
if [[ -e /opt/alert-hub || -e /etc/alert-hub ]]; then
  printf 'yes\n'
else
  printf 'no\n'
fi

printf 'runner_units='
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '/actions[.]runner/ {count++} END {print count + 0}'
else
  printf '0\n'
fi

printf 'running_containers='
if command -v docker >/dev/null 2>&1; then
  docker ps --quiet 2>/dev/null | awk 'END {print NR + 0}'
else
  printf '0\n'
fi

printf 'listeners_80_443='
if command -v ss >/dev/null 2>&1; then
  ss -lntH 2>/dev/null \
    | awk '$4 ~ /:(80|443)$/ {count++} END {print count + 0}'
else
  printf 'unknown\n'
fi

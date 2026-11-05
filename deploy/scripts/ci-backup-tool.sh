#!/usr/bin/env bash
set -Eeuo pipefail

# Exercise ownership and restore guards as root inside a disposable container.
# The persistent CI VM itself needs no general sudo grant for repository code.
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
docker_binary=$(command -v docker)
docker run --rm --network none \
  --mount "type=bind,source=${repo_root},target=/repo,readonly" \
  --mount "type=bind,source=${docker_binary},target=/usr/bin/docker,readonly" \
  --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
  --workdir /repo \
  python:3.12.14-slim-bookworm \
  bash deploy/scripts/test-backup-tool.sh

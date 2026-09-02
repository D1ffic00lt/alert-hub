SHELL := /bin/sh
PYTHON ?= $(if $(wildcard .venv/bin/python),$(abspath .venv/bin/python),python3)
COMPOSE := docker compose -f docker-compose.yml
FRONTEND_BIN := $(abspath frontend/node_modules/.bin)
BASH_SCRIPTS := \
	deploy/scripts/alert-hub-backup \
	deploy/scripts/install-proxy-config.sh \
	deploy/scripts/ci-migrations.sh \
	deploy/scripts/check-no-secrets.sh \
	deploy/scripts/test-backup-tool.sh \
	deploy/scripts/ci-container-smoke.sh \
	deploy/scripts/ci-image-matrix-smoke.sh \
	deploy/scripts/ci-three-node-failure.sh \
	deploy/scripts/host-readiness.sh \
	.github/deploy/scripts/docker-provision-node.sh \
	.github/deploy/scripts/docker-deploy-node.sh \
	.github/deploy/scripts/docker-rollback-node.sh \
	.github/deploy/scripts/docker-status-node.sh
SH_SCRIPTS := \
	docker-install.sh \
	backend/container/entrypoint.sh \
	frontend/container/entrypoint.sh \
	frontend/container/render-ui-runtime.sh
DEPLOY_PYTHON := \
	deploy/scripts/check-codeql-sarif.py \
	deploy/scripts/check-ci-policy.py \
	deploy/scripts/check-openapi.py
override RUNTIME_ROOT := $(abspath runtime)
override RUNTIME_SECRETS_DIR := $(RUNTIME_ROOT)/secrets

.PHONY: \
	init config build up down logs ps health \
	format format-check repository-quality backend-test backend-quality \
	frontend-test frontend-quality security-check operations-check \
	container-smoke distributed-smoke test quality ci

init:
	@if [ -L .env ]; then printf '%s\n' 'Refusing symlinked .env.' >&2; exit 1; fi
	@umask 077; if [ ! -f .env ]; then cp .env.example .env; chmod 0600 .env; fi
	@if [ -L "$(RUNTIME_ROOT)" ] || [ -L "$(RUNTIME_SECRETS_DIR)" ]; then \
		printf '%s\n' 'Refusing a symlinked runtime path.' >&2; \
		exit 1; \
	fi
	@umask 077; mkdir -p "$(RUNTIME_SECRETS_DIR)"; chmod 0700 "$(RUNTIME_ROOT)" "$(RUNTIME_SECRETS_DIR)"
	@printf '%s\n' 'Created local .env and runtime/secrets when missing.'

config:
	$(COMPOSE) config

build:
	$(COMPOSE) build --pull

up:
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --follow --tail=200 alert-hub alert-hub-web

ps:
	$(COMPOSE) ps

health:
	curl --fail --silent --show-error http://127.0.0.1:$${ALERT_HUB_HOST_PORT:-8080}/health/ready

backend-test:
	"$(PYTHON)" -m pytest backend/tests

backend-quality:
	"$(PYTHON)" -m ruff format --check backend
	"$(PYTHON)" -m ruff check backend
	"$(PYTHON)" -m ruff format --check --config ruff.toml $(DEPLOY_PYTHON)
	"$(PYTHON)" -m ruff check --config ruff.toml $(DEPLOY_PYTHON)
	"$(PYTHON)" -m mypy backend/alert_hub
	cd backend && "$(PYTHON)" -m pytest tests --cov=alert_hub --cov-report=term-missing
	bash deploy/scripts/ci-migrations.sh
	"$(PYTHON)" deploy/scripts/check-openapi.py

frontend-test:
	npm --prefix frontend test
	npm --prefix frontend run build
	npm --prefix frontend run test:e2e

frontend-quality:
	npm --prefix frontend run lint
	npm --prefix frontend run typecheck
	npm --prefix frontend test
	npm --prefix frontend run build
	npm --prefix frontend run test:e2e

format:
	"$(FRONTEND_BIN)/prettier" --write . --ignore-unknown
	"$(PYTHON)" -m ruff format backend
	"$(PYTHON)" -m ruff format --config ruff.toml $(DEPLOY_PYTHON)

format-check:
	"$(FRONTEND_BIN)/prettier" --check . --ignore-unknown
	"$(PYTHON)" -m ruff format --check backend
	"$(PYTHON)" -m ruff format --check --config ruff.toml $(DEPLOY_PYTHON)

repository-quality:
	"$(FRONTEND_BIN)/prettier" --check . --ignore-unknown
	"$(FRONTEND_BIN)/markdownlint-cli2" "**/*.md" "!frontend/node_modules/**" "!frontend/dist/**" "!.venv/**" "!backend/.venv/**"
	"$(PYTHON)" -m yamllint -c .yamllint.yaml .yamllint.yaml .github deploy docker-compose.yml docker-compose.split.yml docker-compose.api-only.yml
	"$(PYTHON)" deploy/scripts/check-ci-policy.py
	bash -n $(BASH_SCRIPTS)
	sh -n $(SH_SCRIPTS)
	shellcheck $(BASH_SCRIPTS) $(SH_SCRIPTS)
	@if docker buildx build --help 2>/dev/null | grep -q -- '--check'; then \
		docker buildx build --check --file backend/Dockerfile backend; \
		docker buildx build --check --file frontend/Dockerfile frontend; \
	else \
		printf '%s\n' 'Skipping optional Dockerfile lint: local Buildx lacks build --check.'; \
	fi

security-check:
	bash deploy/scripts/check-no-secrets.sh
	"$(PYTHON)" -m pip check
	"$(PYTHON)" -m pip_audit --local --cache-dir "$${TMPDIR:-/tmp}/alert-hub-pip-audit"
	npm --prefix frontend audit --audit-level=high

operations-check:
	ALERT_HUB_ENV_FILE="$(abspath .env.example)" \
		ALERT_HUB_DATA_VOLUME=alert-hub-config-validation-data ALERT_HUB_SECRETS_DIR=/tmp \
		docker compose -f docker-compose.yml config --quiet
	ALERT_HUB_ENV_FILE="$(abspath .env.example)" \
		ALERT_HUB_DATA_VOLUME=alert-hub-config-validation-data ALERT_HUB_SECRETS_DIR=/tmp \
		docker compose -f docker-compose.split.yml config --quiet
	ALERT_HUB_ENV_FILE="$(abspath .env.example)" \
		ALERT_HUB_DATA_VOLUME=alert-hub-config-validation-data ALERT_HUB_SECRETS_DIR=/tmp \
		docker compose -f docker-compose.api-only.yml config --quiet
	ALERT_HUB_ENV_FILE="$(abspath .env.example)" \
		ALERT_HUB_DATA_VOLUME=alert-hub-config-validation-data ALERT_HUB_SECRETS_DIR=/tmp \
		MONITORING_NETWORK=existing-monitoring \
		docker compose -f docker-compose.yml -f deploy/docker-compose.monitoring.yaml config --quiet
	ALERT_HUB_API_IMAGE=ghcr.io/example/alert-hub-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		ALERT_HUB_WEB_IMAGE=ghcr.io/example/alert-hub-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
		ALERT_HUB_ENV_FILE="$(abspath .env.example)" \
		ALERT_HUB_DATA_DIR=/tmp ALERT_HUB_SECRETS_DIR=/tmp \
		ALERT_HUB_EDGE_SUBNET=10.253.251.0/29 \
		ALERT_HUB_API_IP=10.253.251.2 ALERT_HUB_WEB_IP=10.253.251.3 \
		ALERT_HUB_PEER_ADDRESS=10.253.252.2 \
		docker compose -f .github/deploy/docker-compose.production.yml config --quiet
	ALERT_HUB_API_IMAGE=ghcr.io/example/alert-hub-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		ALERT_HUB_WEB_IMAGE=ghcr.io/example/alert-hub-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
		ALERT_HUB_ENV_FILE="$(abspath .env.example)" \
		ALERT_HUB_DATA_DIR=/tmp ALERT_HUB_SECRETS_DIR=/tmp \
		ALERT_HUB_EDGE_SUBNET=10.253.251.0/29 \
		ALERT_HUB_API_IP=10.253.251.2 ALERT_HUB_WEB_IP=10.253.251.3 \
		ALERT_HUB_PEER_ADDRESS=10.253.252.2 \
		MONITORING_NETWORK=existing-monitoring \
		docker compose \
			-f .github/deploy/docker-compose.production.yml \
			-f .github/deploy/docker-compose.production-monitoring.yml \
			config --quiet
	ALERT_HUB_API_IMAGE=alert-hub-api:ci \
		ALERT_HUB_CI_ROOT=/tmp/alert-hub-ci-compose-validation \
		ALERT_HUB_CI_SUBNET=10.253.250.0/28 \
		ALERT_HUB_CI_RU_IP=10.253.250.2 \
		ALERT_HUB_CI_NL_IP=10.253.250.3 \
		ALERT_HUB_CI_DE_IP=10.253.250.4 \
		ALERT_HUB_CI_SINK_IP=10.253.250.5 \
		docker compose -f deploy/docker-compose.ci-three-node.yaml config --quiet
	sudo bash deploy/scripts/test-backup-tool.sh

container-smoke:
	docker build --tag alert-hub-api:ci --file backend/Dockerfile backend
	docker build --tag alert-hub-web:ci --file frontend/Dockerfile frontend
	bash deploy/scripts/ci-image-matrix-smoke.sh alert-hub-api:ci alert-hub-web:ci
	bash deploy/scripts/ci-three-node-failure.sh alert-hub-api:ci

distributed-smoke:
	bash deploy/scripts/ci-three-node-failure.sh "$${ALERT_HUB_API_IMAGE:-alert-hub-api:ci}"

test: backend-test frontend-test

quality: repository-quality backend-quality frontend-quality

ci: quality security-check operations-check

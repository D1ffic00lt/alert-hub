# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12.14

FROM python:${PYTHON_VERSION}-slim-bookworm AS backend-build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv
RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /src/backend
COPY pyproject.toml ./
COPY alert_hub ./alert_hub
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip setuptools wheel && \
    python -m pip install .

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG BUILD_VERSION=dev
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
ARG BUILD_COMPATIBILITY=dev

LABEL org.opencontainers.image.title="Alert Hub API" \
      org.opencontainers.image.description="Alert Hub API and node-local workers" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_CREATED}" \
      org.opencontainers.image.licenses="MIT" \
      org.alert-hub.component="api" \
      org.alert-hub.compatibility="${BUILD_COMPATIBILITY}" \
      org.alert-hub.schema-compatibility="n-1-expand-contract"

RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates curl tini && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 alert-hub && \
    useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin alert-hub && \
    mkdir -p /data && \
    chown 10001:10001 /data

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOFTWARE_VERSION="${BUILD_VERSION}" \
    BACKEND_HOST=0.0.0.0 \
    BACKEND_PORT=8080 \
    DATABASE_URL=sqlite:////data/alert-hub.db \
    UI_ENABLED=false \
    MIGRATE_ON_START=true

WORKDIR /app/backend
COPY --from=backend-build /opt/venv /opt/venv
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
COPY --chown=0:0 container/entrypoint.sh /usr/local/bin/alert-hub-api-entrypoint

RUN chmod 0555 /usr/local/bin/alert-hub-api-entrypoint

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health/ready || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/alert-hub-api-entrypoint"]

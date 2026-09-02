# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=22.23.2
ARG NGINX_VERSION=1.28.3-alpine3.23

FROM node:${NODE_VERSION}-bookworm-slim AS frontend-build

WORKDIR /src/frontend
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY app ./app
COPY public ./public
COPY index.html postcss.config.mjs tsconfig.json vite.config.ts ./
RUN npm run build

FROM nginx:${NGINX_VERSION} AS runtime

ARG BUILD_VERSION=dev
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
ARG BUILD_COMPATIBILITY=dev

LABEL org.opencontainers.image.title="Alert Hub Web" \
      org.opencontainers.image.description="Alert Hub static PWA and same-origin API proxy" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_CREATED}" \
      org.opencontainers.image.component="web" \
      org.opencontainers.image.licenses="MIT" \
      org.alert-hub.component="web" \
      org.alert-hub.compatibility="${BUILD_COMPATIBILITY}" \
      org.alert-hub.schema-compatibility="n-1-expand-contract"

RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf && \
    mkdir -p /run/alert-hub/ui /tmp/nginx && \
    chown -R 101:101 /run/alert-hub /tmp/nginx /usr/share/nginx/html

COPY --from=frontend-build --chown=101:101 /src/frontend/dist /usr/share/nginx/html
COPY --chown=0:0 container/entrypoint.sh /usr/local/bin/alert-hub-web-entrypoint
COPY --chown=0:0 container/render-ui-runtime.sh /usr/local/bin/render-ui-runtime
COPY --chown=0:0 container/nginx.conf /etc/alert-hub/nginx.conf

RUN chmod 0555 /usr/local/bin/alert-hub-web-entrypoint /usr/local/bin/render-ui-runtime && \
    chmod 0444 /etc/alert-hub/nginx.conf

USER 101:101
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -T 2 -t 1 -O /dev/null http://127.0.0.1:8080/health/ready && \
    wget -q -T 2 -t 1 -O /dev/null http://127.0.0.1:8080/ && \
    wget -q -T 2 -t 1 -O /dev/null http://127.0.0.1:8080/runtime-config.js

ENTRYPOINT ["/usr/local/bin/alert-hub-web-entrypoint"]

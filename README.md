# Alert Hub

Alert Hub is a self-hosted incident intake hub and installable PWA. Each node
keeps its own SQLite database and remains useful when regional peers are
unavailable. Prometheus stays the time-series source of truth and Grafana stays
the detailed visualization surface.

The repository contains a working distributed foundation: authenticated
Alertmanager and generic intake, deterministic incident projection, paginated
peer synchronization, durable provider delivery, encrypted integration
credentials, structured observability, and a React PWA. Real regional,
provider, proxy, and iPhone acceptance exercises remain installation work; see
[implementation status](docs/implementation-status.md) and
[acceptance evidence](docs/acceptance-evidence.md).

Alert Hub is licensed under the [MIT License](LICENSE).

## Start with Docker

Docker Engine with Compose v2 is the only requirement for the standard setup:

```bash
cp .env.example .env
docker compose up -d
curl --fail http://127.0.0.1:8080/health/ready
```

The default Compose file builds and runs two independent containers:

- `alert-hub-api`: Python/FastAPI, migrations, workers, and node-local SQLite;
- `alert-hub-web`: prebuilt React static assets served by unprivileged Nginx.

Only the web service is published, on `127.0.0.1:8080` by default. Put an
existing HTTPS Nginx or Caddy instance in front of it. The supplied proxy
examples deny public access to peer, metrics, deep-health, and API-documentation
routes. Production peer synchronization uses separate operator-managed HTTPS
hostnames; dedicated Nginx/Caddy templates allowlist exact node `/32` sources
and expose only the two required peer operations.

The explicit split example is equivalent to the default:

```bash
docker compose -f docker-compose.split.yml up -d
```

The backend can run without Node.js, npm, a frontend build, or even a
`frontend/` checkout:

```bash
docker compose -f docker-compose.api-only.yml up -d
```

API-only publishes the API on the configured loopback port. The optional
installer creates a private `.env`, prepares the ignored runtime directory,
and prompts for split or API-only mode:

```bash
./docker-install.sh
```

The default development configuration intentionally omits production secrets.
Production mode requires strong file-backed keys, exact HTTPS origins, secure
cookies, and installation-specific peer/proxy allowlists.

## Independent images

Every version release publishes exactly two immutable images with one tag and
separate digests:

```text
ghcr.io/<owner>/alert-hub-api:vX.Y.Z
ghcr.io/<owner>/alert-hub-web:vX.Y.Z
```

The release manifest records both digest-qualified references and their API
contract compatibility value. A release is complete only after both images are
built, tested together, published, attested, and attached to the same GitHub
Release. A manual Release workflow run on `main` reads the product version from
the root `VERSION` file. An optional explicit workflow input or an
existing version tag must match that file. The workflow creates the immutable
tag after the gate; pushing an existing version tag remains supported. Package
manager versions are not used as the product release version.

The API image uses `backend/` as its complete build context. It cannot see or
copy frontend files and contains no Node.js tooling. The web image uses
`frontend/` as its complete build context; Node.js exists only in the build
stage, while the runtime contains static assets and unprivileged Nginx.

Production deployment may update `api`, `web`, or both. A component-only update
does not recreate its peer. If the API is unavailable, the web container stays
running and returns `503` for application requests; it automatically recovers
when the API becomes ready.

## Development

Direct development requires Python 3.12 and Node.js 22.14:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './backend[dev]'
npm --prefix frontend ci
```

Run the complete source checks with:

```bash
make quality
make security-check
make operations-check
```

Focused commands are also available:

```bash
make backend-quality
make frontend-quality
make repository-quality
make container-smoke
```

`make container-smoke` builds both images, verifies their runtime boundaries,
exercises split startup and recovery, proves component-only recreation, and
runs the controlled three-node API failure scenario. CI enforces a 75% backend
branch-coverage floor in addition to migrations, OpenAPI, browser, security,
Compose, backup/restore, and static deployment/rollback policy checks. The full
root-owned host rollback state machine remains a production-like installation drill.

Pull requests and pushes to `main` run read-only GitHub-hosted checks and never
publish or deploy. Semver-like `v*.*.*` tags also run the normal CI matrix
without publishing images; the separate release workflow is the only workflow
that pushes the two `vX.Y.Z` images. It publishes SBOMs, GitHub-hosted provenance
attestations, and the compatible-pair manifest without adding synthetic
`sha256-*` tags to GHCR. Production deploy and rollback are separate, manual,
protected workflows.

## Repository layout

```text
backend/                         Python application and API image
frontend/                        React PWA and static web image
docker-compose.yml               default API + web deployment
docker-compose.split.yml         explicit API + web example
docker-compose.api-only.yml      headless backend example
.github/workflows/               CI, release, manual deploy, rollback
.github/deploy/                  production Compose and node scripts
deploy/                          generic validation, backup, and smoke tooling
docs/                            architecture, security, and runbooks
```

## Documentation

- [Architecture](docs/architecture.md)
- [Implementation status](docs/implementation-status.md)
- [Acceptance evidence](docs/acceptance-evidence.md)
- [Production deployment](docs/deployment.md)
- [Operations and backup](docs/operations.md)
- [Failure and rollback runbook](docs/runbooks/failure-and-rollback.md)
- [Security and threat model](docs/security.md)
- [Security policy](SECURITY.md)
- [Source integrations](docs/source-integrations.md)

The guiding trade-off is deliberate: **do not lose an alert, even when avoiding
a duplicate is temporarily impossible**.

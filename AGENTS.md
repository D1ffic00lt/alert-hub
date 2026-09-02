# Alert Hub agent guide

This repository implements a self-hosted, eventually consistent alert hub. Treat this file as the default working agreement for every directory unless a more specific `AGENTS.md` is added below it.

## Product invariants

- A node must remain useful without quorum: local ingest, reads, incident actions, and queued notification work cannot require another node.
- Prefer preserving an alert over suppressing every duplicate. A partition may produce a duplicate notification; it must not erase an event.
- Every node owns its own SQLite file. Never introduce shared/network SQLite, Redis, a broker, or a hidden central coordinator.
- Replicated history is append-only and idempotent. Preserve `origin_node_id`, `origin_seq`, `event_id`, tombstones, and deterministic projection ordering.
- Public traffic terminates at the operator's existing HTTPS proxy. Application and peer ports stay loopback/private; `/internal/*` must never be routed by the public virtual host.
- Prometheus remains the time-series source of truth and Grafana remains the detailed visualization surface. Do not copy arbitrary time-series into SQLite or accept browser-authored PromQL.
- Product display text comes from `APP_NAME`; table names, Python namespaces, protocol fields, and event types do not.

## Repository map and dependency direction

- `backend/alert_hub/domain`: pure domain rules. It must not import FastAPI, SQLAlchemy, provider SDKs, or deployment code.
- `backend/alert_hub/application`: use-case orchestration and small external-boundary interfaces.
- `backend/alert_hub/infrastructure`: database, peer transport, encryption, Prometheus, and notification provider adapters.
- `backend/alert_hub/api`: HTTP validation, authentication/authorization, serialization, and error mapping only.
- `backend/alert_hub/workers`: short, restart-safe in-process loops; all durable state belongs in SQLite.
- `frontend/app`, `frontend/public`: Vite React PWA, React Router/TanStack Query runtime, and service worker.
- `backend/Dockerfile`: standalone Python/FastAPI image; its build context is `backend/` and must never require frontend or Node.js files.
- `frontend/Dockerfile`: standalone static web image; Node.js is build-only and must not exist in the Nginx runtime.
- Root `docker-compose*.yml`: universal split and API-only examples. The default `docker-compose.yml` is the two-service deployment.
- `.github/deploy`: production-only Compose override and root-owned deploy/rollback/status scripts. Never commit installation inventory or credentials there.
- `deploy`: generic backup, validation, reverse-proxy, and controlled integration tooling.
- `docs`: architecture, operator procedures, security boundaries, and honest implementation status.

Keep dependencies pointing inward. Do not invent repository classes for trivial ORM operations, but isolate real boundaries such as HTTP providers, encryption, and peer transport so they can be tested without a network.

## Security rules

- Never commit or log passwords, cookies, bearer/refresh/source tokens, VAPID private keys, channel credentials, authorization headers, real infrastructure IPs, or SQLite data.
- Store source and refresh credentials only as keyed hashes. Show newly generated source credentials once.
- Store notification, datasource, and push material with context-bound AES-GCM using the file-backed master key.
- Validate outbound URLs at configuration time and again at connection time. Block loopback, link-local, metadata, private, and DNS-rebinding targets unless an explicit narrowly scoped setting permits a private integration.
- Mutations authenticated by cookies require exact Origin and CSRF checks. Credentialed CORS uses an exact allowlist, never `*`.
- Browser access tokens live in memory. Refresh credentials stay `HttpOnly`, `Secure` in production, scoped narrowly, rotated, and revocable.
- An authenticated service-worker read cache must be partitioned by session and cleared/pruned on session changes. Never cache secrets, auth endpoints, mutations, or raw bearer tokens.
- Web Push handlers always show a visible notification. Permission prompts are allowed only directly after a user action.
- Keep provider timeouts finite, retry only retryable failures, cap backoff, and redact provider responses before persistence or logs.

## Backend changes

- Target Python 3.12 and strict typing. Run:

  ```bash
  ruff format --check backend
  ruff check backend
  ruff format --check --config ruff.toml deploy/scripts/*.py
  ruff check --config ruff.toml deploy/scripts/*.py
  mypy backend/alert_hub
  pytest backend/tests
  bash deploy/scripts/ci-migrations.sh
  python deploy/scripts/check-openapi.py
  ```

- New behavior needs focused unit tests and an integration regression when it crosses the database, HTTP, worker, encryption, or sync boundary.
- Keep transactions short. Worker claims, retries, and remote calls must not hold a SQLite write transaction across network I/O.
- Treat duplicate events and retries as normal control flow. Database uniqueness remains the final idempotency guard.
- Every schema change gets a new Alembic revision. Never edit an already released revision; `0001_initial` is an explicit immutable snapshot and must not import live ORM metadata.
- Migrations are forward-only and N-1 compatible. Ordinary application rollback never downgrades or restores the database.
- Add committed API operations to `docs/openapi-contract.json` and verify the generated contract.
- Production dependencies belong in `[project.dependencies]`; test/style tools belong in the `dev` extra. Pin compatible major ranges.

## Frontend and PWA changes

- Target accessible React/TypeScript: semantic controls, keyboard operation, visible focus, useful labels, responsive layouts, and `prefers-reduced-motion` support.
- Do not fabricate operational data after authentication. An explicit demo mode may use fixtures; live and cached modes display only data verified from the API/session partition.
- Reads may fail over to trusted HTTPS peers. Mutations remain on the authenticated origin unless a separately authenticated mutation-failover design is implemented.
- Preserve runtime `APP_NAME` propagation through page metadata, manifest, visible brand, and default notification title.
- Treat the service worker as a security boundary. Version cache changes, preserve offline shell behavior, and test notification click routing and cache isolation.
- Run:

  ```bash
  npm --prefix frontend run format:check
  npm --prefix frontend run lint
  npm --prefix frontend run typecheck
  npm --prefix frontend test
  npm --prefix frontend run test:e2e
  ```

## Operations and deployment changes

- Inventory existing Docker/systemd/proxy/private-network state read-only before proposing host changes. Never replace or restart monitoring services without explicit authorization.
- Examples use placeholders and loopback/private addresses only. Do not add real hostnames, tokens, certificates, or fixed RU/NL/DE assumptions to application logic.
- Publish exactly two release images, `alert-hub-api` and `alert-hub-web`. They share a release version but have separate immutable digests and must be deployable independently; do not add a bundled image.
- Keep the API build independent from npm and from the existence or buildability of `frontend/`. Keep Node.js, npm, Vite, Python, and backend code out of the web runtime image.
- A failed API must not crash the web container: public web requests fail closed with `503` and recover when the API returns. Updating either service must not recreate the other.
- Deployment scripts are root-owned trust boundaries. Validate every user-controlled value, avoid shell interpolation, acquire locks, back up before migration, resolve immutable image digests, and fail closed.
- A changed proxy snippet must be backed up and validated with `nginx -t` or `caddy validate`; restore it on validation failure.
- A changed backup/restore path needs a real SQLite integrity/restore test. Cluster replication is not a backup.
- Parse every shell script with `bash -n`/`sh -n`, run ShellCheck, and validate every Compose combination used by CI.

## Tests and definition of done

- A bug fix includes a regression that fails without the fix.
- Distributed changes cover duplicate, out-of-order, pagination, retry, unavailable-peer, and restart behavior. Where feasible, use separate databases/app instances rather than mocking the state boundary away.
- Delivery adapters use deterministic fakes/mocks for success, retryable failure, permanent failure, `404/410`, timeout, escaping, SSRF, and redaction.
- Do not weaken coverage thresholds, lint rules, security checks, or assertions to make CI pass. Fix the behavior or document a narrowly justified exclusion.
- Update architecture, security, operations/runbook, OpenAPI contract, examples, and implementation status in the same change as the code they describe.
- Do not claim the distributed MVP is accepted until three-node partition/recovery, failed deploy rollback, backup restore, and real iPhone Home Screen Web Push have evidence. Automated substitutes should be labelled as such.

## Git and CI

- Work in small reviewable commits; never commit generated databases, runtime secrets, `.env`, caches, build output, or provider artifacts.
- Pull requests target `main`. Required PR jobs must be read-only with least-privilege permissions and must not publish images or deploy.
- Third-party GitHub Actions are pinned to full commit SHAs. Production images use an immutable tag/digest; never deploy `latest`.
- `main` may publish only an immutable candidate. Releases originate from validated `vX.Y.Z` tags; deployment remains an explicit protected workflow.
- Do not force-push, rewrite shared history, dismiss checks, loosen branch protection, or push/deploy unless the user explicitly authorizes that external mutation.

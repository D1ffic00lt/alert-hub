# Acceptance evidence

This document separates repeatable repository evidence from checks that require the
operator's real hosts, monitoring topology, GitHub environments, provider accounts, or an
iPhone. An automated substitute is useful regression evidence, but it is not recorded as a
production acceptance result.

For the current implementation, the latest local backend run completed **254 tests**
with **83.10% branch coverage** against a **75% CI floor**; Ruff, strict mypy, migrations, and the
OpenAPI contract also passed locally. Frontend lint/types, 23 unit tests, the production build,
eleven Playwright paths, the two-image Docker matrix, and the controlled three-node gate also passed.
That is supporting development evidence, not a green GitHub check tied to a reviewed commit.

## Evidence levels

- **Automated** — encoded in tests and configured to run on pull requests targeting `main`; a
  successful check for the exact commit is the durable result.
- **Controlled integration** — runs real application containers and databases in an isolated
  Docker network, but does not represent the production RU/NL/DE network.
- **External acceptance required** — must be exercised against the installation and have a
  dated evidence link before the distributed MVP is declared accepted.

## Repository and controlled-integration evidence

| Area                                | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Level                  |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Backend behavior                    | Ruff, strict mypy, a 254-test pytest suite with 83.10% measured branch coverage and a 75% gate, clean/previous-schema migration exercise, and generated OpenAPI contract comparison                                                                                                                                                                                                                                                                                                                              | Automated              |
| Ingest and incident projection      | API integration tests cover Alertmanager, generic JSON, deduplication, out-of-order events, state actions, and restart-safe persistence. A separate three-database regression covers replicated heartbeat observations, false-miss prevention, and both recovery-before-firing and firing-before-recovery ordering.                                                                                                                                                                                              | Automated              |
| Authentication and trust boundaries | Bootstrap/login/session rotation, exact Origin and CSRF enforcement, trusted-proxy parsing, source/peer CIDRs, bounded rate limits, secret redaction, and production startup invariants                                                                                                                                                                                                                                                                                                                          | Automated              |
| Notification delivery               | Durable outbox, routing, retry/permanent failure, Web Push `404/410`, Telegram escaping, generic-webhook SSRF controls, and delivery receipts use deterministic adapters and HTTP mocks. A separate multi-database regression proves logical event-key ownership/ID selection, sender receipt mapping to a different local event row, and suppression after replicated success. SMTP tests cover allowlisted templates, malformed/unknown placeholders, header injection, defaults, and deterministic rendering. | Automated              |
| Peer convergence                    | Separate application/database instances cover duplicate and out-of-order history, pagination, partition accumulation, restart, and convergence                                                                                                                                                                                                                                                                                                                                                                   | Automated              |
| Three-node runtime                  | The CI scenario runs three non-root, read-only containers with separate SQLite volumes for partition/recovery, duplicate ingress, reverse-order resolution, node loss/restart, cursor convergence, re-fire, and connected-cluster single-owner delivery. It passed locally for this working tree; the reviewed commit still needs its GitHub container job.                                                                                                                                                      | Controlled integration |
| Frontend and PWA                    | Formatting, ESLint, TypeScript, 23 component/service-worker tests, production build, and eleven Playwright primary paths passed locally for this working tree. No automated browser result substitutes for real iPhone Home Screen behavior.                                                                                                                                                                                                                                                                     | Automated              |
| Supply chain                        | Secret scan, dependency integrity/audits, pinned GitHub Actions, least-privilege CI policy, release-only image publication, SBOM, provenance, and attestation workflow checks                                                                                                                                                                                                                                                                                                                                    | Automated              |
| Public proxy boundary               | Static policy tests assert that the public Nginx/Caddy examples deny `/internal/*` and operator paths, while dedicated peer templates render repeated exact source `/32` values and expose only health `GET` plus event-query `POST`; real proxy validation and exposure scans remain external                                                                                                                                                                                                                   | Automated              |
| Container boundary                  | The locally passing image matrix checks independent non-root/read-only API and web runtimes, absence of Node/frontend material from API, absence of Node/Python/backend/secrets from web, split startup, `503` gating and recovery, component-only recreation, API-only operation, and lack of an API host port in split mode. The reviewed commit still needs its GitHub container job.                                                                                                                         | Controlled integration |
| Recovery tooling                    | Compose-model validation, a real SQLite online-backup/integrity/restore/ownership/failure-path exercise, deployment-script policy and shell analysis, and two-image component recreation/API-loss/recovery smoke. Node-local automatic deploy rollback and failed rollback still require a dated production-like drill.                                                                                                                                                                                          | Automated              |

The canonical commands and workflow composition are in the root `Makefile` and
`.github/workflows/ci.yml`. CI artifacts and a successful GitHub check run are the durable
evidence for a particular commit; a developer's local run is supporting evidence only.

## External acceptance register

| Requirement                        | Required evidence                                                                                                                                                                                                                                                                                                      | Status                                                 |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Real iPhone Home Screen Web Push   | iPhone/iOS and Safari version, installation, user-gesture permission, firing and resolved delivery while closed, notification click deep-link, and reserve-node delivery                                                                                                                                               | Pending external acceptance                            |
| Production network exposure        | External scan showing only intended `443` (and restricted `22` where required), no public application ports, loopback-only smoke mappings and fixed managed-edge proxy upstreams, direct peer DNS/TLS, allowed-node reachability for exactly two peer operations, and source/method/path denial from unrelated clients | Pending external acceptance                            |
| Real regional convergence          | Dated RU/NL/DE partition, one/two-node loss, reconnection, cursor/state comparison, and notification-duplicate observations                                                                                                                                                                                            | Pending external acceptance                            |
| Prometheus and Grafana integration | Datasource connection evidence, real `source_region`/`target_name` labels, auth/network route, partial-failure behavior, and installation-specific Grafana links                                                                                                                                                       | Pending external acceptance                            |
| Existing Nginx/Caddy integration   | Inventory, backed-up snippet, native validator output, SSE behavior, cache headers, and restoration after a deliberately invalid candidate                                                                                                                                                                             | Pending external acceptance                            |
| Release publication                | Successful protected `vX.Y.Z` workflow, GHCR digest, SBOM, provenance/attestation verification, and GitHub Release link                                                                                                                                                                                                | `v0.1.0` published; current change pending release     |
| GitHub UI deployment               | Configured protected environments and repository-scoped runners; ordered RU → NL → DE rollout with per-node manifest and health evidence                                                                                                                                                                               | Environments/runners configured; first rollout pending |
| Failed deploy and rollback         | Deliberately fail migration/readiness/static on a prepared node, prove automatic rollback of only the selected component and stopped rollout, record failed deployment status, then exercise manual `previous` rollback. Container failure gating is regression evidence, not this host-level result.                  | Pending infrastructure setup                           |
| Backup operations                  | Scheduled host backup, off-node copy, checksum/integrity result, retention result, and timed restore drill with matching encryption keys                                                                                                                                                                               | Pending external acceptance                            |

## Known residual risks

- Web Push pins its TLS connection to the immediately validated public address set. Generic
  webhooks and monitoring requests validate immediately before bounded I/O but do not yet pin the
  operating-system connect call; an egress firewall remains required to close that residual
  DNS-rebinding time-of-check/time-of-use gap for those adapters.
- Compact replication snapshots/retention, master-key bulk re-encryption, and an authenticated
  operator workflow for bootstrap-conflict resolution need dedicated designs and tests.
- Per-node rate limits intentionally preserve no-quorum availability; they are not a
  distributed account lockout or cluster-global ingest quota.
- Browser CSP already restricts scripts to `'self'`; installation-level reporting and a
  nonce/hash or equivalent design are still needed before the narrowly scoped inline-style
  allowance can be removed.

## Licensing state

The repository is distributed under the committed [MIT License](../LICENSE).

Do not change an external row to accepted without a date, release/commit identity, operator,
environment, exact procedure, and an evidence link or attached artifact.

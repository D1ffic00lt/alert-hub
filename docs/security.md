# Security and threat model

## Trust boundaries

Alert Hub crosses five materially different boundaries:

1. an untrusted browser and public webhook senders reach the existing HTTPS reverse proxy;
2. the proxy reaches a fixed private application address on the managed edge bridge;
3. peer nodes reach a dedicated HTTPS hostname with exact source and internal API policy;
4. the backend makes constrained outbound connections to providers and Prometheus;
5. a repository-scoped GitHub runner asks a root-owned local wrapper to deploy an immutable image.

SQLite, secret files, Docker socket, proxy configuration, backup directory, and deployment wrapper are host-privileged assets. A container or runner compromise must not automatically grant control of them.

## Threat model

| Threat                                 | Asset/impact                            | Current control                                                                                                                                                                                                                                                                                                        | Residual/follow-on work                                                                                                                                                         |
| -------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stolen source token                    | False incidents or ingest flood         | Random bearer token displayed once, only keyed hash stored, body limit, disabled/deleted source checks, optional per-source CIDRs, and bounded per-node ingest limiting                                                                                                                                                | Limits are not cluster-global. Keep firewall/proxy controls and sender backoff; rotate a compromised source token.                                                              |
| Credential stuffing/bootstrap attack   | Admin account/session                   | Bootstrap token file, Argon2id with a valid dummy-hash path for unknown users, rotating hashed refresh sessions, exact Origin/CSRF checks, replicated split-brain detection, and bounded per-node login/bootstrap limits                                                                                               | Add an authenticated operator conflict-resolution workflow and a deliberate distributed lockout policy if operationally required.                                               |
| Cookie/token theft                     | Account takeover                        | Short access lifetime, refresh rotation/revoke, exact trusted origins, secure cookie settings                                                                                                                                                                                                                          | Review shared cookie domain carefully; add WebAuthn/passkeys later.                                                                                                             |
| Malicious webhook payload              | Memory/CPU/DB exhaustion, log injection | 1 MiB default limit, per-node pre-parse rate limiting, Pydantic/adapter validation, normalized enums/timestamps, unknown data kept as structured JSON                                                                                                                                                                  | Add row-retention controls and fuzz/property tests; never log authorization headers or raw secrets.                                                                             |
| Public peer/operator endpoint          | Cluster forgery or diagnostics exposure | The UI proxy denies `/internal/*`, metrics, deep health, and API docs; a distinct TLS peer vhost exposes only health/query with exact source `/32`, overwritten forwarding headers, cluster bearer, strict transport limits/backoff, and failed-auth audit                                                             | Validate real DNS/TLS/source preservation and exposure on every host; retain host firewall controls and automate secret-rotation drills.                                        |
| Compromised peer                       | Validly signed bad cluster events       | Append-only identity/cursors and deterministic validation boundary                                                                                                                                                                                                                                                     | There is no Byzantine consensus. Incident response must revoke the peer/key and rebuild projections from trusted evidence.                                                      |
| SSRF through datasource/channel URL    | Cloud metadata/internal service access  | Prometheus defaults to HTTPS/public addresses, rejects embedded credentials and redirects, re-resolves immediately before bounded requests, ignores environment proxies, and requires explicit HTTP/private settings; generic webhooks validate destinations                                                           | DNS can change between validation and OS connect; retain egress firewall controls and allow only the intended monitoring network. Provider delivery needs equivalent exercises. |
| Secret disclosure in image/Git/log     | Provider or cluster compromise          | Secret-file mounts, `.dockerignore`, pattern CI check, no token CLI argument in ingest smoke, no secret artifacts                                                                                                                                                                                                      | Add an organization secret scanner and validate application redaction with integration tests.                                                                                   |
| SQLite theft                           | Incident/user/config disclosure         | Host permissions; channel/push material uses AES-256-GCM envelope storage; password/source/refresh tokens are hashes                                                                                                                                                                                                   | Full DB encryption is not provided. Labels, annotations, audit data, and incident history may themselves be sensitive.                                                          |
| SQLite corruption/ransomware           | Lost history/availability               | WAL invariants, online verified backups, checksum, retention, isolated restore procedure                                                                                                                                                                                                                               | Replicate backups off-node and perform scheduled restore drills; replication is not backup.                                                                                     |
| Malicious PR on self-hosted runner     | Root/container takeover                 | PR CI uses GitHub-hosted runners; production node jobs do not check out code; sudo permits only a root-owned validating wrapper                                                                                                                                                                                        | Protect workflow changes with CODEOWNERS/branch rules; keep runner repository-scoped and ephemeral where practical.                                                             |
| Mutable image/action tag               | Supply-chain substitution               | Production tag resolved to digest; all Actions pinned to full commits; tag releases include SBOM/provenance/attestation; no `latest`                                                                                                                                                                                   | Verify attestations and admission policy before rollout; review dependency lock updates.                                                                                        |
| Proxy-header spoofing                  | IP allowlist/audit bypass               | One resolver ignores forwarding headers from untrusted immediate peers and walks an explicitly trusted chain right-to-left; production trusts only loopback and the root-controlled managed edge subnet containing the application and operator proxy; dedicated proxies overwrite or append observed source addresses | Keep the edge subnet isolated from unreviewed containers; never put ordinary peer/sender networks in the proxy-trust list.                                                      |
| XSS/service-worker compromise          | Long-lived client control               | CSP/frame/content-type/referrer/permissions headers, `script-src 'self'`, and no-store service-worker updates                                                                                                                                                                                                          | Add installation-level CSP reporting and replace the narrowly scoped inline-style allowance with a nonce/hash or equivalent design when the runtime UI permits it.              |
| Duplicate notification under partition | User fatigue/action confusion           | Deterministic rendezvous ownership and delivery IDs use the logical incident event key; durable claims, failover delay, and replicated receipts map success onto each node's corresponding local event row                                                                                                             | A true partition can still produce a duplicate by design. Validate owner loss with the real providers/topology; this is not exactly-once behavior.                              |

## Secrets

Production secrets are files mounted read-only at `/run/secrets`; they are not image build arguments or release variables. Supported file settings include signing, cluster, master-encryption, and VAPID material. Channel and push secrets are encrypted at rest with AES-256-GCM envelope storage. SMTP subject/body templates use an allowlisted placeholder renderer rather than `eval`, Jinja, format-string attribute access, or other executable templating; literal subject control characters are rejected and substituted subject values are flattened before RFC 5322 header construction. Web Push, Telegram, SMTP, and generic webhook senders are implemented, while real provider-account delivery remains an external acceptance gate.

Recommended host permissions:

```text
/opt/alert-hub/secrets           root:10001 0750
individual secret file           10001:10001 0600
/opt/alert-hub/config/*.env      root:root  0600
/etc/alert-hub/*.env             root:root  0600
/usr/local/sbin/docker-*-node.sh root:root  0755
```

Do not pass secrets as deployment wrapper flags, environment outputs, image labels, GitHub artifacts, or `curl -H` arguments visible in the process list. Both controlled CI and production ingest smoke read generated tokens from mode-`0600` curl config files. Production derives a dedicated token, provisions a persistent per-node system heartbeat source, passes the token to the helper over stdin, deletes temporary response/config files on exit, and never prints the value.

Application logging uses a fixed structured-field allowlist, excludes request headers/cookies/bodies and peer/provider URLs, and applies bounded bearer/labelled-secret redaction to messages and exception traces. Request events include only the path, never its query. Regression tests deliberately inject credentials into excluded fields and failure text. This is defense in depth: new code must still pass identifiers or error codes rather than raw provider responses, URLs, payloads, or exception values that may contain credentials.

`APP_NAME` is normalized once by settings: surrounding/repeated whitespace and control characters collapse safely, empty values fail, and the final display name is capped at 80 characters before it reaches provider subjects or visible runtime metadata.

## Network policy

- Public inbound: steady-state HTTPS `443` only; SSH `22` only if already
  required and restricted. Prefer DNS-01 certificate issuance; an HTTP-01 flow
  needs an explicitly timed and monitored `80` exception that is removed after
  issuance or renewal.
- Host application: loopback-published web/API ports are for local smoke and
  operator access only. Host proxies use the fixed private web/API addresses on
  the managed edge bridge; neither application port may bind a public interface.
- Peer: a dedicated operator-managed HTTPS hostname on `443`, DNS-resolved
  directly to the node, proxy-allowlisted to the other nodes' exact public IPv4
  `/32` values, and restricted to the health/query method-path pairs. The
  cluster bearer and application CIDR policy remain mandatory second layers.
  Literal RFC1918/ULA HTTP remains valid only as an optional WireGuard/private-
  network mode; it must never traverse the public Internet.
- SQLite: filesystem only, no network listener.
- Prometheus/Alertmanager/Blackbox: existing private/local exposure unchanged.
- Runner: outbound HTTPS to GitHub; no inbound deployment port.
- Provider egress: deny by default until an adapter is configured. Restrict Prometheus egress to the explicit monitoring network even when private URL support is enabled.

The supplied public Nginx/Caddy examples return `404` for `/internal/*`, `/metrics`,
`/health/deep`, `/api/docs*`, `/api/redoc*`, and `/api/openapi.json`. Keep these operator surfaces
on loopback/private paths and verify the real virtual host from an external network; the static
example check is not an exposure scan.

Peer-sync clients ignore `HTTP_PROXY`/`HTTPS_PROXY`, require exact HTTPS origins
unless an operator deliberately selects literal RFC1918/ULA HTTP for a private
network, do not follow redirects, apply finite connect/read/write/pool timeouts, cap
decoded response bodies with `SYNC_MAX_RESPONSE_BYTES`, cap events/pages, and
back off independently per peer. This keeps the cluster bearer out of ambient
proxies and prevents an oversized peer response from consuming unbounded worker
memory or advancing a cursor.

Verify externally that only the intended `443` virtual hosts are reachable and
that application, metrics, and monitoring ports remain closed. From each peer,
verify the certificate and only the two permitted method/path pairs. From an
unrelated address, verify the peer hostname fails closed.

## Authentication and browser policy

Use exact HTTPS origins. Wildcard CORS with credentials is rejected. Refresh and logout require one exact allowed `Origin` plus the matching double-submit CSRF value; a missing Origin is not accepted. Authenticated responses expose `X-Alert-Hub-Cache-Partition`, and CORS permits/exposes that header so the service worker can keep session cache namespaces separate. Permission for browser notifications must be requested only from a direct user gesture in an installed Home Screen PWA; do not attempt silent push.

Web Push subscriptions are bound by the API to the authenticated session ID; the client-supplied device label is not an authorization or identity key. Revoking a device session, logging out, reaching absolute session expiry, or disabling the owning user prevents delivery and emits a replicated, remove-wins subscription tombstone before the next provider request. A locally observed sliding expiry suppresses delivery without a permanent tombstone because another replica may later supply a valid rotation. Pre-migration subscriptions without a session ID are disabled during migration and are also rejected fail-closed at runtime; the browser must register them again after upgrade.

Immediately before Web Push delivery, the API resolves the endpoint, rejects every non-global
answer, and pins the actual TLS connection to that validated address set while retaining the
original hostname for SNI, certificate verification, and the HTTP `Host` value. The pinned client
does not use environment proxies and refuses redirects, so provider I/O cannot trigger a second
attacker-controlled resolution or escape to another origin.

Shared parent-domain cookies reduce friction but expand the compromise boundary to every trusted sibling subdomain. Prefer per-node sessions unless all subdomains share administration and hardening. Session signing keys may be common across nodes only with replicated revocation/session state.

## Client addresses, CIDRs, and rate limits

`TRUSTED_PROXY_CIDRS` identifies only infrastructure allowed to speak for an earlier network hop. The immediate socket peer must match before `Forwarded`, `X-Forwarded-For`, or `X-Real-IP` is read. The resolver walks the resulting chain from the application outward and stops at the first untrusted address. Malformed or ambiguous forwarding values fall back to the immediate peer.

The web container's Nginx uses `$proxy_add_x_forwarded_for`; it does not pass an
inbound value through unchanged. The dedicated peer templates are stricter:
they overwrite `X-Forwarded-For` and `X-Real-IP` with the directly observed TCP
source and remove `Forwarded`/`X-Forwarded-Host`. The API trusts the managed edge
proxy hop before resolving that source. A containerized Caddy adds the managed
edge network to any proxy-owned networks it already requires and must not join
Alert Hub egress or monitoring; it proxies directly to `alert-hub:8080`. A host proxy uses
the fixed `API_IP:8080` on that bridge. The public host proxy likewise uses the
fixed `WEB_IP:8080`; loopback publishes are local smoke endpoints, not proxy
upstreams. Do not put ordinary peer or sender networks in
`TRUSTED_PROXY_CIDRS`: a trusted member could then author an earlier address.
Source and peer allowlists, rate-limit keys, and audit entries use this same
resolved address.

`PEER_ALLOWED_CIDRS` is checked on every `/internal/*` request before cluster
bearer validation. Production with sync enabled refuses an empty list; configure
only the other nodes' exact public IPv4 `/32` values. Keep the ordinary public
vhost denial, dedicated peer-vhost path/method/source policy, and host firewall
as independent controls. Cluster auth/CIDR/rate failures are audited with the
resolved address and request ID, never the bearer value.

Login, bootstrap, ingest, and internal peer traffic use bounded fixed-window limiters. Ingest has an IP-global node budget, so rotating arbitrary source IDs cannot create a fresh allowance. Limits/windows, memory capacity, and cleanup cadence are settings. At capacity, unseen keys share a throttled overflow bucket rather than growing memory without bound. A rejection is `429` with `Retry-After`. State is in one process and one node only: this protects local expensive work but is not a distributed lockout or cluster-global quota.

## Production startup invariants

Production startup fails closed unless cookies are secure; `PUBLIC_API_URL` is an exact non-loopback HTTPS origin included in the exact non-loopback HTTPS `TRUSTED_ORIGINS`; signing, active cluster, and any previous cluster secrets are pairwise distinct, non-default, and high entropy; a master encryption key file is configured; a cookie domain is syntactically safe and contains every trusted origin host; peer/origin URLs are valid; an optional `GRAFANA_URL` uses HTTPS without embedded credentials; and sync has a non-empty peer CIDR policy. Local HTTP health checks behind the proxy remain possible because these checks validate declared public trust configuration rather than weakening runtime cookie/origin policy.

Authenticated administrators may replace the runtime Grafana fallback with a replicated cluster
link. This path also requires HTTPS without embedded credentials. Configurable Prometheus job
selection accepts bounded glob values only; the backend escapes them into its named `up` queries,
so the browser cannot submit arbitrary PromQL or turn Alert Hub into a query proxy.

## Deployment trust

Protect `.github/workflows`, `.github/deploy`, `deploy/scripts`, both component Dockerfiles,
migrations, dependency locks, and proxy examples with mandatory review. A release tag must be
protected and created from reviewed `main`. Verify both images before production:

```bash
gh attestation verify oci://ghcr.io/OWNER/alert-hub-api:vX.Y.Z --repo OWNER/alert-hub
gh attestation verify oci://ghcr.io/OWNER/alert-hub-web:vX.Y.Z --repo OWNER/alert-hub
docker buildx imagetools inspect ghcr.io/OWNER/alert-hub-api:vX.Y.Z
docker buildx imagetools inspect ghcr.io/OWNER/alert-hub-web:vX.Y.Z
```

Compare both reported digests and compatibility labels with the node state after deployment.
Provenance is stored by GitHub's attestation service and is not pushed to GHCR as a synthetic
`sha256-*` package version. `latest` and commit-SHA candidates are neither published by the
workflows nor accepted as deployment versions.

The dedicated runner account must not be in the Docker group. Root-owned node scripts validate the
operation/version/component, hold a lock, validate paths and config, and invoke fixed commands.
They never execute a script or Compose file from the Actions checkout.

`docker-provision-node.sh` is an operator-only bootstrap boundary. It copies the
reviewed Compose and node scripts from a fully root-controlled source tree,
rejects Docker-group membership, generates a command-exact sudoers policy, and
validates it with `visudo`. Sudo preserves only an explicit deployment-variable
allowlist under `env_reset` and a system-only `secure_path`; broad `SETENV`,
mutable-checkout provisioning, user-writable command paths, and
environment-selected interpreters are not trusted. The runner cannot sudo the
provisioner, and runner registration tokens are never an input to it.
Provisioning and runtime operations share one root-owned lock. Boundary files
are staged and rollback-restored as a set, and an established node policy may be
refreshed only byte-for-byte; topology mutation is not hidden inside a script
upgrade. Status accepts a missing state only on a genuinely empty node and
rejects unexpected container networks, including stale monitoring access.

Deployment state stores only the active runtime config's lowercase SHA-256, never an arbitrary
snapshot path. The root engine derives a fixed content-addressed filename beneath the private
history directory, rejects malformed checksums, symlinks, wrong ownership or mode, and checksum
mismatches before copying a snapshot atomically into place. API and `all` rollback activate the
verified historical config before starting its image; if the target fails, the engine restores the
starting config before the starting image. This ordering prevents an older binary from being
started with an untrusted or incompatible candidate configuration. Runtime config snapshots are
private deployment evidence and must not be uploaded as Actions artifacts or attached to issues.

Pull-request CI statically checks workflow trust and parses/lints the node scripts. The image-matrix
smoke exercises component isolation, failed API startup, guarded `503`, and recovery. It is not
evidence that automatic rollback, host permissions, storage, firewall, or a self-hosted runner is
safely configured on a real node.

## Security incident response

1. Preserve logs, audit rows, release manifests, image digest, and current cursor state without copying bearer values.
2. Remove the affected node/source/channel from eligibility at the narrowest boundary.
3. Rotate the specific source, cluster, signing, or provider credential; avoid a broad cluster-key change before healthy nodes have compatibility configuration.
4. If host integrity is uncertain, rebuild it rather than trusting a binary rollback on the same host.
5. Verify SQLite and a pre-incident backup; decide explicitly whether peer replay is trustworthy.
6. Review unexpected duplicate/suppressed alerts across the partition window.
7. Document the event and add a regression test or control.

## Security gates still required for the full MVP

Before declaring the full distributed MVP accepted, complete the master-key rotation/re-encryption
procedure, CSP reporting and inline-style nonce/hash hardening, operator bootstrap-conflict
resolution, compact snapshot/bootstrap retention, a deliberate distributed lockout policy if
required, real provider exercises, and real multi-region partition/deployment/rollback drills.
Outbound tests cover redirects, rebinding-style revalidation, escaping, timeouts, redaction, and
Web Push `410`; an egress firewall is still required because validation does not pin the resolved
address through the operating-system connect call.

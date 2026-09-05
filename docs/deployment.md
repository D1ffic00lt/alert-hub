# Production deployment

This guide installs one Alert Hub node without replacing its existing
Prometheus, Alertmanager, Blackbox, Nginx, Caddy, or firewall configuration.
Repeat it for every node and keep every SQLite database local to that node.
Enabling Checks adds fixed read-only Prometheus queries; it does not install,
configure, or require Blackbox or any other prober/executor service.

## Deployment artifacts

Normal users deploy from the repository root:

```text
docker-compose.yml
docker-compose.split.yml
docker-compose.api-only.yml
.env.example
docker-install.sh
Caddyfile.example
nginx.conf.example
deploy/proxy/caddy/Caddyfile.peer.example
deploy/proxy/nginx/alert-hub-peer.conf.example
deploy/scripts/install-proxy-config.sh
backend/Dockerfile
frontend/Dockerfile
```

Production-only automation is isolated under `.github`:

```text
.github/
├── workflows/
│   ├── ci.yml
│   ├── release.yml
│   ├── deploy.yml
│   └── rollback.yml
└── deploy/
    ├── docker-compose.production.yml
    ├── docker-compose.production-monitoring.yml
    └── scripts/
        ├── docker-provision-node.sh
        ├── docker-deploy-node.sh
        ├── docker-rollback-node.sh
        └── docker-status-node.sh
```

Do not add an `inventory.yml`, host address, domain, credential, or generated
runtime file to Git. A fork can see the automation but cannot use the protected
Environments, repository secrets, or installation-specific runners.

Every version release publishes exactly two images:

```text
ghcr.io/<owner>/alert-hub-api:vX.Y.Z
ghcr.io/<owner>/alert-hub-web:vX.Y.Z
```

The GitHub Release includes a manifest with both digest-qualified references,
their shared version, revision, and OpenAPI-derived compatibility value. The
node scripts accept only `ghcr.io/...@sha256:...` references from that manifest.
They never deploy `latest`.

## Read-only host inventory

Before installing files, record the host's actual state. These commands are
examples; do not stop or recreate services during inventory:

```bash
docker version
docker compose version
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
docker network ls
systemctl list-units --type=service --state=running
ss -lntup
ip -brief address
nginx -T 2>/dev/null
caddy adapt --config /etc/caddy/Caddyfile --pretty 2>/dev/null
```

Record separate free loopback ports for local web/API smoke checks, the fixed
`WEB_IP` and `API_IP` on the managed edge bridge, the public UI and peer
hostnames, exact public `/32` source addresses of the other nodes, proxy
ownership/network mode, firewall rules, filesystem capacity, backup destination,
and outbound HTTPS access to GHCR and GitHub. Confirm that peer DNS resolves
directly to the node rather than through a CDN or L7 proxy. If the API must reach
an existing Prometheus network directly, also record that Docker network; this
attachment is optional. Never place SQLite on NFS, a shared Docker volume, or
another node's filesystem.

## Prepare a node

Export the exact reviewed release commit into a root-owned staging directory
whose complete path is not group/other writable. Do not provision directly from
the runner's mutable checkout. Replace the uppercase inventory placeholders
with values confirmed above; omit `--monitoring-network` when no direct
attachment is required:

```bash
sudo /root/alert-hub-reviewed/.github/deploy/scripts/docker-provision-node.sh \
  --source-dir /root/alert-hub-reviewed \
  --runner-user RUNNER_USER \
  --repository OWNER/alert-hub \
  --node-name NODE_NAME \
  --host-port FREE_LOOPBACK_WEB_PORT \
  --api-host-port FREE_LOOPBACK_API_PORT \
  --edge-subnet DEDICATED_RFC1918_CIDR \
  --api-ip API_ADDRESS_IN_EDGE_SUBNET \
  --web-ip WEB_ADDRESS_IN_EDGE_SUBNET \
  --monitoring-network EXISTING_DOCKER_NETWORK
```

The helper rejects a root runner or any runner account in the Docker group. It
also rejects a source path, source directory, or source file that is not
root-owned and protected from group/other writes, closing the checkout race at
the bootstrap boundary. It parses every script, validates both Compose
combinations, validates the generated sudoers file with `visudo`, and installs
only fixed root-owned entry points. It also preflights the backup tool's host
commands and Python 3.9+ SQLite backup support before changing the boundary. Its
sudoers rule uses `env_reset`, a fixed `secure_path`, and an explicit
deployment-variable allowlist; it does not grant `SETENV`. The dedicated runner
may invoke deploy/rollback with that validated environment and status without
arguments, but may not invoke the provisioner.
GitHub runner registration remains a separate operator step: the helper has no
option for and never reads a registration token.

Before replacing any trust-boundary file, the helper creates and exclusively
locks `/opt/alert-hub/.deploy.lock`, stages every destination on its own
filesystem, and records the previous root-owned files. Activation uses atomic
renames while deploy, rollback, and status are excluded by the same lock. A late
copy, content, mode, or `visudo` failure restores the complete previous set;
failure to restore is reported as critical and preserves root-only recovery
material instead of deleting it.

The same locked boundary installs `/usr/local/sbin/alert-hub-backup` and a
mode-`0600` `/etc/alert-hub/backup.env`. A new config takes `NODE_NAME` from the
validated immutable policy and uses the production API container, database
ownership, paths, and 7-daily/4-weekly/6-monthly retention defaults. On
re-provisioning, an existing root-owned mode-`0600` config is validated against
a strict data-only key/value grammar and the policy node name, then preserved
byte-for-byte. The default backup directory is created as `root:root` mode
`0700`; a customized directory must already exist with that ownership and mode.
A symlink, unsafe mode/owner, command-like value, unsupported or duplicate key,
unsafe path, or different node name aborts before activation; the helper never
silently replaces an operator-customized config with defaults. If later
activation fails, a newly created empty default backup directory is removed
along with the staged boundary.

The generated policy has six required keys: `GITHUB_REPOSITORY`, `NODE_NAME`,
`HOST_PORT`, `EDGE_SUBNET`, `API_IP`, and `WEB_IP`. `API_HOST_PORT` and
`MONITORING_NETWORK` are optional keys written only when requested; the API port
defaults to `18081`. The API and web ports must differ. The policy is a root-owned
regular file with mode `0600`; it contains node-local topology but no public
domain, token, or cryptographic secret, and it is never committed. The engine
validates CIDR membership, address separation, network ownership, and
repository/node identity before touching a container. The runner must not be
able to edit any installed copy. Once created, the complete policy is immutable:
ordinary re-provisioning accepts only a byte-identical policy and refreshes the
reviewed scripts/Compose files. A node-name, port, subnet, address, or monitoring
network change requires a separately reviewed topology migration while the
application is stopped; the bootstrap helper intentionally has no bypass flag.

The provisioner and deploy engine create these paths with restrictive ownership
and modes:

```text
/opt/alert-hub/config/alert-hub.env    root:root 0600
/opt/alert-hub/data/                   10001:10001
/opt/alert-hub/secrets/*               10001:10001 0600
/opt/alert-hub/state/current.env        root:root 0600
/opt/alert-hub/history/*.env            root:root 0600
/opt/alert-hub/history/configs/         root:root 0700
/opt/alert-hub/history/configs/*.env    root:root 0600
/opt/alert-hub/.deploy.lock             root:root 0600
/etc/alert-hub/deploy-policy.env         root:root 0600
/etc/alert-hub/backup.env                root:root 0600
/etc/alert-hub/docker-compose*.yml       root:root 0644
/etc/sudoers.d/alert-hub-deploy          root:root 0440
/usr/local/sbin/alert-hub-backup          root:root 0755
/usr/local/sbin/docker-*-node.sh         root:root 0755
```

The runtime config and secret files are never printed. Shell tracing is not
enabled. The runner account should be repository-scoped, should not join the
`docker` group, and should receive sudo access only to these installed,
root-owned entry points with the narrowly required environment allowlist.

Successful state records include `CONFIG_SHA256`, the lowercase SHA-256 of the
active runtime application config. The value is an identifier, not a caller-
controlled path. The engine derives the corresponding content-addressed
snapshot as `history/configs/sha256-<sha256>.env`, requires a root-owned mode-
`0600` regular non-symlink, and re-hashes it before activation. Config snapshots
contain runtime settings and topology, so treat them as private host material
even though cryptographic keys remain in the separate secret files.

This HTTPS peer topology also records `PEER_TRANSPORT=https-peer-v1`. Records
created before that marker are parsed as `legacy`. Every operation against a
currently deployed legacy API is rejected before pulling images or changing
runtime state because even web readiness depends on the new loopback API
listener. API and `all` rollback targets must also use the new marker; a web-only
rollback may reuse an older web artifact after the current API has been migrated
and its compatibility label has been verified. An existing legacy installation
therefore needs a separately reviewed, one-time topology migration; do not
relabel or delete its history to bypass the guard. Fresh installations need no
migration.

The secret directory also contains a deployment-smoke token derived with its
own domain-separation label. The wrapper passes it to the API helper over stdin
and to `curl` through a temporary root-only mode-`0600` config; the token is
never a process argument or log field.

## Network boundary

The production Compose model runs independent API and web services:

- web publishes `127.0.0.1:<HOST_PORT>` and API publishes
  `127.0.0.1:<API_HOST_PORT>` for local smoke/operator access only;
- API and web communicate on the dedicated private subnet and addresses recorded
  in the root-owned node policy;
- a host Nginx/Caddy targets the fixed `WEB_IP:8080` for public traffic and
  `API_IP:8080` for the peer vhost, preserving a trusted edge-gateway hop;
- a containerized Caddy adds that edge bridge to the proxy-owned networks it
  already needs and uses the corresponding Docker service names; the edge
  bridge is its only Alert Hub application network;
- only API mounts SQLite, application config, and secrets;
- only API joins the managed outbound egress bridge;
- only API optionally joins the inventoried external monitoring network when
  `MONITORING_NETWORK` is present in the node policy;
- `/internal/*` is never routed by the public UI Nginx/Caddy examples;
- the peer virtual host routes only `GET /internal/v1/nodes/health` and
  `POST /internal/v1/sync/events/query`, after an exact source `/32` allowlist.

Neither application port is publicly bound. TLS and source filtering belong to
the operator-managed peer proxy on `443`; the cluster bearer and the
application's `PEER_ALLOWED_CIDRS` remain independent controls. The peer proxy
must overwrite client-supplied forwarding headers with the address it actually
observed. Keep the peer DNS record DNS-only so the exact source policy is not
masked by a CDN address.

An optional production monitoring network must be a user-defined, local,
non-internal IPv4 bridge. The helper rejects Docker's built-in `bridge`, `host`,
and `none` networks, non-bridge/swarm networks, explicit disabled masquerading,
and disabled inter-container communication. Docker does not provide a reliable
non-mutating endpoint-attachment probe, so provisioning validates network
properties only; the first component deployment and readiness check remain the
attachability evidence. Both the managed egress bridge and any accepted
monitoring bridge provide masqueraded outbound routing. This deliberately avoids
`gw_priority`, retaining compatibility with Docker Compose 2.15.1 even if Docker
chooses either bridge as the container's default gateway.

The web container performs a readiness authorization subrequest before serving
the PWA. If API readiness is lost, web stays running but returns `503` for
application and static requests. It recovers automatically when API is ready
again.

## GitHub Environments and secrets

Create these protected GitHub Environments:

```text
production-ru
production-nl
production-de
```

Each Environment contains non-secret variables:

```text
NODE_IP
PUBLIC_DOMAIN
PEER_PUBLIC_URL
```

Optional Environment or Repository Variables consumed by deployment are:

```text
APP_NAME
PEER_URLS
PEER_ALLOWED_CIDRS
VAPID_PUBLIC_KEY
CHECKS_ENABLED
CHECKS_STALE_AFTER_SECONDS
CHECKS_MIN_FAILURE_SOURCES
CHECKS_GRAFANA_BASE_URL
CHECKS_CACHE_TTL_SECONDS
CHECKS_FUTURE_TOLERANCE_SECONDS
CHECKS_MAX_SERIES
```

`APP_NAME` defaults to `Alert Hub`. `PEER_URLS` is a comma-separated list of the
other nodes' exact HTTPS peer origins; setting it also requires their exact
public IPv4 `/32` values in `PEER_ALLOWED_CIDRS`. `VAPID_PUBLIC_KEY` may be
omitted because the API derives it from the P-256 private key.

Checks defaults to disabled. When these optional variables are omitted, the
API deployment writes `false`, 180 seconds stale age, one failure source, no
Checks-specific Grafana link, a five-second cache TTL, 30 seconds of future
timestamp tolerance, and a combined 5,000-sample refresh/registry limit. The
accepted configuration ranges are 1–86,400 seconds for stale age, 1–1,000
failure sources, 0.1–5 seconds for cache TTL, 0–300 seconds for future
tolerance, and 1–100,000 series. `CHECKS_GRAFANA_BASE_URL` is non-secret
navigation metadata; use an absolute HTTPS URL without credentials. An invalid
or disallowed URL disables only the link.

The workflow passes Checks variables only to `api` and `all` deployment steps.
The root-owned engine validates them, writes them to the private runtime env,
and includes them in its content-addressed config checksum. Consequently, a
settings-only API deployment with the same image digest still recreates the API
and records rollback state. Web-only deployment and rollback receive no new
Checks values and continue to use the activated config snapshot. Refresh the
reviewed root-owned provisioner before relying on these variables so its
sudoers `env_keep` allowlist, the workflow policy allowlist, and the installed
deploy engine agree.

`PUBLIC_DOMAIN` is a DNS hostname without a scheme. `PEER_PUBLIC_URL` is this
node's dedicated peer origin, such as `https://peer-node.example.invalid`, with
no port, path, query, fragment, or credentials. `NODE_IP` is inventory metadata
and is not implicitly used as a bind address.

Store these shared values as Repository Secrets, or as identically configured
Environment Secrets:

```text
CLUSTER_MASTER_KEY
SESSION_SIGNING_KEY
VAPID_PRIVATE_KEY
```

Use three distinct high-entropy values. `VAPID_PRIVATE_KEY` is an unencrypted
P-256 PEM private key. On the first API deployment, the node engine derives
separate master-encryption, peer-bearer, and deployment-smoke material from
`CLUSTER_MASTER_KEY` with domain separation; it does not reuse the raw value. A
later image deploy refuses an implicit key rotation.

Before an `api` or `all` deployment creates or changes runtime directories and
files, the node engine passes `VAPID_PRIVATE_KEY` to the host OpenSSL process on
standard input. It rejects encrypted PEM, non-EC keys, malformed keys, and EC
curves other than P-256 without writing or logging the submitted material. When
`VAPID_PUBLIC_KEY` is set, it must be the canonical unpadded base64url encoding
of the 65-byte uncompressed P-256 point derived from that private key. A
`web`-only deployment and every rollback continue to use installed runtime
material and do not require workflow API secrets.

Static runner labels remain in the workflow:

```text
self-hosted, alert-hub-ru
self-hosted, alert-hub-nl
self-hosted, alert-hub-de
```

Configure required reviewers and deployment-branch rules for each Environment.
Branch protection should require the CI jobs and CODEOWNERS review for workflow,
Docker, production, and dependency-lock changes.

Peer origins and sender `/32` values are installation topology, not universal
defaults. Without a peer list, the node deliberately starts with synchronization
disabled rather than inventing a topology.

## Release and deploy behavior

Pull requests and pushes to `main` build and test API and web independently and together with
read-only permissions; they never publish or deploy. The two images are built in one gated,
ephemeral integration job so the exact pair can be exercised without uploading Docker archives as
Actions artifacts. A version tag runs only the complete release gate. The root `VERSION` file is the sole product
release version source. An operator may instead run the Release workflow on `main` without entering
a version; the workflow reads `VERSION`, validates the main revision, creates the immutable tag, and
publishes the release. An optional explicit `vX.Y.Z` input and any pushed version tag must match
`VERSION`. Backend and frontend package-manager versions do not gate the product release. Failure
of either image makes the release incomplete. Pushing an already-created version tag remains
supported.
Provenance is stored in GitHub's attestation service rather than pushed into GHCR as synthetic
`sha256-*` versions, so the registry receives only the explicit `vX.Y.Z` image tags.
If a manual run fails after creating its tag and `main` advances, resume it with
**Re-run jobs** on that original Actions run. A new manual run starts from the
new `main` commit and therefore refuses to reuse the older immutable tag.

`deploy.yml` and `rollback.yml` are manual `workflow_dispatch` workflows. They
have no `push` or `pull_request` trigger. A deploy selects:

- a published `vX.Y.Z` release;
- target node or ordered node set;
- component `api`, `web`, or `all`.

The workflow resolves the reviewed, checksummed release manifest to exact image digests before
entering a protected node job. A web-only deploy leaves the API container and
SQLite untouched. An API-only deploy backs up SQLite, runs forward migrations,
and leaves web running in guarded mode until readiness returns. An `all` deploy
updates the compatible pair. A component-only update is rejected when it would
leave mismatched compatibility labels.

For `api` and `all`, the engine renders and hashes the candidate runtime config
even when the selected image digest is already running. It treats the operation
as a no-op only when both the selected digest(s) and config checksum match;
changed peer URLs, allowlists, domains, or other runtime settings therefore
still create history/backup material and recreate the selected service. A
web-only same-digest run may verify readiness and return without touching the
API config.

For each selected node, the engine:

1. validates its root-owned script and Compose file, inputs, Docker, network,
   paths, permissions, local lock, and at least 1 GiB of free headroom on both
   the data and Docker filesystems (plus the current DB/WAL/SHM footprint on
   data);
2. pulls exact digest references and verifies component, version, compatibility,
   and schema labels;
3. creates or verifies the mode-`0600` runtime material without logging values;
4. records the prior state and content-addressed runtime-config snapshot, and
   makes an online SQLite backup before an API migration when a database
   exists;
5. force-recreates only the requested service or services;
6. gates container health, public readiness, PWA root, and runtime config;
7. reads the database through `/health/deep`, provisions or verifies the
   persistent per-node `[system] Deployment smoke` heartbeat source, and sends
   an authenticated heartbeat through the loopback-only API smoke listener;
8. records the successful component references, compatibility, and active
   runtime-config checksum.

If readiness fails after an API or `all` candidate changed runtime settings, the
engine first reactivates the config snapshot named by the previously recorded
checksum and only then starts the selected component's previous exact digest.
It does not downgrade SQLite. A failed config verification or automatic
restoration stops the rollout and requires operator intervention; the engine
never starts the prior API against a candidate config it did not own.

The GitHub rollback form requires the literal confirmation `ROLLBACK PRODUCTION`.
After that global confirmation, the workflow derives the node-scoped
`ROLLBACK <node>` value passed to each pre-provisioned wrapper. It selects
`previous` or an installed version from local history, changes only the requested
component, and for `api`/`all` reactivates the selected historical config before
starting the historical image. If that rollback target is unhealthy, it restores
the starting config before restoring the starting image. Web-only rollback keeps
the active API config unchanged.

Console status is available without exposing secrets:

```bash
sudo /usr/local/sbin/docker-status-node.sh
```

## Existing public reverse proxy

Use [nginx.conf.example](../nginx.conf.example) or
[Caddyfile.example](../Caddyfile.example) as a reviewed snippet for the existing
HTTPS service. Replace placeholders outside Git, stage the file, back up the
active configuration, and validate the complete proxy before reload. The
private upstream below is a sanitized example; substitute the node policy's
fixed `WEB_IP`, not its loopback smoke port:

```bash
sudo /usr/local/sbin/install-proxy-config.sh nginx \
  /root/alert-hub-nginx.template \
  /etc/nginx/conf.d/alert-hub.conf \
  --server-name alerts.example.com \
  --upstream 10.253.251.3:8080 \
  --trusted-proxy 127.0.0.1/32
sudo nginx -t
```

The installer refuses an unmanaged destination, keeps a timestamped backup,
validates the full proxy, and restores the previous file on validation failure.
It does not reload automatically. Validate Caddy with `caddy validate` before a
separate explicit reload.

The examples preserve SSE, no-store service-worker/runtime headers, CSP and
security headers, and public `404` denials for `/internal/*`, `/metrics`,
`/health/deep`, `/api/docs*`, `/api/redoc*`, and `/api/openapi.json`.

## Dedicated HTTPS peer proxy

Give each node a separate peer hostname and point its DNS `A` record directly
at that node. Do not proxy this record through a CDN: the templates deliberately
match the TCP source against repeated exact public IPv4 `/32` entries. The peer
hostname terminates TLS but is not a general API vhost. It exposes only:

- `GET /internal/v1/nodes/health`;
- `POST /internal/v1/sync/events/query`.

Wrong methods, the cursor/apply operations, public API/UI paths, metrics, and
diagnostics return `404`; a source outside the allowlist returns `403`. The
ordinary public UI hostname still returns `404` for every `/internal/*` path.

The following three-node table uses reserved documentation addresses and
`.example.invalid` names; replace every value with inventory outside Git. The
same two `/32` values go into both the peer proxy and that node's
`PEER_ALLOWED_CIDRS`:

| Environment     | `PEER_PUBLIC_URL`                 | `PEER_URLS`                                                       | `PEER_ALLOWED_CIDRS`               |
| --------------- | --------------------------------- | ----------------------------------------------------------------- | ---------------------------------- |
| `production-ru` | `https://peer-ru.example.invalid` | `https://peer-nl.example.invalid,https://peer-de.example.invalid` | `198.51.100.20/32,203.0.113.30/32` |
| `production-nl` | `https://peer-nl.example.invalid` | `https://peer-ru.example.invalid,https://peer-de.example.invalid` | `192.0.2.10/32,203.0.113.30/32`    |
| `production-de` | `https://peer-de.example.invalid` | `https://peer-ru.example.invalid,https://peer-nl.example.invalid` | `192.0.2.10/32,198.51.100.20/32`   |

### RU pattern: containerized Caddy

Inventory the existing Caddy mounts and networks first. If it is not already
attached, add `alert-hub-edge` to the Caddy service in the Compose file that owns
that container; do not connect it to egress or monitoring. A one-off
`docker network connect` is not durable and must not be used as the installation
method. Merge the following entries into the owning Compose without removing
its existing networks:

```yaml
services:
  caddy:
    networks:
      - existing-caddy-network
      - alert-hub-edge

networks:
  existing-caddy-network:
    external: true
  alert-hub-edge:
    external: true
```

Back up both the owning Compose and the complete Caddyfile, then validate and
recreate only Caddy so the persistent attachment is applied. The rendered site
file must be in a host directory already mounted and imported by the container's
main Caddyfile:

```bash
sudo docker network inspect alert-hub-edge
cd /HOST/CADDY/COMPOSE/DIRECTORY
sudo docker compose config --quiet
sudo docker compose up --detach --no-deps CADDY_SERVICE
sudo docker inspect CADDY_CONTAINER \
  --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}'
sudo /usr/local/sbin/install-proxy-config.sh caddy \
  /root/alert-hub-peer-caddy.template \
  /HOST/PATH/IMPORTED/alert-hub-peer.caddy \
  --server-name peer-ru.example.invalid \
  --upstream alert-hub:8080 \
  --peer-cidr 198.51.100.20/32 \
  --peer-cidr 203.0.113.30/32 \
  --caddy-container CADDY_CONTAINER \
  --validate-config /etc/caddy/Caddyfile
sudo docker exec CADDY_CONTAINER caddy reload --config /etc/caddy/Caddyfile
```

The node provisioner installs `install-proxy-config.sh` as a root-owned helper
in `/usr/local/sbin`. Caddy manages the peer certificate automatically after the
explicit validated reload. In that same container, the separate ordinary public
UI site uses `alert-hub-web:8080` and retains its unconditional `/internal/*`
denial; never reuse the peer block for the UI hostname.

### NL pattern: host Nginx and Certbot

Obtain the hostname's certificate with the installation's existing Certbot
mode, then render the dedicated server block to an included directory. Prefer
DNS-01 when steady-state policy exposes only `443`; the shown Nginx HTTP-01 flow
requires a narrowly timed inbound `80` exception for issuance and renewal that
must be removed and externally verified afterward:

```bash
sudo certbot certonly --nginx --domain peer-nl.example.invalid
sudo /usr/local/sbin/install-proxy-config.sh nginx \
  /root/alert-hub-peer-nginx.template \
  /etc/nginx/conf.d/alert-hub-peer.conf \
  --server-name peer-nl.example.invalid \
  --upstream 10.253.251.2:8080 \
  --peer-cidr 192.0.2.10/32 \
  --peer-cidr 203.0.113.30/32 \
  --tls-certificate /etc/letsencrypt/live/peer-nl.example.invalid/fullchain.pem \
  --tls-private-key /etc/letsencrypt/live/peer-nl.example.invalid/privkey.pem
sudo nginx -t
sudo systemctl reload nginx
```

### DE pattern: host Caddy

Import the rendered site block from the active host Caddyfile. Caddy manages the
certificate automatically and reaches the API's fixed address on the managed
edge bridge:

```bash
sudo /usr/local/sbin/install-proxy-config.sh caddy \
  /root/alert-hub-peer-caddy.template \
  /etc/caddy/conf.d/alert-hub-peer.caddy \
  --server-name peer-de.example.invalid \
  --upstream 10.253.251.2:8080 \
  --peer-cidr 192.0.2.10/32 \
  --peer-cidr 198.51.100.20/32 \
  --validate-config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

The proxy templates replace, rather than append, Internet-supplied forwarding
headers. The API trusts only its managed edge proxy hop, then evaluates the
recovered sender against the same exact `/32` values in
`PEER_ALLOWED_CIDRS`. Never put peer addresses in `TRUSTED_PROXY_CIDRS`; peers
are authenticated clients, not proxies allowed to assert another address.

After validation and an explicit reload, test from an allowlisted peer and from
an unrelated external address. Record certificate verification, the two allowed
method/path pairs, wrong-method/path denial, source denial, and confirmation
that ports `18080` and `18081` remain loopback-only. If a containerized proxy
sees every client as one Docker gateway address, stop: use host networking or a
host proxy that preserves the source. Never allowlist that shared gateway as a
substitute for the real peer `/32` values.

WireGuard remains an optional alternative, not a prerequisite. The application
accepts literal RFC1918/ULA `http://` peer origins when the private tunnel and
firewall provide the transport boundary; never use private HTTP over the public
Internet. The protected production workflow documented here intentionally uses
the HTTPS peer-hostname mode, while universal/manual deployments may retain a
reviewed private-HTTP topology.

## Existing monitoring network

Neither universal nor production Compose creates or modifies monitoring
services. For a local installation, join an inventoried external network only
through the optional overlay:

```bash
MONITORING_NETWORK=existing_monitoring \
docker compose \
  -f docker-compose.yml \
  -f deploy/docker-compose.monitoring.yaml \
  config
```

Joining a Docker network does not authorize exposing Prometheus, Alertmanager,
or Blackbox ports on the host. Production uses the separate root-owned
`docker-compose.production-monitoring.yml` override only when the optional
`MONITORING_NETWORK` policy key is present. Without that key the API keeps its
ordinary outbound egress bridge but is not attached to any monitoring network.
Status validates the exact runtime network set: API must have only edge, egress,
and the optional configured monitoring network; web must have only edge and
ingress. A stale or unexpected attachment is unhealthy rather than silently
reported as disabled.

Checks queries every enabled Alert Hub Prometheus datasource. Before setting
`CHECKS_ENABLED=true`, verify the intended `synthetic_check_*` recording or
executor metrics are visible from those datasources and that `check_id` is
unique across their combined view. Keep the executor and scrape configuration
outside Alert Hub. The API uses its existing bounded monitoring egress and does
not need a new container, published port, shared database, Redis, or broker.

The sanitized `deploy/scripts/host-readiness.sh` field
`sudo_unrestricted_nopasswd` checks whether the current account can run an
arbitrary passwordless sudo command. A secure runner with only the provisioned
three-command sudo boundary should report `no`; that result is not a failed
deployment prerequisite.

## Deployment evidence

For every production rollout retain the GitHub run, release manifest checksum,
tag, per-component digests before and after, compatibility value, node status,
backup checksum, migration result, and readiness result. For failed-deploy and
rollback drills, retain both the deliberate failure and verified restoration.

Never attach application env files, Actions secrets, token values, SQLite data,
Docker auth configuration, or secret directories to workflow artifacts or
issues. DNS records and certificates remain installation changes and are not
created by these repository workflows.

# Production deployment

This guide installs one Alert Hub node without replacing its existing
Prometheus, Alertmanager, Blackbox, Nginx, Caddy, firewall, or private-network
configuration. Repeat it for every node and keep every SQLite database local to
that node.

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

Record a free loopback web port, the exact
RFC1918/WireGuard address for peer traffic, public proxy ownership, firewall
rules, filesystem capacity, backup destination, and outbound HTTPS access to
GHCR and GitHub. If the API must reach an existing Prometheus network directly,
also record that Docker network; this attachment is optional. Never place SQLite
on NFS, a shared Docker volume, or another node's filesystem.

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
  --host-port FREE_LOOPBACK_PORT \
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
only fixed root-owned entry points. Its sudoers rule uses `env_reset`, a fixed
`secure_path`, and an explicit deployment-variable allowlist; it does not grant
`SETENV`. The dedicated runner may invoke deploy/rollback with that validated
environment and status without arguments, but may not invoke the provisioner.
GitHub runner registration remains a separate operator step: the helper has no
option for and never reads a registration token.

Before replacing any trust-boundary file, the helper creates and exclusively
locks `/opt/alert-hub/.deploy.lock`, stages every destination on its own
filesystem, and records the previous root-owned files. Activation uses atomic
renames while deploy, rollback, and status are excluded by the same lock. A late
copy, content, mode, or `visudo` failure restores the complete previous set;
failure to restore is reported as critical and preserves root-only recovery
material instead of deleting it.

The generated policy has six required keys: `GITHUB_REPOSITORY`, `NODE_NAME`,
`HOST_PORT`, `EDGE_SUBNET`, `API_IP`, and `WEB_IP`. `MONITORING_NETWORK` is a
seventh optional key written only when requested. The policy is a root-owned
regular file with mode `0600`; it contains node-local topology but no public
domain, token, or cryptographic secret, and it is never committed. The engine
validates CIDR membership, address separation, network ownership, and
repository/node identity before touching a container. The runner must not be
able to edit any installed copy. Once created, the complete policy is immutable:
ordinary re-provisioning accepts only a byte-identical policy and refreshes the
reviewed scripts/Compose files. A node-name, port, subnet, address, or monitoring
network change requires a separately reviewed topology migration while the
application is stopped; the bootstrap helper intentionally has no bypass flag.

The deploy engine creates these paths with restrictive ownership and modes:

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
/etc/alert-hub/docker-compose*.yml       root:root 0644
/etc/sudoers.d/alert-hub-deploy          root:root 0440
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

The secret directory also contains a deployment-smoke token derived with its
own domain-separation label. The wrapper passes it to the API helper over stdin
and to `curl` through a temporary root-only mode-`0600` config; the token is
never a process argument or log field.

## Network boundary

The production Compose model runs independent API and web services:

- web binds `127.0.0.1:<HOST_PORT>` from the inventoried root-owned node policy
  for the existing public HTTPS proxy;
- API binds port `8080` only on the Environment's private `PEER_ADDRESS`;
- API and web communicate on the dedicated private subnet and addresses recorded
  in the root-owned node policy;
- only API mounts SQLite, application config, and secrets;
- only API joins the managed outbound egress bridge;
- only API optionally joins the inventoried external monitoring network when
  `MONITORING_NETWORK` is present in the node policy;
- `/internal/*` is never routed by the public Nginx/Caddy examples.

Firewall the private API listener to the exact peer and operator CIDRs. The
deployment script accepts `PEER_ADDRESS` only as an RFC1918 IPv4 address without
a scheme or port. The application protocol can validate ULA peer URLs, but the
current production Compose/host wrapper is intentionally IPv4-only for this MVP.
This check is a guard, not a firewall replacement.

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
PEER_ADDRESS
```

Optional Environment or Repository Variables consumed by deployment are:

```text
APP_NAME
PEER_URLS
PEER_ALLOWED_CIDRS
VAPID_PUBLIC_KEY
```

`APP_NAME` defaults to `Alert Hub`. `PEER_URLS` is a comma-separated list of
private literal peer URLs; setting it also requires the narrowest applicable
`PEER_ALLOWED_CIDRS`. `VAPID_PUBLIC_KEY` may be omitted because the API derives
it from the P-256 private key.

`PUBLIC_DOMAIN` is a DNS hostname without a scheme. `PEER_ADDRESS` is the
current node's private bind address. `NODE_IP` is inventory metadata and is not
implicitly used as a bind address.

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

Static runner labels remain in the workflow:

```text
self-hosted, alert-hub-ru
self-hosted, alert-hub-nl
self-hosted, alert-hub-de
```

Configure required reviewers and deployment-branch rules for each Environment.
Branch protection should require the CI jobs and CODEOWNERS review for workflow,
Docker, production, and dependency-lock changes.

Peer lists and sender CIDRs are installation topology, not universal defaults.
When configured, pass only private `PEER_URLS` and the narrowest
`PEER_ALLOWED_CIDRS`. Without a peer list, the node deliberately starts with
synchronization disabled rather than inventing a topology.

## Release and deploy behavior

Pull requests to `main` build and test API and web independently and together,
but have read-only permissions and never publish or deploy. A version tag runs
the complete release gate. Failure of either image makes the release incomplete.

`deploy.yml` and `rollback.yml` are manual `workflow_dispatch` workflows. They
have no `push` or `pull_request` trigger. A deploy selects:

- a published `vX.Y.Z` release;
- target node or ordered node set;
- component `api`, `web`, or `all`.

The workflow resolves the signed release manifest to exact image digests before
entering a protected node job. A web-only deploy leaves the API container and
SQLite untouched. An API-only deploy backs up SQLite, runs forward migrations,
and leaves web running in guarded mode until readiness returns. An `all` deploy
updates the compatible pair. A component-only update is rejected when it would
leave mismatched compatibility labels.

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
   an authenticated heartbeat through web or the private API listener;
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
active configuration, and validate the complete proxy before reload:

```bash
sudo /usr/local/sbin/install-proxy-config.sh nginx \
  /root/alert-hub-nginx.template \
  /etc/nginx/conf.d/alert-hub.conf \
  --server-name alerts.example.com \
  --upstream 127.0.0.1:8080 \
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

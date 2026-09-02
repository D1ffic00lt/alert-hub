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
    └── scripts/
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

Record the existing monitoring network, a free loopback web port, the exact
RFC1918/WireGuard address for peer traffic, public proxy ownership, firewall
rules, filesystem capacity, backup destination, and outbound HTTPS access to
GHCR and GitHub. Never place SQLite on NFS, a shared Docker volume, or another
node's filesystem.

## Prepare a node

Install files from the exact reviewed release commit. The runner must not be
able to edit the installed copies:

```bash
sudo install -d -o root -g root -m 0755 /etc/alert-hub
sudo install -d -o root -g root -m 0700 /opt/alert-hub
sudo install -o root -g root -m 0644 \
  .github/deploy/docker-compose.production.yml \
  /etc/alert-hub/docker-compose.production.yml
sudo install -o root -g root -m 0755 \
  .github/deploy/scripts/docker-deploy-node.sh \
  /usr/local/sbin/docker-deploy-node.sh
sudo install -o root -g root -m 0755 \
  .github/deploy/scripts/docker-rollback-node.sh \
  /usr/local/sbin/docker-rollback-node.sh
sudo install -o root -g root -m 0755 \
  .github/deploy/scripts/docker-status-node.sh \
  /usr/local/sbin/docker-status-node.sh
# Create this node-local policy without using a repository file. Replace every
# angle-bracket placeholder with values confirmed by the read-only inventory:
sudo sh -c 'umask 077; printf "%s\n" \
  "GITHUB_REPOSITORY=OWNER/alert-hub" \
  "NODE_NAME=<node-name>" \
  "HOST_PORT=<free-loopback-port>" \
  "EDGE_SUBNET=<dedicated-rfc1918-cidr>" \
  "API_IP=<api-address-in-edge-subnet>" \
  "WEB_IP=<web-address-in-edge-subnet>" \
  "MONITORING_NETWORK=<existing-docker-network>" \
  > /etc/alert-hub/deploy-policy.env'
```

Replace `OWNER` and every placeholder with the expected repository owner, fixed
node name, inventoried free loopback port, a dedicated non-overlapping private
bridge subnet and addresses, and the exact existing monitoring network name.
The policy must be a root-owned regular file with mode `0600` and exactly those
seven keys. It contains node-local network topology but no public domain, token,
or cryptographic secret, and it is never committed. The engine validates CIDR
membership, address separation, network ownership, and repository/node identity
before touching a container.

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
- only API joins the existing monitoring/egress network;
- `/internal/*` is never routed by the public Nginx/Caddy examples.

Firewall the private API listener to the exact peer and operator CIDRs. The
deployment script accepts `PEER_ADDRESS` only as an RFC1918 IPv4 address without
a scheme or port. This check is a guard, not a firewall replacement.

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

Universal Compose does not create or modify monitoring services. For a local
installation, join an inventoried external network only through the optional
overlay:

```bash
MONITORING_NETWORK=existing_monitoring \
docker compose \
  -f docker-compose.yml \
  -f deploy/docker-compose.monitoring.yaml \
  config
```

Joining a Docker network does not authorize exposing Prometheus, Alertmanager,
or Blackbox ports on the host.

## Deployment evidence

For every production rollout retain the GitHub run, release manifest checksum,
tag, per-component digests before and after, compatibility value, node status,
backup checksum, migration result, and readiness result. For failed-deploy and
rollback drills, retain both the deliberate failure and verified restoration.

Never attach application env files, Actions secrets, token values, SQLite data,
Docker auth configuration, or secret directories to workflow artifacts or
issues. DNS records and certificates remain installation changes and are not
created by these repository workflows.

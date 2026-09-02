# Failure and rollback runbook

This runbook separates application-image rollback from database restore. Image rollback is routine and keeps the forward-migrated DB. SQLite restore is a last-resort, explicitly confirmed recovery that may lose new events.

## Automatic deployment gate

For one node the root deploy engine performs, in order:

1. acquire a non-blocking local lock;
2. validate root-owned files, operation/version/paths, Docker, Compose, runtime
   permissions, disk headroom, and exact image references;
3. pull the selected digest or compatible pair and verify component, version,
   compatibility, and schema labels;
4. capture the current component state and content-addressed runtime-config
   snapshot, and create an online SQLite backup when an API update has an
   existing database;
5. recreate only `api`, `web`, or both as selected, running forward Alembic
   migration only for API;
6. poll component health and, when web is installed, verify public readiness,
   the PWA root, and runtime config;
7. read SQLite through deep health and submit an authenticated heartbeat with
   the root-only deployment-smoke credential;
8. write the successful API/web digest, compatibility, and active config
   checksum plus local rollback history.

If preflight, migration, start, readiness, database, ingest, or static smoke
fails, the engine stops the
candidate. For `api`/`all`, it verifies and restores the config snapshot named
by the prior state's `CONFIG_SHA256` before restoring the selected component
from its prior digest. It then checks readiness, leaves the recorded current
state unchanged, exits nonzero, and prevents later workflow slots from
deploying. API rollback keeps the forward-migrated, N-1-compatible database.

Pull-request CI parses and lints the privileged scripts and exercises the two-image runtime's
component-only recreation, failed API startup, guarded `503`, and recovery paths. It does not prove
that a production node, its Docker daemon, disk, credentials, or runner completed the node-local
automatic rollback path. That remains a required installation drill.

## Failed rollout triage

1. Confirm the GitHub job stopped at the affected node and later deploy slots did not run.
2. On that node, run `sudo /usr/local/sbin/docker-status-node.sh` and record the
   mode-`0600` state file through the approved evidence process.
3. Confirm the old version is ready. If automatic rollback says the old version is unhealthy, remove the node from traffic immediately.
4. Inspect candidate and migration logs without printing env/secrets.
5. Verify the pre-deploy backup and available disk.
6. Classify failure: image/runtime, proxy/config, migration/schema, static/PWA, ingest, or underlying host.
7. Fix forward in a new version. Do not move/reuse a published tag.

A failed SQLite DDL migration can be partly applied depending on the operation. N-1 expand-contract compatibility should let the prior binary run, but it does not excuse inspection. If `quick_check` fails or the prior binary cannot read its required schema, keep ingest disabled and follow emergency restore.

## Manual image rollback

Use the separate GitHub **Rollback** workflow, choose one node first, select
`api`, `web`, or `all`, set the version to `previous` or an exact installed
version, and enter the UI confirmation `ROLLBACK PRODUCTION`. The workflow
derives the node-specific `ROLLBACK <node>` confirmation for the root wrapper.

Console fallback when GitHub or a runner is unavailable:

```bash
export NODE_NAME=ru
export NODE_IP=NODE_INVENTORY_VALUE
export PUBLIC_DOMAIN=alerts.example.com
export PEER_ADDRESS=10.0.0.10
export GITHUB_REPOSITORY=OWNER/alert-hub
export ALERT_HUB_COMPONENT=api
export ALERT_HUB_ROLLBACK_VERSION=previous
export ALERT_HUB_CONFIRMATION='ROLLBACK ru'
# For a private package, also export GHCR_TOKEN and GITHUB_ACTOR without
# placing the token in argv or shell tracing.
sudo --preserve-env=NODE_NAME,NODE_IP,PUBLIC_DOMAIN,PEER_ADDRESS,GITHUB_REPOSITORY,ALERT_HUB_COMPONENT,ALERT_HUB_ROLLBACK_VERSION,ALERT_HUB_CONFIRMATION,GHCR_TOKEN,GITHUB_ACTOR \
  /usr/local/sbin/docker-rollback-node.sh
unset GHCR_TOKEN
```

For `api` or `all`, the wrapper verifies and activates the config snapshot recorded with the
selected historical state before it starts that state's digest. It does not run an Alembic
downgrade. For `web`, it changes no API config. The wrapper runs the same health/smoke gates; if the
rollback target fails, it restores the starting config before it restores the starting image. It
does not create a new database backup during ordinary image rollback; verify the existing
pre-deploy backup and current database integrity first. Verify incident reads, intake, sessions,
static assets, and metrics after rollback.

If a recorded config snapshot is missing, has a malformed identifier, is a symlink, has unexpected
ownership/mode, or no longer hashes to its recorded checksum, stop. Do not recreate it from memory
or point state at another path. Diagnose the host-evidence failure and deploy a reviewed fixed-
forward release or rebuild the node from trusted material.

## Failure decision table

| Failure                       | Immediate action                                            | Recovery                                                                                   | Data note                                                                           |
| ----------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| One process/container stops   | Keep other regions serving; inspect restart/health          | Restart same immutable digest; rollback if caused by release                               | Node-local events remain in SQLite.                                                 |
| Host/application disk full    | Remove node from ingest; stop write pressure                | Free known disposable image/log space, expand disk, verify DB, then start                  | Never delete DB/WAL blindly. Backup may also have failed.                           |
| Candidate readiness fails     | Let automatic rollback finish                               | Diagnose candidate; release a new tag                                                      | Forward migration stays; must be N-1 compatible.                                    |
| Migration fails               | Stop rollout; confirm old image health                      | Inspect revision/DB, fix forward; restore only if integrity/compatibility fails            | Pre-deploy online backup is the recovery point.                                     |
| Proxy validation fails        | Do not reload and do not deploy                             | Installer restores managed snippet; correct staged config and revalidate                   | Application/data unchanged.                                                         |
| Proxy works but PWA/SSE fails | Keep API available; inspect cache/buffering headers         | Correct separate proxy snippet, validate, reload explicitly                                | No DB restore. Service worker must be no-store.                                     |
| GitHub runner offline         | Continue serving current release                            | Repair runner outbound connectivity or use console wrapper                                 | No inbound deploy port is needed.                                                   |
| GitHub unavailable            | Freeze normal rollout                                       | Use console wrapper with an already published version/digest path                          | Preserve local release history; do not bypass validation.                           |
| One complete node lost        | Disable its DNS/eligibility and revoke host credentials     | Rebuild host; restore verified node backup or bootstrap as a new node                      | Preserve old node ID only when restoring its history. New empty node gets a new ID. |
| RU↔EU partition               | Keep both sides accepting; avoid destructive reconciliation | Restore network, observe cursor convergence and duplicates                                 | Target behavior permits duplicates, never disappearance.                            |
| Push/provider failure         | Keep intake/UI healthy; retain queued deliveries            | Observe durable retry/backoff and ownership failover; disable `404/410` subscriptions      | Provider outage must not make local API readiness fail.                             |
| Suspected host compromise     | Isolate host/private peer immediately                       | Rotate node/provider credentials and rebuild from trusted image/backup                     | Do not trust local rollback alone.                                                  |
| Full cluster loss             | Stop senders from cycling uncontrolled retries              | Restore keys, choose newest verified DB, start one isolated node, validate, then add peers | Decide recovery point explicitly; peer replication is unavailable.                  |

## Complete node rebuild

If the host is lost but a trusted node backup and key bundle exist:

1. inventory/rebuild the host and private network;
2. install root-owned wrapper/config from a verified release;
3. restore cluster/signing/encryption/VAPID secrets over the secret channel;
4. restore SQLite while the container is stopped, preserving the backed-up node ID;
5. deploy the compatible digest and validate locally with public traffic disabled;
6. check vector cursors against peers, then enable private sync and observe;
7. re-enable ingest, notification eligibility, and public routing one at a time.

If no usable node DB exists, assign a new node ID and use snapshot/full-resync bootstrap after that feature is implemented. Never reuse another live node's ID or point two nodes at the same SQLite file.

## Full cluster recovery

1. Freeze ingress or spool at Alertmanager if possible; preserve sender retry queues.
2. Inventory all DB backups and release manifests by UTC time and checksum.
3. Recover the shared offline key bundle before starting an application.
4. Select the best verified DB based on required history, not filename alone.
5. Start one node isolated from peers/providers, run `quick_check`, migrations at the recorded digest, and read-only incident checks.
6. Reintroduce notification providers only after preventing replay of already delivered events.
7. Restore additional nodes from their own DBs or full-resync them; do not clone a live SQLite file.
8. Re-enable sources gradually and reconcile the outage window with Alertmanager/audit evidence.

## Emergency DB restore

Use only when current SQLite is corrupt/incompatible or the operator deliberately selects an older recovery point. Follow the exact procedure in [operations](../operations.md#emergency-sqlite-restore). Record the chosen backup checksum and expected loss window. Keep peer sync and notifications disabled until deciding whether replay can create stale state or duplicate delivery.

## Partition and convergence evidence boundary

Periodic transport, empty-cursor full-history resync, deterministic projection, replicated
heartbeat observations, notification receipts, and durable delivery ownership are implemented.
Separate-database regressions cover both heartbeat recovery arrival orders and notification
ownership/receipt mapping through a stable logical event key even when local incident-event row IDs
differ. Pull-request CI includes a controlled three-container substitute that exercises separate
SQLite files, partitioned duplicate and reverse-order ingress, process loss, peer return, restart,
cursor convergence, and re-fire.

That test is not evidence that the installation's RU/EU private routes, host firewalls, proxies,
provider egress, or delivery-owner failure behave correctly. Run the same scenario against the
real topology, capture the fields listed below, and link the dated artifacts from
[acceptance evidence](../acceptance-evidence.md) before marking the production partition scenario
accepted.

## Closeout evidence

After any failure, capture UTC start/end, affected node/region, version and digest before/after, config checksum, backup checksum, migration revision, ready/deep results, proxy validation, ingest/dedup result, cursor/queue impact, duplicate/lost-event analysis, credential rotations, and corrective test. Never attach raw SQLite, secret files, cookies, bearer headers, or full sensitive payloads to a public issue.

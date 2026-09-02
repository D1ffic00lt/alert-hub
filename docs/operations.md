# Operations

## Daily health view

Use the public readiness endpoint for routing and the local status wrapper for deployment state:

```bash
curl --fail --silent --show-error https://alerts.example.com/health/ready
sudo /usr/local/sbin/docker-status-node.sh
sudo docker logs --tail=200 alert-hub-api
sudo docker logs --tail=200 alert-hub-web
```

On a freshly provisioned node with no deployment state, runtime config, or
managed containers, the status wrapper returns a successful explicit
`not-deployed` report. Any partial bootstrap residue fails closed. For recorded
components it also requires the exact managed Docker network set, so a stale
monitoring attachment is an unhealthy state.

`ready` proves the local API can read SQLite. `deep` adds peer/channel diagnostics but remote
failures are informational, so they do not remove an autonomous node from service. The supplied
public proxy examples deny `/health/deep`, `/metrics`, API documentation, and `/internal/*` with
`404`. Query or scrape those operator surfaces through loopback/private paths; never publish a
separate metrics port.

Set the optional `GRAFANA_URL` to the installation's HTTPS dashboard when the UI should offer a
detailed-view link. The validated URL is returned only in the authenticated metrics summary. It is
navigation metadata, not a Grafana credential or a way to submit PromQL; Prometheus remains the
time-series source of truth.

Alert on at least:

- readiness failure or restart loop;
- ingest error ratio and payload rejection;
- SQLite errors or disk exhaustion;
- outbox growth and delivery failure ratio;
- sync lag, peer availability, and `alert_hub_clock_skew_suspected` when a peer event timestamp differs from local time beyond `CLOCK_SKEW_THRESHOLD_SECONDS`;
- backup age/checksum/restore-test failure;
- release digest/config checksum drift across nodes.

## Peer HTTPS boundary

Each node has a dedicated peer hostname on `443`; it is separate from the
public UI hostname and resolves directly to the node. The operator proxy
terminates and renews TLS, checks the other nodes' exact public `/32` sources,
overwrites forwarding headers, and routes only the peer health `GET` and event
query `POST`. The application then applies the same CIDR decision and cluster
bearer authentication. A proxy allowlist is not a replacement for the bearer.

After DNS, certificate, proxy, or public-address changes:

1. validate the complete Nginx/Caddy configuration before reload;
2. confirm `docker-status-node.sh` reports distinct loopback API/web listeners;
3. from each allowed node, verify the certificate and both permitted operations;
4. from an allowed node, verify wrong methods and every other path return `404`;
5. from an unrelated network, verify the peer hostname returns `403` or `404`;
6. externally scan that the loopback application ports are not reachable;
7. record evidence without authorization headers, bearer values, or payloads.

Certificate renewal must use the proxy's existing ACME process and a validated
reload hook. If a node's public egress address changes, update both other
nodes' proxy `/32` allowlists and `PEER_ALLOWED_CIDRS` as one reviewed operation;
an incomplete change is expected to fail closed and temporarily pause sync.

## Release state

Each successful node deployment records the active API and web digest references plus their
compatibility value and the SHA-256 of the active runtime config beneath `/opt/alert-hub`. The
deployment scripts also retain local state history and content-addressed config snapshots suitable
for component rollback. State files contain no application secrets. Runtime config and its
snapshots are root-readable only; key material remains in the separate secret files.

```text
/opt/alert-hub/config/alert-hub.env
/opt/alert-hub/state/current.env
/opt/alert-hub/history/                 # state history
/opt/alert-hub/history/configs/         # sha256-<digest>.env config snapshots
/etc/alert-hub/docker-compose.production.yml
/etc/alert-hub/docker-compose.production-monitoring.yml  # optional override
/etc/alert-hub/deploy-policy.env
/etc/sudoers.d/alert-hub-deploy
```

`CONFIG_SHA256` is deliberately not a path. Before activation, the engine derives the fixed
history filename, requires a root-owned mode-`0600` regular non-symlink, and verifies its content
hash. Do not rename, edit, symlink, or copy snapshots into the history directory by hand. If the
snapshot for a recorded API state is missing or fails verification, rollback fails closed before
starting that image.

The wrapper holds a node-local `flock` while it changes state. Concurrent deploy/rollback attempts
fail immediately. Do not remove a lock file to “unstick” a running process; first confirm no
wrapper process holds it with `lslocks` or `lsof`.

The container image-matrix smoke covers component-only recreation, API loss, guarded web `503`,
recovery, and failed API startup. Repository policy checks parse and lint the privileged scripts.
Neither substitutes for the dated failed-deploy and manual-rollback drills on a prepared node.

## Backups

Cluster replication is not a backup. Schedule node-local online SQLite backup
and copy verified backups to an access-controlled failure domain according to
local policy. Node provisioning installs the root-owned tool and a mode-`0600`
`/etc/alert-hub/backup.env`. Fresh defaults use the immutable policy's node name,
`/opt/alert-hub/data/alert-hub.db`, `/opt/alert-hub/backups`, container
`alert-hub-api`, database UID/GID `10001`, and 7-daily/4-weekly/6-monthly
retention. Re-provisioning preserves a valid operator-customized config exactly
and fails closed on an unsafe file or value instead of replacing it.

The supplied tool uses Python's SQLite backup API, runs `PRAGMA quick_check`,
writes a SHA-256 sidecar, and atomically publishes the result. Provisioning
requires host Python 3.9+ with `sqlite3` backup support, creates the default
backup directory with root-only access, and requires an operator-customized
directory to exist as `root:root` mode `0700`. The tool reasserts that mode on
each run.

```bash
sudo /usr/local/sbin/alert-hub-backup backup --label manual
sudo /usr/local/sbin/alert-hub-backup list
sudo /usr/local/sbin/alert-hub-backup verify /opt/alert-hub/backups/alert-hub-YYYYMMDDTHHMMSSZ-manual-PID.db
```

Default retention keeps the union of one newest backup for 7 daily, 4 ISO-week, and 6 monthly buckets. `prune` deletes only tool-named regular backup files in the configured backup directory. Monitor capacity independently: retention cannot help if a sudden WAL or log surge consumes the disk before backup starts.

Provisioning deliberately does not enable a timer. Install and enable the
reviewed `deploy/systemd/alert-hub-backup.{service,timer}.example` units, or use
the site's scheduler, after confirming the destination and off-node copy policy.
If `BACKUP_DIR` is customized, update the service sandbox's `ReadWritePaths` to
the same directory before enabling it. If `DATABASE_PATH` is customized, update
`ReadOnlyPaths` at the same time.

At least monthly, restore a copied backup into an isolated test path/container and verify:

1. checksum and `quick_check` succeed;
2. Alembic reports the expected revision;
3. the application reaches ready;
4. recent incidents/timeline rows are readable;
5. a test source remains idempotent;
6. encrypted data can be read with the offline recovery keys.

## Emergency SQLite restore

An ordinary application rollback never restores the database. Restore only after choosing a recovery point and accepting loss of newer node-local events.

1. Remove the node from public ingest and notification eligibility.
2. Record cluster cursors and copy the current DB/WAL/SHM if readable.
3. Stop the application container.
4. Verify the selected backup.
5. Run the separately confirmed restore.
6. Start the current compatible application image.
7. Validate local history before permitting peer sync; decide whether peers should refill missing events or whether this node needs a full resync.

```bash
sudo /usr/local/sbin/alert-hub-backup verify /opt/alert-hub/backups/SELECTED.db
sudo /usr/local/sbin/alert-hub-backup restore /opt/alert-hub/backups/SELECTED.db --confirm 'RESTORE ru'
```

The tool fails closed unless Docker can prove the application is stopped. It rejects both the configured container name and any running container whose writable host mount contains the configured database path, checking again immediately before replacement. Broad read-only monitoring mounts do not block recovery. The tool then preserves the prior database as a fresh online backup when possible, moves stale WAL/SHM sidecars aside, restores ownership to UID/GID `10001`, and runs `quick_check`. It does not restore cluster/VAPID/signing keys.

## Secret rotation

- Source tokens: rotate through the source endpoint/UI, update senders, observe the compatibility window if supported, then revoke the old token. Only hashes belong in SQLite.
- Cluster bearer secret: distribute a new key file through the secret channel, configure old+new compatibility, roll nodes, verify peer auth, then remove the old key.
- Signing key: coordinate every node; rotating without a compatibility strategy invalidates sessions.
- Master encryption/VAPID keys: export an encrypted offline recovery bundle first. AES-GCM storage is implemented; safe bulk re-encryption/key rotation and VAPID subscription impact still require a dedicated tested runbook.

Never echo a key in a shell command recorded by Actions. The root-owned secret directory is
traversable only by container GID `10001`; individual files are owned by UID/GID `10001`, mode
`0600`, and mounted read-only.

## SMTP notification templates

SMTP channel configuration accepts optional `subject_template` and `body_template` strings.
Templates use only `{{name}}` substitution; they do not execute expressions, filters, attribute
access, or application code. Supported names are `app_name`, `state`, `status`, `event_type`,
`severity`, `severity_upper`, `title`, `body`, `description`, `event_id`, `incident_id`,
`source_id`, `occurred_at`, `incident_url`, `incident_link`, `labels`, and `annotations`.
`labels` and `annotations` render as deterministic compact JSON. `incident_link` includes the
leading blank lines and is empty when no public incident URL is configured.

Omitting either field uses the built-in template. Sending JSON `null` for a template in a channel
PATCH resets that field to its built-in default. Unknown or malformed placeholders and control
characters in a subject template are rejected with `422`; values substituted into a subject are
also flattened to one line before the message is constructed.

## Capacity and SQLite care

- Keep the database on a local durable filesystem and ensure the volume supports fsync and file locking.
- Leave headroom for the DB, WAL, one online backup, a pulled image, and migration temporary space. The wrapper enforces at least 1 GiB on Docker storage and 1 GiB plus the current DB/WAL/SHM footprint on application data; site policy should be larger.
- Do not copy a live `.db` file with ordinary `cp`; use the backup API.
- Do not run two application containers against the same file.
- Investigate a persistently growing `-wal` file, long transactions, or repeated busy-timeout metrics before forcing a checkpoint.
- Use expand-contract migrations. Never issue `alembic downgrade` during routine rollback.

## Logs and audit

Container logs rotate at five 10 MiB files by default. `LOG_FORMAT=json` is the production default; `LOG_FORMAT=text` is intended for local development. `LOG_LEVEL` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` (case-insensitive). Invalid values fail settings validation rather than silently changing verbosity.

JSON application records contain an RFC 3339 UTC timestamp, level, logger, stable event/message, and an explicit allowlist of scalar context such as request, node, source, incident, channel, route, outbox, and peer identifiers. Exception records include the exception type and a bounded redacted trace. Arbitrary `extra` values are dropped: authorization/cookie fields, request bodies, provider responses, peer URLs, and unapproved dictionaries are not serialized. Sensitive labelled values and bearer material are redacted as a second boundary; callers must still never pass secrets to a logger.

The request boundary accepts a caller/proxy `X-Request-ID` only when it is 1–128 safe ASCII identifier characters; otherwise it generates a UUID. The same value is returned and logged for normal responses, pre-routing `400`/`413`/`429`/role-disabled responses, and unhandled application exceptions. The log uses the URL path without its query and never records request headers, cookies, authorization, or body. Uvicorn's separate plain access logger is disabled so the application emits one correlated API request event. The web Nginx access/error logs remain separate proxy evidence.

Access to Docker logs remains privileged because approved incident/source identifiers and proxy metadata can still be sensitive. Log redaction is not an audit guarantee and logs are not a secret-storage channel.

Security-relevant audit should cover authentication, source/channel changes, token rotations, session revocation, failed peer authorization, and deployment-relevant actions. Deployment manifests/history are host evidence; they do not replace the application audit log.

## Follow-on distributed operations

The current repository runs periodic peer pull with pagination, persisted vector cursors,
exponential backoff, deterministic projection replay, and peer health/lag metrics. Heartbeat
requests append replicated observation events; the projection uses the newest observation and
reconciles missed/restored incidents across either arrival order. Notification ownership and
delivery IDs use the logical incident event key, while replicated receipts map that key to each
node's local event row before suppressing reserve delivery. These behaviors have separate-database
regressions, but a true partition can still duplicate delivery by design.

Empty-cursor replay can rebuild a node while complete cluster history is retained. This is not a
compact snapshot protocol: do not prune cluster history until a retention/snapshot design and
restore drill exist. Real provider delivery and multi-region partition evidence remain separate
acceptance gates.

See the [failure and rollback runbook](runbooks/failure-and-rollback.md) for decision procedures.

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

The authenticated UI uses `/api/v1/cluster/status`. It combines durable node inventory with the
serving process's current peer result: the local node is healthy when it serves the request, a peer
is healthy after a successful pull, degraded during the first two consecutive failures, offline
from the third consecutive failure, and unknown before an attempt has produced evidence. Sync lag
is the worker's current cursor evidence, not an estimate from the durable `last_seen_at` field. The
UI refreshes this runtime view every 30 seconds even while its cluster-event stream is connected.

Administrators set the optional Grafana HTTPS dashboard link and the bounded `job` glob lists under
**Settings → Grafana and job selection**. The values are audited and replicated as append-only
cluster configuration. `GRAFANA_URL` remains the initial fallback until a cluster setting is saved.
The link is navigation metadata, not a Grafana credential or a way to submit PromQL; Prometheus
remains the time-series source of truth.

Alert on at least:

- readiness failure or restart loop;
- ingest error ratio and payload rejection;
- SQLite errors or disk exhaustion;
- outbox growth and delivery failure ratio;
- sync lag, peer availability, and `alert_hub_clock_skew_suspected` when a peer event timestamp differs from local time beyond `CLOCK_SKEW_THRESHOLD_SECONDS`;
- repeated Checks `unavailable`/`checks_limit_exceeded` responses and unexpected growth in
  `unknown` or stale results when Checks is enabled;
- backup age/checksum/restore-test failure;
- release digest/config checksum drift across nodes.

## Checks

Checks is an optional, read-only view of results produced by operator-managed external executors.
Alert Hub neither ships nor runs a prober, owns schedules or subscriptions, stores executor
credentials, nor performs network checks itself. Prometheus remains the operational source of
truth; check samples, run history, status snapshots, and the in-memory registry are never written
to SQLite.

Set `CHECKS_ENABLED=true` on an API node only after at least one enabled Alert Hub Prometheus
datasource can read the contract below. Every `/api/v1/checks*` operation still authenticates the
caller when the feature is disabled. Disabled requests return `200`, `enabled: false`,
`data_state: disabled`, and no check data; they do not query Prometheus. A successful refresh with
no contract series returns `200`, `data_state: empty`, an empty list, and a zero summary. This is a
normal state and does not affect Dashboard, alerts, incidents, readiness, or notification work.

The authenticated operations are:

- `GET /api/v1/checks` for the filtered, paginated list;
- `GET /api/v1/checks/summary` for the same filtered population without pagination;
- `GET /api/v1/checks/{check_id}` for normalized per-source/scenario/variant results, optional
  canaries/assertions, alert links, and an optional safe Grafana link.

Response metadata separates acquisition state (`ready`, `empty`, `stale`, `unavailable`, or
`disabled`) from each Check's `up`, `degraded`, `down`, `stale`, or `unknown` status. Ready snapshots
include a server-generated `snapshot_id`, fetch/evaluation time, cache expiry, and bounded warning
codes. A detail request returns `404` only when a reliable current inventory proves the Check is
absent.

### Metric contract and executor connection

The two required gauges describe the same latest completed run:

| Metric                                         | Meaning                                                                            |
| ---------------------------------------------- | ---------------------------------------------------------------------------------- |
| `synthetic_check_status`                       | `1` for success or `0` for failure of the latest completed run                     |
| `synthetic_check_last_run_timestamp_seconds`   | Unix timestamp at which that same run completed                                    |
| `synthetic_check_info`                         | Optional expected-inventory/metadata series; publish value `1`                     |
| `synthetic_check_duration_seconds`             | Optional non-negative total run duration                                           |
| `synthetic_check_ttfb_seconds`                 | Optional non-negative time to first byte when meaningful                           |
| `synthetic_check_canary_success{canary="..."}` | Optional named nested result, `0` or `1`                                           |
| `synthetic_check_egress_match`                 | Optional assertion result, exposed as assertion key `egress_match` without IP data |

`check_id` is the only required label. It must be a stable public identifier, unique across the
enabled datasources visible to the user. The allowlisted optional labels are `check_name`, `group`,
`source`, `target`, `scenario`, and `variant`; `canary` is additionally read only on the canary
metric. Do not put hostnames, URLs, IP addresses, protocol UUIDs, account names, tokens,
credentials, subscription data, or other secrets into any of them. Unknown and service labels
such as `job` and `instance` are not returned to the client.

This is a complete minimal example. Its fixed timestamp is illustrative documentation data, not a
fallback or live fixture:

```prometheus
# TYPE synthetic_check_status gauge
synthetic_check_status{check_id="checkout-flow"} 1
# TYPE synthetic_check_last_run_timestamp_seconds gauge
synthetic_check_last_run_timestamp_seconds{check_id="checkout-flow"} 1788609600
```

A multi-source executor can publish richer results through the same contract:

```prometheus
# TYPE synthetic_check_info gauge
synthetic_check_info{check_id="checkout-flow",check_name="Checkout flow",group="customer-paths",source="edge-a",target="Primary storefront",scenario="purchase",variant="standard"} 1
synthetic_check_info{check_id="checkout-flow",check_name="Checkout flow",group="customer-paths",source="edge-b",target="Primary storefront",scenario="purchase",variant="standard"} 1
# TYPE synthetic_check_status gauge
synthetic_check_status{check_id="checkout-flow",source="edge-a",scenario="purchase",variant="standard"} 1
synthetic_check_status{check_id="checkout-flow",source="edge-b",scenario="purchase",variant="standard"} 0
# TYPE synthetic_check_last_run_timestamp_seconds gauge
synthetic_check_last_run_timestamp_seconds{check_id="checkout-flow",source="edge-a",scenario="purchase",variant="standard"} 1788609600
synthetic_check_last_run_timestamp_seconds{check_id="checkout-flow",source="edge-b",scenario="purchase",variant="standard"} 1788609598
# TYPE synthetic_check_duration_seconds gauge
synthetic_check_duration_seconds{check_id="checkout-flow",source="edge-a",scenario="purchase",variant="standard"} 0.42
# TYPE synthetic_check_canary_success gauge
synthetic_check_canary_success{check_id="checkout-flow",source="edge-a",scenario="purchase",variant="standard",canary="receipt"} 1
# TYPE synthetic_check_egress_match gauge
synthetic_check_egress_match{check_id="checkout-flow",source="edge-a",scenario="purchase",variant="standard"} 1
```

Expose these metrics to the existing Prometheus scrape topology, then confirm an enabled Alert Hub
datasource can query them through its configured network and credentials. If an executor emits
different names, normalize them with executor-side output or reviewed Prometheus recording rules;
do not add browser PromQL or a vendor-specific Alert Hub adapter. Update every optional series for
a result consistently with the required status and completion-timestamp gauges for that run. The
main status remains authoritative: Alert Hub does not infer that a canary or assertion failure must
fail the Check.

`source` is the executor-declared logical observation point, not proof of physical independence.
Give genuinely independent points different stable values, and give replicas of one logical point
the same value. When omitted, Alert Hub treats the result as one private default source; it never
substitutes `instance`, `job`, a scrape address, or a random ID. Scenario, variant, and canary are
also optional and never create extra failure-quorum votes.

Publish `synthetic_check_info` for every expected `(check_id, source, scenario, variant)`, including
before its first run. Without `info`, Alert Hub can discover only tuples present in the required
metrics. A source that has never emitted, or a Check whose series vanished before the process saw
it, is unknowable. Previously observed tuples remain visible only for the life of the bounded
in-memory registry; after restart they cannot be reconstructed. Prometheus retention and `info`,
not the Alert Hub database, provide durable inventory.

Executors that publish `info` may coexist with status-only executors. A valid `info` family removes
an absent cached tuple only when that tuple was itself previously declared by `info`; the presence
of an unrelated `info` series never erases a remembered status-only source. The public identifier
`summary` is reserved by the API route and is rejected like internal sentinels, IP/UUID-bearing
identifiers, and obvious credential markers.

### Freshness, quorum, and aggregation

One result is keyed by `(check_id, source, scenario, variant)`. Exactly matching duplicates are
coalesced. Conflicting main values for one key make that result `unknown`; conflicting optional
values remove only that optional field. Conflicting names fall back to `check_id`, conflicting
optional metadata becomes `null`, and a diagnostic code records the reason. Malformed identifiers,
non-`0`/`1` status values, NaN/infinite values, negative durations, missing timestamps, and
timestamps more than `CHECKS_FUTURE_TOLERANCE_SECONDS` ahead are not allowed to confirm success or
failure.

Age comes from `synthetic_check_last_run_timestamp_seconds`, never scrape or HTTP time. A result is
fresh through the exact `CHECKS_STALE_AFTER_SECONDS` boundary; it becomes stale only when its age is
greater. For each scenario/variant, apply these rules in order:

1. at least one fresh success and one fresh failure is `degraded`;
2. no fresh success and failures from at least `CHECKS_MIN_FAILURE_SOURCES` distinct logical
   sources is `down`;
3. a non-empty set in which every known result is fresh, valid, and successful is `up`;
4. a non-empty set in which every known result has an expired valid timestamp is `stale`;
5. every other case is `unknown`, including a single failure below the configured quorum.

The whole Check is `down` if any scenario/variant part is down, otherwise `degraded` if any part is
degraded, `up` only when every part is up, `stale` only when every part is stale, and `unknown`
otherwise. An empty set is never up. `sources_total` counts distinct known logical sources;
`sources_up` counts sources whose every known result is fresh and successful. List latency is the
maximum available duration among fresh successful results, not an average. `last_checked_at`,
`oldest_checked_at`, `stale_results`, and `data_incomplete` make age and partial evidence explicit.

List filters (`status`, `group`, `source`, `target`, `scenario`, and bounded `search`) are combined
with AND. A source filter selects complete Checks but never recomputes their status from a subset.
Summary applies the same filters and counts Checks, not samples; its five status counts sum to
`total`. Results use stable ordering with `check_id` as the final key. The default list page is 50
Checks and the maximum is 200.

An active alert relates to a Check only by exact `check_id` inside the same authorization scope.
This relationship does not change the Check status or create an incident. If alert lookup fails,
`active_alerts` is `null`, not zero; an unavailable Prometheus refresh cannot turn into a false
detail `404`.

### Cache, errors, and limits

All seven fixed metric queries across all enabled datasources use one evaluation time and one
coalesced process-local refresh. The default cache TTL is five seconds and cannot be configured
above five seconds. Measurement age is recalculated on every response, including cache hits. A
refresh never combines required status from one snapshot with a timestamp from another.

During a refresh, an expired prior snapshot may be exposed only as `data_state: stale`; its original
values belong in explicitly marked last-known data, not the current summary. If either required
query fails, current statuses become `unknown`, `data_state` becomes `unavailable`, and the API
returns `503` even when a previously successful cache exists. When no reliable inventory remains,
summary is `null`, not a zero summary. Failure of an optional query produces a bounded warning and
removes that capability without invalidating the required results. Client responses contain safe
codes such as `prometheus_unavailable` or `checks_limit_exceeded`, never upstream bodies, URLs, or
raw error text.

| Limit                                           | Default / bound                                                     |
| ----------------------------------------------- | ------------------------------------------------------------------- |
| Checks samples across all 7 queries/datasources | 5,000 total (`CHECKS_MAX_SERIES`, allowed range 1–100,000)          |
| Samples in one Prometheus vector response       | 10,000 (`PROMETHEUS_MAX_SAMPLES`)                                   |
| One Prometheus HTTP response                    | 2 MiB (`PROMETHEUS_MAX_RESPONSE_BYTES`)                             |
| Prometheus query timeout                        | 8 seconds (`PROMETHEUS_QUERY_TIMEOUT_SECONDS`)                      |
| Checks cache TTL                                | 5 seconds (`CHECKS_CACHE_TTL_SECONDS`, allowed range 0.1–5)         |
| Future timestamp tolerance                      | 30 seconds (`CHECKS_FUTURE_TOLERANCE_SECONDS`, allowed range 0–300) |
| List page                                       | 50 by default, 200 maximum                                          |
| Results within one Check                        | 1,000 maximum; excess fails the refresh                             |
| Canary entries within one result                | 100 maximum; excess fails the refresh                               |
| Encoded Checks API response                     | 2 MiB maximum; excess returns `checks_limit_exceeded`               |
| Related alerts/incidents or reverse Check links | 200 items per detail response; totals and truncation are explicit   |

`CHECKS_MAX_SERIES` also bounds the retained in-memory registry. Exceeding the Checks total or an
upstream sample/body, per-Check nesting, or final API body limit returns
`checks_limit_exceeded`; Alert Hub does not truncate and compute a deceptively healthy summary.
Keep Prometheus cardinality below both the per-response and combined limits, and alert on repeated
unavailable/limit responses.

The production settings are:

```dotenv
CHECKS_ENABLED=false
CHECKS_STALE_AFTER_SECONDS=180
CHECKS_MIN_FAILURE_SOURCES=1
CHECKS_GRAFANA_BASE_URL=
CHECKS_CACHE_TTL_SECONDS=5
CHECKS_FUTURE_TOLERANCE_SECONDS=30
CHECKS_MAX_SERIES=5000
```

`CHECKS_STALE_AFTER_SECONDS` accepts 1–86,400 seconds and
`CHECKS_MIN_FAILURE_SOURCES` accepts 1–1,000. `CHECKS_GRAFANA_BASE_URL` is an optional
administrator-defined absolute HTTP(S) dashboard URL without userinfo. HTTPS is the default;
internal HTTP works only with the separately reviewed `ALLOW_HTTP_MONITORING_URLS=true` setting.
Invalid or disallowed values disable only the link and produce a safe diagnostic. The backend
constructs the deep link with an encoded `var-check_id`; labels and browser parameters cannot
change its scheme, authority, or path. No Grafana setting is required for Checks to work.

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

An allowlisted request that reaches the application with a missing or invalid cluster bearer is
intentionally written to the audit log before returning `401`. One bounded negative probe is enough
for each reviewed path; do not use an unauthenticated retry loop for boundary verification.

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

## Web Push registration and test

A browser subscription and a delivery route are separate resources. Complete this sequence for
each device that should receive alerts:

1. In **Channels**, create and enable a `Web Push` channel.
2. Create an enabled route whose incident filters include that channel. An empty filter matches
   every source/severity; tighten it only after the broad test works.
3. On desktop, open Alert Hub through HTTPS. On iPhone or iPad 16.4 or newer, open the site in
   Safari, use **Share → Add to Home Screen**, then launch and sign in from the installed icon.
4. Select **Enable alerts** and accept the browser/system permission prompt. The UI registers the
   root service worker, fetches the node's public VAPID key, replaces an old browser subscription
   when that key changed, and binds the new endpoint to the current authenticated session.
5. In **Channels**, select **Send test** on the Web Push channel. Success requires a visible
   notification, not only an HTTP success message. Then test one real firing event, its resolved
   event, and the notification deep link while the app is closed.

Upgrades from a version that created Web Push subscriptions without a browser-session binding
disable those legacy endpoints. Each affected browser must select **Enable alerts** again; this is
intentional so a signed-out or lost device cannot retain notification access after migration.

Permission `denied` is a device setting and cannot be reset by the site. On macOS Safari use
**Safari → Settings → Websites → Notifications**. In Chromium/Firefox use the site-permissions
control beside the address bar. On iOS/iPadOS use **Settings → Notifications → Alert Hub** for the
installed app. Reload or reopen the app after allowing it, then repeat registration.

Troubleshoot in this order:

- `curl -sS -D - -o /dev/null https://alerts.example.com/sw.js` must return JavaScript from the
  same origin. Because the worker lives at `/sw.js`, `Service-Worker-Allowed` is unnecessary; if
  an edge adds it, there must be exactly one valid `/` value, never a combined `/, /` value.
- A VAPID-key error before subscription means the serving API node cannot load or validate its
  sender key. All delivery nodes must use the same unencrypted P-256 private key; omit the public
  override unless it is the matching canonical public point.
- A subscription error after permission was granted is reported with the API/DOM failure instead
  of a green status. Check HTTPS, service-worker registration, API readiness, egress DNS and TCP
  `443`, then retry.
- A channel test reports sanitized provider status/error codes. `subscription_gone` requires
  registering that browser again; provider `401`/`403` usually indicates VAPID configuration or
  subject policy; timeout/transport failures require checking node egress.
- Device/session revocation and logout disable every server-side Push endpoint bound to that
  session. A later sign-in must register again before delivery resumes.

VAPID rotation intentionally invalidates existing provider subscriptions. Roll the same key to
every delivery node, then re-register each browser; do not mix old and new private keys across the
cluster.

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

Security-relevant audit covers authentication, source/channel changes, token rotations, session
revocation, failed peer authorization, and deployment-relevant actions. The current application
audit is append-only and local to the node serving the request; it is not replicated cluster
history. The UI may group identical events from a short burst for readability, while its JSONL
export retains every loaded row. Deployment manifests/history are host evidence; they do not
replace the application audit log.

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

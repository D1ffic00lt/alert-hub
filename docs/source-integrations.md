# Source integrations

Sources are configured through the authenticated UI/API and receive a random bearer token exactly once. Alert Hub stores only a keyed hash. Losing the token requires rotation; it cannot be read back from SQLite.

The repository implements Alertmanager, normalized generic JSON, and heartbeat intake, plus
backend-owned named Prometheus datasource queries for regional reachability and the always-present
read-only Checks model. Administrators may select validated `job` globs for the two `up` summaries,
but Grafana-specific payload adapters and arbitrary browser-authored PromQL are not implemented.
Source adapters never execute source-provided code or interpolation expressions. SMTP notification
templates are a separate allowlisted-placeholder feature described in
[operations](operations.md#smtp-notification-templates).

## UI quick start

Sign in, open **Sources**, and choose **Add source**. The wizard supports Alertmanager, Generic
JSON, and Heartbeat. Give the source a stable name and optional nearest region. Alertmanager and
Generic JSON can also be restricted to comma- or newline-separated sender IPs/CIDRs; leave this
empty until the real proxy/source address has been verified. Heartbeat interval, grace period,
severity, and stable labels are configured in the same wizard.

After **Create source**, copy the bearer token, absolute webhook URL, and generated example before
closing the dialog. The token is shown only once. **Send test event** proves the authenticated
management path and incident projection, but it deliberately does not exercise the source bearer,
public ingress, sender CIDR, or external system. Complete setup with one real request from the
sender. Rotating a source token invalidates the previous token immediately.

Generated webhook URLs use `PUBLIC_INGEST_URL` when it is configured. Keep this
stable ingress origin separate from per-node `NODE_PUBLIC_API_URL` values used
for browser failover; changing the active browser API must not rewrite source
configuration. `PUBLIC_API_URL` remains the compatibility fallback for existing
installations that have not split those origins yet.

Prometheus is not an event source in this menu. Add it under **Regional reachability → Add
datasource**; Alert Hub runs only its named backend-owned queries. Set the Grafana link and the
allowed `job` globs under **Settings → Grafana and job selection**. Grafana webhook payloads are not
accepted directly.

## Common rules

- Send HTTPS to the public source URL or private HTTPS where appropriate.
- Keep the bearer token in the sender's secret storage and redact request headers.
- Maximum request body defaults to 1 MiB.
- Timestamps are normalized to UTC.
- Severity becomes `info`, `warning`, `critical`, or `unknown`.
- Unknown labels/annotations are preserved as structured data.
- A repeated event key returns success without a second timeline event.
- Stable labels belong in deduplication; volatile labels such as instance restart counters should not.

Each source accepts an optional top-level `allowed_cidrs` array through create/update API calls. Host addresses are canonicalized to networks (`203.0.113.42/24` becomes `203.0.113.0/24`), duplicates are removed, and invalid entries return `422`. An empty array means no application CIDR restriction. A denied address receives the same `401 Invalid source credentials` response as a bad source ID/token, so the policy is not an authentication oracle.

CIDR checks use the application's canonical client-IP resolver. Forwarding headers are considered only when the immediate peer is in `TRUSTED_PROXY_CIDRS`, and the chain is walked right-to-left across explicitly trusted proxies. Configure the actual proxy/Docker-gateway chain before enabling a source allowlist; otherwise the application intentionally sees the first untrusted proxy address and may deny the sender. Keep the firewall/reverse-proxy allowlist as a separate layer.

Example create fragment:

```json
{
  "name": "production-alertmanager",
  "kind": "alertmanager",
  "allowed_cidrs": ["203.0.113.0/28", "2001:db8:1234::/64"]
}
```

Login, bootstrap, and ingest limits are bounded and enforced before password hashing or payload parsing. The ingest budget is keyed by resolved client IP across source IDs, so changing a nonexistent source ID does not reset it. Limits are deliberately local to each node; they do not provide a cluster-wide account lockout or global sender quota.

## Alertmanager

Create an `alertmanager` source. Copy the source ID, one-time bearer token, and generated URL. Add a dedicated receiver without replacing unrelated routes:

```yaml
receivers:
  - name: alert-hub
    webhook_configs:
      - url: https://alerts.example.com/ingest/v1/alertmanager/SOURCE_ID
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials: SOURCE_TOKEN
```

For rule trees that emit both a global outage and per-probe/per-endpoint alerts,
inhibit the child alerts while the global alert is active. This preserves the
detailed series in Prometheus while preventing one node failure from producing
one notification per probe and port:

```yaml
inhibit_rules:
  - source_matchers:
      - 'alertname="VlessServerDownGlobally"'
    target_matchers:
      - 'alertname=~"VlessEndpointUnreachable|VlessServerUnreachableFromSource"'
    equal:
      - target_server
  - source_matchers:
      - 'alertname="SyntheticCheckFleetDegraded"'
    target_matchers:
      - 'alertname=~"SyntheticCheckUnreachableFromInstance|SyntheticCheckUnavailableFromMultipleInstances|SyntheticCheckExecutionError|SyntheticEgressMismatch|SyntheticEgressAssertionUnavailable"'
```

Inhibition alone does not cover the complete correlated-alert lifecycle. A
child can finish the root route's initial wait before its aggregate starts
firing, and a still-firing child is eligible for delivery as soon as its
aggregate resolves. More importantly, Alertmanager 0.32.1 applies inhibition
before notification deduplication. If a child was delivered before its
aggregate existed and later resolves while inhibited, the primary receiver may
never receive that recovery. This is the upstream
[inhibited recovery gap](https://github.com/prometheus/alertmanager/issues/5247).

Protect activation and recovery independently:

1. Give every route that matches an inhibition target a child-specific
   `group_wait`. With a 30-second aggregate activation lag and a 30-second rule
   evaluation interval, use a `75s` child `group_wait` (60 seconds plus a
   15-second delivery margin). Keep the shorter root wait for aggregate and
   unrelated alerts. Merge these settings into the first existing matching
   child route; Alertmanager stops at the first matching sibling unless
   `continue` is enabled.

   ```yaml
   route:
     receiver: alert-hub
     group_wait: 20s
     group_interval: 2m
     repeat_interval: 4h
     routes:
       - receiver: alert-hub
         matchers:
           - 'alertname=~"VlessEndpointUnreachable|VlessServerUnreachableFromSource"'
         group_wait: 75s
       - receiver: alert-hub
         matchers:
           - 'alertname=~"SyntheticCheckUnreachableFromInstance|SyntheticCheckUnavailableFromMultipleInstances|SyntheticCheckExecutionError|SyntheticEgressMismatch|SyntheticEgressAssertionUnavailable"'
         group_wait: 75s
   ```

   Keep each route matcher identical to the corresponding inhibition target
   matcher so newly protected children receive the same activation buffer. Do
   not broaden a matcher to the aggregate itself. If the measured aggregate
   activation lag plus one full evaluation interval can exceed 60 seconds,
   increase the child wait by the same amount. One or two isolated child
   failures still notify after this bounded wait because no aggregate inhibits
   them.

2. Add a `5m` `keep_firing_for` hold to each aggregate Prometheus rule. Keep
   its existing expression, `for`, labels, and annotations unchanged:

   ```yaml
   # Fragment of the existing aggregate rules; retain the other fields.
   - alert: VlessServerDownGlobally
     keep_firing_for: 5m
   - alert: SyntheticCheckFleetDegraded
     keep_firing_for: 5m
   ```

   The hold starts when the aggregate expression stops matching. It keeps the
   inhibitor present while correlated children finish their own recovery, but
   it does not change the synthetic quorum or the child expressions. Size the
   hold above the longest expected child cleanup lag plus one evaluation
   interval. A child that remains broken beyond the bounded hold becomes
   independently notifiable instead of being hidden forever. The hold prevents
   a recovery-time child burst; it does not fix the inhibited recovery gap.

3. Run one small recovery-shadow Alertmanager beside each primary
   Alertmanager. Prometheus must send the same rule stream to both instances.
   The shadow has no inhibition rules and sends its webhook stream to the
   recovery-only URL on the same node-local Alert Hub destination used by the
   primary:

   ```yaml
   # Prometheus fragment. Preserve the installation's TLS/auth settings.
   alerting:
     alertmanagers:
       - static_configs:
           - targets: ["primary-alertmanager:9093"]
       - static_configs:
           - targets: ["recovery-alertmanager:9093"]
   ```

   ```yaml
   # recovery-alertmanager.yml: intentionally no inhibit_rules.
   route:
     receiver: alert-hub-recoveries
     group_by: ["..."]
     group_wait: 0s
     group_interval: 30s
     repeat_interval: 4h

   receivers:
     - name: alert-hub-recoveries
       webhook_configs:
         - url: https://alerts.example.com/ingest/v1/alertmanager/SOURCE_ID/recoveries
           send_resolved: true
           http_config:
             authorization:
               type: Bearer
               credentials: SOURCE_TOKEN
   ```

   The recovery ingress authenticates with the same source token. It returns
   success while ignoring every firing alert and every resolution for which
   that Alert Hub node has no incident. It accepts only resolutions for an
   existing open, acknowledged, or silenced incident. Retries are idempotent.
   Consequently, a child suppressed for its entire lifetime does not appear in
   Alert Hub, while a child delivered before inhibition cannot remain open
   forever. Point both receivers at the same node-local Alert Hub destination;
   the intentional orphan filter is not a cross-node ordering mechanism.

   Keep the shadow private, give it a durable notification-log volume, and
   monitor it like the primary. It is not an HA peer of the primary and must not
   share the primary's inhibition configuration.

Keep the detailed child rules loaded. Inhibition affects notification delivery,
not the Prometheus alert series: inhibited children must remain queryable with
`ALERTS{alertstate="firing"}` and visible in Grafana. Apply the Alertmanager
child-route buffer before reloading the Prometheus aggregate hold, then exercise
these cases against a non-production receiver:

| Exercise                                                                      | Expected webhook result                                                        |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Child fires about 30 seconds before its aggregate                             | Aggregate only; the child is inhibited before 75 seconds elapse                |
| Aggregate condition clears while a child remains firing for up to two minutes | No recovery-time child burst; the aggregate remains firing during cleanup      |
| One or two isolated child alerts fire without the aggregate                   | Each child is delivered after the 75-second wait                               |
| Delivered child resolves after its aggregate starts inhibiting it             | Primary omits recovery; recovery shadow closes the existing Alert Hub incident |
| Child is inhibited for its entire firing lifetime                             | Recovery ingress ignores both shadow firing and orphan resolution              |
| A child is inspected while inhibited                                          | Its firing series remains in Prometheus and Grafana                            |

Keep `send_resolved: true` when Alert Hub is the incident state owner. Turning it
off hides recovery from Alert Hub rather than merely silencing recovery pushes.
Use inhibition at the primary Alertmanager, the uninhibited recovery shadow,
and notification routing in Alert Hub together to control fan-out without
leaving incidents permanently open.

Route only the intended alert tree, then validate both configurations before
reload:

```bash
amtool check-config /path/to/alertmanager.yml
amtool check-config /path/to/recovery-alertmanager.yml
promtool check rules /path/to/alert-rules.yml
```

Alertmanager groups alerts in `alerts[]`; each item is normalized separately. The adapter prefers Alertmanager's `fingerprint`. If absent, it generates a stable key from sorted labels. `summary`/`title` becomes the title, `description`/`message` becomes the description, and unknown labels/annotations remain available in the incident.

During verification, exercise the exact lifecycle rather than only validating
durations: deliver a child through the primary, start its aggregate, resolve
the child while the primary reports it inhibited, and confirm that the
recovery shadow produces a firing→resolved Alert Hub timeline. Also prove that
an inhibited child which was never delivered creates no incident. Do not route
all production alerts until both cases pass.

## Generic JSON

Create a `generic_json` source and send schema version 1:

```bash
curl --fail --silent --show-error \
  -H 'Authorization: Bearer SOURCE_TOKEN' \
  -H 'Content-Type: application/json' \
  --data-binary @event.json \
  https://alerts.example.com/ingest/v1/events/SOURCE_ID
```

```json
{
  "schema_version": 1,
  "external_event_id": "monitor-0189",
  "dedup_key": "vless:nl-1:unreachable",
  "status": "firing",
  "title": "Endpoint unreachable",
  "description": "nl-1 is unreachable from ru-1",
  "severity": "critical",
  "starts_at": "2026-09-01T12:00:00Z",
  "ends_at": null,
  "labels": {
    "source_region": "ru",
    "target_region": "eu",
    "target_name": "nl-1"
  },
  "annotations": {},
  "source_url": "https://grafana.example.com/d/example"
}
```

`dedup_key` is required; `status` must be `firing` or `resolved`. A retry must repeat the same
normalized event identity, including the same `external_event_id`, `starts_at`, status, and event
content; `external_event_id` alone does not override changed fields. Always send an explicit stable
`starts_at` instead of relying on the receive-time default. A new firing occurrence needs a new
external event identity and `starts_at` while keeping the logical dedup key. Its resolved event
keeps that occurrence's `dedup_key` and original `starts_at` so a delayed resolution cannot close a
newer occurrence. The generated curl uses a fixed smoke identity and timestamp, so repeating it is
also a quick idempotency check; use the full schema above for a real sender.

The response reports accepted and duplicate counts plus incident IDs. Treat any 2xx duplicate response as successful delivery. Retry transient failure with bounded exponential backoff and jitter; do not retry permanent `401`, `413`, or schema `422` without correcting the request.

## Heartbeat

Create a `heartbeat` source with interval, grace period, severity, and stable labels in its config.
The management API also accepts an optional custom title; the current UI uses
`Heartbeat missed: <source name>`. Send an authenticated POST on schedule; the body may be empty:

```bash
curl --fail --silent --show-error -X POST \
  --connect-timeout 5 --max-time 10 \
  -H 'Authorization: Bearer SOURCE_TOKEN' \
  https://alerts.example.com/ingest/v1/heartbeat/SOURCE_ID
```

The missed-heartbeat window starts when the source is created, so schedule the real sender
immediately rather than creating it before the cron job/systemd timer is ready.

Each accepted request appends a `heartbeat_observation` to cluster history and projects its receive
time locally. Connected peers replicate that observation and keep the maximum known receive time
for the same replicated source. An evaluator on any node creates a firing incident after
`interval + grace`; a newer observation resolves the missed-heartbeat incident. Projection is
tested for both arrival orders, including a recovery observation arriving before an older firing
event. Invalid legacy/replicated heartbeat windows are skipped and counted rather than stopping
evaluation of other sources.

Use one replicated heartbeat source identity and credential across connected nodes. Send to a
stable health-checked ingress name or explicitly fail over between its node URLs; do not create a
different source per node unless independent liveness incidents are intentional. During a true
partition a side that cannot observe the heartbeat may still fire and later converge to resolved,
which preserves the availability-first design. Monitor the sender itself: a cron job that never ran
cannot report its own curl failure. Use a timeout and alert locally on repeated non-2xx responses.

## Prometheus and regional reachability

Alert Hub's `/metrics` endpoint is available for Prometheus scraping through loopback/private
operator paths; the supplied public proxy examples deny it. Administrators manage backend
datasources through `/api/v1/prometheus-datasources`. Credentials support `none`, bearer, and basic
modes and are stored only as AES-GCM envelopes. Responses expose the auth mode and configured field
names, never credential values.

The backend exposes only named queries and never accepts browser-authored PromQL. Defaults are:

```promql
probe_success
ALERTS{alertstate="firing"}
up{job=~"prometheus|alertmanager|blackbox.*"}
up{job=~"alert[-_]?hub.*"}
```

An administrator can replace the two default `job` selectors with comma-separated glob patterns
such as `vless_blackbox_*` or `alert-hub-api-*`. Patterns accept only bounded job-label characters
and `*`; the backend escapes them and constructs the `up{job=~...}` selector. The browser cannot
provide metric names, operators, functions, or other PromQL syntax.

`GET /api/v1/metrics/reachability` merges the latest `probe_success` samples using the label pair selected on each datasource. The default `canonical` mode reads `source_region` and `target_name`; its fixed query requires both labels to be non-empty. An explicit `server` mode reads and requires non-empty `source_server` and `target_server` for existing installations that retain geographic `source_region` grouping for Grafana. Each datasource gets the fixed selector for its own mode, so unrelated Blackbox/TLS `probe_success` series do not enter reachability validation. Modes never fall back into one another, and a malformed sample that still reaches the selected dataset remains a visible datasource error. It returns `partial` with per-datasource errors when some Prometheus instances fail. `GET /api/v1/metrics/queries/{query_name}` exposes the other fixed vectors, and `POST /api/v1/prometheus-datasources/{id}/test` uses a fixed `vector(1)` probe.

Set the optional Grafana HTTPS dashboard link under **Settings** when operators should get a
detailed-view link. `GRAFANA_URL` remains an initial fallback for installations that configure it
before a cluster setting has been saved.
The backend requires a concrete `/d/<uid>[/slug]` or `d-solo` view for new values, rejects embedded
credentials, and returns it in the authenticated
`GET /api/v1/metrics/summary` response. Alert Hub does not proxy Grafana or turn that link into an
arbitrary-query surface.

`GET /api/v1/metrics/statistics` supplies the overview's bounded operational-history block. The
server accepts only the fixed windows `24h`, `7d`, and `30d`; it builds incident cohorts from the
append-only `IncidentEvent` lifecycle and delivery-attempt outcomes from original replicated
`ClusterEvent` receipt history. Historical counts and durations come from those append-only events.
Current active counters use the mutable incident projection; missing event metadata falls back to
the current incident, while source and channel display fields use current configuration. The
response includes fixed buckets, current incident totals, response/resolution durations, severity
and source counts, and per-channel delivery outcomes. Source and channel rankings are limited to the
five most active entries. It is an eventually consistent view of the node's replicated Alert Hub
history, not a cluster quorum read. During a partition, another node can temporarily show a
different newest bucket without preventing local reads or actions.
Composite temporal indexes restrict both history scans to the selected window, and rows are consumed
in bounded batches. A request fails with `503` rather than returning partial statistics when a
window contains more than 100,000 lifecycle events, 20,000 incidents with lifecycle activity, or
100,000 delivery receipts; select a shorter window or reduce event volume before retrying. Each
application process keeps completed snapshots fresh for 30 seconds and may serve one for at most 60
seconds while another request refreshes it or a refresh fails. Refresh followers never wait for an
in-progress refresh. Worker processes refresh independently, so this does not introduce a shared
coordinator.

HTTPS and public addresses are required by default. Set `ALLOW_HTTP_MONITORING_URLS=true` and `ALLOW_PRIVATE_MONITORING_URLS=true` only for an intentional private HTTP monitoring network. Requests use finite connect/read/write/pool and query timeouts, reject redirects, cap response bytes/samples, ignore proxy environment variables, and repeat DNS/address validation immediately before sending. Keep an egress firewall allowlist because application checks cannot eliminate every DNS race.

Alert Hub does not copy complete Prometheus time-series into SQLite. The statistics block aggregates
Alert Hub's own append-only incident and delivery history; detailed infrastructure series remain in
Prometheus and Grafana. Automated coverage uses mocked Prometheus responses; configure and test the
actual regional topology separately.

Join the application to an existing monitoring Docker network only with the optional Compose overlay, or use an explicitly allowed private URL. Never recreate the monitoring stack and never make Prometheus public to simplify integration.

## Checks metric integration

Checks is not another webhook source and does not appear in the Sources wizard. An external,
operator-managed executor publishes the fixed `synthetic_check_*` gauges to Prometheus; Alert Hub
queries all enabled Prometheus datasources at one evaluation time and normalizes their results.
There is no Checks-specific scheduler, executor configuration, executor credential store,
subscription importer, or prober inside Alert Hub. Removing every Checks metric produces an empty
Checks view; that state and omitting Grafana must not affect event intake or incident handling.

For a minimal result, publish exactly one stable public identifier on both required metrics:

```prometheus
synthetic_check_status{check_id="billing-smoke"} 1
synthetic_check_last_run_timestamp_seconds{check_id="billing-smoke"} 1788609600
```

For independent observations, add stable logical `source` values to the same Check rather than
encoding scrape endpoints or infrastructure addresses:

```prometheus
synthetic_check_info{check_id="billing-smoke",check_name="Billing smoke",group="customer-paths",source="edge-a",target="Primary billing",scenario="invoice",variant="standard"} 1
synthetic_check_info{check_id="billing-smoke",check_name="Billing smoke",group="customer-paths",source="edge-b",target="Primary billing",scenario="invoice",variant="standard"} 1
synthetic_check_status{check_id="billing-smoke",source="edge-a",scenario="invoice",variant="standard"} 1
synthetic_check_status{check_id="billing-smoke",source="edge-b",scenario="invoice",variant="standard"} 0
synthetic_check_last_run_timestamp_seconds{check_id="billing-smoke",source="edge-a",scenario="invoice",variant="standard"} 1788609600
synthetic_check_last_run_timestamp_seconds{check_id="billing-smoke",source="edge-b",scenario="invoice",variant="standard"} 1788609598
```

The names in these examples are safe aliases and the timestamps are fixed documentation values;
they are never injected as authenticated UI fallback data. Do not publish real URLs, IP addresses,
tenant/account names, tokens, credentials, protocol identifiers, or subscription data in any Check
label. Replicas of one executor location use the same logical `source`. In the minimal contract,
missing `source` means one private default source and is never inferred from Prometheus scrape
`instance` or `job`. In the richer xray-e2e-prober contract, the explicitly exported `instance_id`
identifies the concrete prober process while `source` or `source_id` identifies its logical Source.
Distinct instance IDs never collapse, but several Instances of one Source do not add independent
quorum votes. Its info metadata is joined to state/status/last-run/target/assertion series before
`mode` and `target_set_id` become Scenario and Variant. `entry_name` is the safe display-name
fallback. Keep `check_id` unique across all enabled datasources. Publish `synthetic_check_info` for
expected tuples so a never-run or vanished result remains observable; previously seen missing
Instances remain visible in the bounded in-memory inventory, but restart still loses inventory that
no longer exists in Prometheus.

The richer projection also supports one-hot `synthetic_check_state`, target-specific
`synthetic_check_target_success`/`synthetic_check_target_state` plus duration/TTFB, separate
`synthetic_check_egress_state`/`synthetic_check_egress_match` rows per `assertion_id`, and the
cumulative allowlisted `synthetic_check_errors_total{reason}` diagnostics. Alert Hub never returns
observed/expected egress addresses or free-form executor error text.

When the executor uses other metric names, translate them before Alert Hub with reviewed recording
rules or executor configuration. Alert Hub does not accept a metric name or PromQL from the browser.
See [Checks operations](operations.md#checks) for the complete metric contract, aggregation order,
cache/error behavior, settings, and cardinality limits.

To relate an existing alert or incident, add the same safe `check_id` label to the alerting rule.
Alert Hub links only an exact match inside the caller's existing authorization scope. A Check status
does not create an incident, an alert without `check_id` is unchanged, and an active incident does
not force a recovered Check to remain down.

## Adding a future adapter

A source adapter must map external input to the normalized event contract, preserve unknown safe fields, define a stable dedup strategy, validate payload size/types/time, redact credentials, and include unit fixtures plus retry/idempotency integration tests. Keep vendor parsing in `infrastructure/sources`; do not leak it into incident domain logic.

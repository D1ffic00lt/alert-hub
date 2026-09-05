# Source integrations

Sources are configured through the authenticated UI/API and receive a random bearer token exactly once. Alert Hub stores only a keyed hash. Losing the token requires rotation; it cannot be read back from SQLite.

The repository implements Alertmanager, normalized generic JSON, and heartbeat intake, plus
backend-owned named Prometheus datasource queries for regional reachability. Administrators may
select validated `job` globs for the two `up` summaries, but Grafana-specific payload adapters and
arbitrary browser-authored PromQL are not implemented. Source adapters never
execute source-provided code or interpolation expressions. SMTP notification templates are a
separate allowlisted-placeholder feature described in [operations](operations.md#smtp-notification-templates).

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
```

Keep `send_resolved: true` when Alert Hub is the incident state owner. Turning it
off hides recovery from Alert Hub rather than merely silencing recovery pushes.
Use inhibition at Alertmanager and notification routing in Alert Hub to control
fan-out without leaving incidents permanently open.

Route only the intended alert tree, then validate before reload:

```bash
amtool check-config /path/to/alertmanager.yml
```

Alertmanager groups alerts in `alerts[]`; each item is normalized separately. The adapter prefers Alertmanager's `fingerprint`. If absent, it generates a stable key from sorted labels. `summary`/`title` becomes the title, `description`/`message` becomes the description, and unknown labels/annotations remain available in the incident.

During verification, send one firing alert, repeat the identical webhook, then send its resolved form. Confirm a single incident, a deduplicated repeat, and a firing→resolved timeline. Do not route all production alerts until this passes.

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

`GET /api/v1/metrics/reachability` merges the latest `probe_success` samples using the label pair selected on each datasource. The default `canonical` mode reads `source_region` and `target_name`. An explicit `server` mode reads `source_server` and `target_server` for existing installations that retain geographic `source_region` grouping for Grafana. Modes never fall back into one another, so adding the compatibility option cannot silently change an existing datasource's matrix identity. It returns `partial` with per-datasource errors when some Prometheus instances fail. `GET /api/v1/metrics/queries/{query_name}` exposes the other fixed vectors, and `POST /api/v1/prometheus-datasources/{id}/test` uses a fixed `vector(1)` probe.

Set the optional Grafana HTTPS dashboard link under **Settings** when operators should get a
detailed-view link. `GRAFANA_URL` remains an initial fallback for installations that configure it
before a cluster setting has been saved.
The backend validates it, rejects embedded credentials, and returns it in the authenticated
`GET /api/v1/metrics/summary` response. Alert Hub does not proxy Grafana or turn that link into an
arbitrary-query surface.

`GET /api/v1/metrics/statistics` supplies the overview's bounded operational-history block. The
server accepts only the fixed windows `24h`, `7d`, and `30d`; it builds incident cohorts from the
append-only `IncidentEvent` lifecycle and delivery-attempt outcomes from original replicated
`ClusterEvent` receipt history. Only current active counters use the mutable incident projection.
The response includes fixed buckets, current incident totals, response/resolution durations,
severity and source counts, and per-channel delivery outcomes. Source and channel rankings are
limited to the five most active entries. It is an eventually consistent view of the node's
replicated Alert Hub history, not a cluster quorum read. During a partition, another node can
temporarily show a different newest bucket without preventing local reads or actions.
Composite temporal indexes restrict both history scans to the selected window, and rows are consumed
in bounded batches. A request fails with `503` rather than returning partial statistics when a
window contains more than 100,000 lifecycle events, 20,000 incidents with lifecycle activity, or
100,000 delivery receipts; select a shorter window or reduce event volume before retrying. Each
application process keeps completed snapshots fresh for 30 seconds and may serve one for at most 60
seconds while another request refreshes it or a refresh fails. Refresh followers never wait on an
in-process lock. Worker processes refresh independently, so this does not introduce a shared
coordinator.

HTTPS and public addresses are required by default. Set `ALLOW_HTTP_MONITORING_URLS=true` and `ALLOW_PRIVATE_MONITORING_URLS=true` only for an intentional private HTTP monitoring network. Requests use finite connect/read/write/pool and query timeouts, reject redirects, cap response bytes/samples, ignore proxy environment variables, and repeat DNS/address validation immediately before sending. Keep an egress firewall allowlist because application checks cannot eliminate every DNS race.

Alert Hub does not copy complete Prometheus time-series into SQLite. The statistics block aggregates
Alert Hub's own append-only incident and delivery history; detailed infrastructure series remain in
Prometheus and Grafana. Automated coverage uses mocked Prometheus responses; configure and test the
actual regional topology separately.

Join the application to an existing monitoring Docker network only with the optional Compose overlay, or use an explicitly allowed private URL. Never recreate the monitoring stack and never make Prometheus public to simplify integration.

## Adding a future adapter

A source adapter must map external input to the normalized event contract, preserve unknown safe fields, define a stable dedup strategy, validate payload size/types/time, redact credentials, and include unit fixtures plus retry/idempotency integration tests. Keep vendor parsing in `infrastructure/sources`; do not leak it into incident domain logic.

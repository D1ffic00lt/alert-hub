# Alert Hub MCP

Read-only MCP server that gives Codex structured Alert Hub context without opening the browser.
It queries the public `/api/v1` surface with a dedicated service token and can correlate node
readiness, cluster replication, incidents, checks, Prometheus datasource errors, fixed metric
queries, and notification queue depth.

The server intentionally has no shell, SSH, arbitrary URL, arbitrary PromQL, or mutation tool.
Codex can still use its separately configured host and repository access to propose and apply a
fix after it has established the failure from independent evidence.

## Install

Use Python 3.12 or 3.13:

```bash
python3.12 -m venv .venv
.venv/bin/pip install ./integrations/alert-hub-mcp
```

Create a time-bounded service token once with an administrator access token returned by
`POST /api/v1/auth/login`:

```http
POST /api/v1/service-tokens
Authorization: Bearer <administrator-access-token>
Content-Type: application/json

{"name":"Codex MCP","expires_in_days":90}
```

The response contains the bearer token once. Alert Hub stores only its keyed hash. Store the
returned `ahs_...` value in a local file readable only by the Codex user:

```bash
install -m 0600 /dev/null "$HOME/.config/alert-hub-mcp-token"
```

Then paste the token into that file without committing it. Its keyed hash and revocation are
cluster-replicated. The credential is read-only, revocable, and accepted only by the operational
endpoints used by this MCP server.

## Codex configuration

Single node:

```toml
[mcp_servers.alert-hub]
command = "/absolute/path/to/.venv/bin/alert-hub-mcp"

[mcp_servers.alert-hub.env]
ALERT_HUB_URL = "https://alerts.example.com"
ALERT_HUB_TOKEN_FILE = "/absolute/path/to/alert-hub-mcp-token"
```

Multiple public API nodes:

```toml
[mcp_servers.alert-hub]
command = "/absolute/path/to/.venv/bin/alert-hub-mcp"

[mcp_servers.alert-hub.env]
ALERT_HUB_NODES = "ru=https://ru-api.example.com,nl=https://nl-api.example.com"
ALERT_HUB_TOKEN_FILE = "/absolute/path/to/alert-hub-mcp-token"
```

HTTPS is mandatory by default. `ALERT_HUB_ALLOW_HTTP=true` exists only for explicit local
development. An internal CA can be supplied with `ALERT_HUB_CA_BUNDLE`. Requests have finite
timeouts, do not follow redirects or inherit proxy environment variables, and responses are
size-bounded.

## Available tools

- `diagnose_alert_hub`
- `list_configured_nodes`
- `list_incidents` and `get_incident`
- `list_checks` and `get_check`
- `get_alert_rules` and `get_availability`
- `get_cluster_status`
- `get_metrics_summary` and `get_metrics_reachability`
- `run_named_metric_query`

Incident labels, annotations, comments, and provider text are untrusted data. The diagnostic tool
marks this explicitly so text received from an alert can never be treated as an instruction to
run commands or change infrastructure.

## Development

```bash
python3.12 -m venv integrations/alert-hub-mcp/.venv
integrations/alert-hub-mcp/.venv/bin/pip install -e './integrations/alert-hub-mcp[dev]'
integrations/alert-hub-mcp/.venv/bin/ruff format --check integrations/alert-hub-mcp
integrations/alert-hub-mcp/.venv/bin/ruff check integrations/alert-hub-mcp
integrations/alert-hub-mcp/.venv/bin/mypy integrations/alert-hub-mcp/src
integrations/alert-hub-mcp/.venv/bin/pytest integrations/alert-hub-mcp
```

# Frontend API high availability

## Supported modes

`API_HA_MODE` selects one explicit routing model. It does not change peer
replication and never exposes the peer API to browsers.

| Mode              | Browser API address                       | Reserve selector              | Shell with local API down |
| ----------------- | ----------------------------------------- | ----------------------------- | ------------------------- |
| `single`          | same origin                               | none                          | guarded `503`             |
| `client-failover` | bounded HTTPS origins from runtime config | PWA endpoint manager          | available                 |
| `proxy-failover`  | same origin                               | operator Nginx/Caddy          | available                 |
| `external`        | load balancer or smart-DNS address        | external load balancer or DNS | guarded `503` by default  |

| Failure or operation               | `single`          | `client-failover`                    | `proxy-failover`                   | `external`                          |
| ---------------------------------- | ----------------- | ------------------------------------ | ---------------------------------- | ----------------------------------- |
| One API process is lost            | no                | yes, after shell load                | yes, while the gateway is healthy  | owned by the external router        |
| Selected frontend's local API lost | no                | yes                                  | yes                                | owned by the external router        |
| Complete selected frontend lost    | no                | cached PWA or alternate UI URL only  | no, unless another UI URL is known | yes, when the router removes it     |
| Cold browser start                 | healthy pair only | yes, if `PUBLIC_UI_URL` is reachable | yes, if UI/gateway is reachable    | yes, if external routing is healthy |
| Session refresh                    | local API only    | eligible API origins                 | selected proxy upstream            | healthy externally selected pair    |
| Ambiguous write outcome            | never replayed    | never replayed                       | proxy must not replay              | external router must not replay     |

No mode can make a never-loaded UI hostname reachable. Frontend-host failover
still requires external routing, multiple operator-published UI URLs, or a
previously installed service-worker shell. API HA starts after the HTML and
runtime configuration are available.

## Configuration contract

- `PUBLIC_UI_URL` is the exact HTTPS origin shown to operators and used in
  incident links. In `client-failover` it is required and is the browser Origin
  that every API node must include in `TRUSTED_ORIGINS`.
- `NODE_PUBLIC_API_URL` is the unique exact public HTTPS API origin for the
  current node. `PUBLIC_API_URL` remains a backward-compatible alias.
- `PUBLIC_INGEST_URL` is the stable exact HTTPS origin used in newly generated
  source webhook examples. It may be an external ingest load balancer or one
  deliberately selected node.
- `PRIVATE_PEER_URL` is the separate peer-sync origin. It is never inserted into
  browser runtime configuration.
- `PUBLIC_API_CANDIDATES` is a comma-separated, ordered list of at most eight
  unique exact HTTPS origins. The web entrypoint validates it and publishes it
  in the frozen, no-store `/runtime-config.js` before application code runs.
- `COOKIE_DOMAIN` is required in `client-failover` and must contain the UI and
  every API hostname. All nodes must use the same session signing key and
  compatible refresh/session state through normal Alert Hub replication.

Example values use reserved names:

```dotenv
API_HA_MODE=client-failover
PUBLIC_UI_URL=https://alerts.example.com
NODE_PUBLIC_API_URL=https://api-ru.alerts.example.com
PUBLIC_API_URL=https://api-ru.alerts.example.com
PUBLIC_INGEST_URL=https://ingest.alerts.example.com
PUBLIC_API_CANDIDATES=https://api-ru.alerts.example.com,https://api-nl.alerts.example.com,https://api-de.alerts.example.com
PRIVATE_PEER_URL=https://peer-ru.alerts.example.com
TRUSTED_ORIGINS=https://alerts.example.com
COOKIE_SECURE=true
COOKIE_DOMAIN=alerts.example.com
```

Give every node the same UI origin, candidate list, cookie domain, and signing
material; change only `NODE_PUBLIC_API_URL` and `PRIVATE_PEER_URL`. Never put
credentials, tokens, query strings, paths, wildcard origins, private listener
addresses, or peer URLs in `PUBLIC_API_CANDIDATES`.

## Client behavior

The endpoint manager is enabled by default. At cold start it shares one bounded
probe burst across concurrent callers, probes only shallow `/health/ready`, and
prefers the current healthy endpoint. Each read/refresh attempt and health probe
has a finite timeout. Network errors, timeouts, and `5xx` responses place an
endpoint in exponential backoff and allow a safe `GET` or `HEAD` to move to the
next candidate. Concurrent failures share one recovery probe instead of each
starting another probe burst. An authoritative `4xx` never triggers failover.
Visibility/focus and browser-online transitions revalidate the pool.

Login and bootstrap mutations first select a healthy endpoint, then send once.
Normal `POST`, `PATCH`, `PUT`, and `DELETE` requests are never replayed after an
ambiguous network failure. Refresh recovery is the narrow exception: it may try
another eligible API, and concurrent refresh work remains coalesced. SSE follows
the current selected endpoint after token renewal. Settings shows the mode,
active origin, aggregate health counts, health/backoff state, the last switch,
and degraded routing reason. Candidate origins are not seeded from
`localStorage`; authenticated cluster inventory may only add another validated
HTTPS origin within the same eight-entry bound. If several cluster nodes
advertise one normalized API origin, Settings reports an explicit configuration
warning instead of presenting it as node-level HA.

## Proxy and public API boundaries

For client failover, install a dedicated public API vhost on each node from:

- `deploy/proxy/nginx/alert-hub-public-api.conf.example`; or
- `deploy/proxy/caddy/Caddyfile.public-api.example`.

Those vhosts expose only `/api/v1/*`, `/ingest/v1/*`, `/health/live`, and
`/health/ready`. Their catch-all returns `404`, so `/internal/*`, metrics, deep
health, API docs, runtime assets, and the UI cannot leak through an API hostname.
Keep the existing source-allowlisted peer vhost separate.

For same-origin proxy selection, import
`deploy/proxy/nginx/alert-hub-api-failover.conf.example` or
`deploy/proxy/caddy/Caddyfile.api-failover.example` before the UI catch-all.
The upstreams are exact private/WireGuard API addresses. The Nginx fragment does
not enable `proxy_next_upstream non_idempotent`; the Caddy fragment uses active
health without a retry window, preventing automatic replay of ambiguous
mutations.

In `proxy-failover` mode the browser can diagnose only the single same-origin
gateway. Per-upstream state remains an operator-owned Nginx/Caddy health and log
surface; it cannot be inferred truthfully by the SPA without adding a new
authenticated gateway-status API. The supplied examples therefore avoid
fabricating node health in browser diagnostics.

Back up the active proxy file, render into a staged file, validate the complete
configuration with `nginx -t` or `caddy validate`, then reload. Restore the
backup if validation fails. Certificate issuance must prove each exact API DNS
name and must not modify or restart monitoring services.

## Failure exercise

Before production acceptance, capture evidence for all of the following:

1. Load the UI while the first candidate and local API are stopped.
2. Authenticate and refresh through an eligible reserve node.
3. Read incidents while stopping one and then two API nodes.
4. Submit one incident mutation while forcing an ambiguous connection failure
   and verify at most one mutation event exists.
5. Confirm each API hostname returns `404` for `/internal/v1/nodes/health`,
   `/metrics`, `/health/deep`, and API documentation.
6. Recover the preferred node and verify bounded revalidation without a request
   storm.
7. Repeat in a previously installed PWA and a fresh browser profile.

Automated endpoint-manager, renderer, container, and Playwright tests are useful
substitutes, but they do not prove real DNS, TLS, cookies, proxies, or a full
three-node outage exercise.

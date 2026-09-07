import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";
import { readFile } from "node:fs/promises";

const TEST_TOKEN_EXPIRY_SECONDS = Math.floor(Date.now() / 1000) + 60 * 60;
const TEST_VAPID_PUBLIC_KEY =
  "BHqKzvWvL4jD7SjGmLTrgV9eQYB3sE0JQF3mVZl-B4gtUJvrYJJaM7_zsY4ErX5L5E8cTDPb5i7-pwQ6S2K4h3A";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("alert-hub-ui-language", "ru");
  });
});

function token(sessionId: string) {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode({ sid: sessionId, exp: TEST_TOKEN_EXPIRY_SECONDS })}.test`;
}

async function fulfill(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

function deferredGate() {
  let release: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

type MockState = {
  applicationSettingsRequest?: Record<string, unknown> | null;
  auditPageGate?: Promise<void> | null;
  auditPageStarted?: (() => void) | null;
  auditItems?: unknown[];
  authoritativeUnauthorized: boolean;
  clusterResponseGates?: Promise<void>[];
  clusterRequestStarted?: (() => void) | null;
  clusterUnavailable?: boolean;
  clusterStatus?: unknown;
  clusterApiAlertRequests?: Array<Record<string, unknown>>;
  checksDetails?: Record<string, Record<string, unknown>>;
  checksGate?: Promise<void> | null;
  checksItems?: Array<Record<string, unknown>>;
  checksMode?: "disabled" | "ready" | "unavailable";
  checksSummarySearches?: string[];
  checksWarningCodes?: string[];
  incidentBulkRequests?: Array<Record<string, unknown>>;
  incidentDetails?: Record<string, Record<string, unknown>>;
  incidentDetailRequests?: string[];
  incidentListGate?: Promise<void> | null;
  incidentListRequests?: string[];
  incidentListStarted?: (() => void) | null;
  incidents?: Array<Record<string, unknown>>;
  lateTokenRequests: string[];
  logoutRequests: number;
  primaryUnavailable: boolean;
  refreshGate: Promise<void> | null;
  refreshRequests: number;
  refreshResponseStatuses?: number[];
  refreshStarted: (() => void) | null;
  transientUnauthorizedReads?: number;
  datasourcePatchRequest?: Record<string, unknown> | null;
  datasourceRequest?: Record<string, unknown> | null;
  sourceRequest: Record<string, unknown> | null;
  liveEventSource?: boolean;
  loginRequest?: Record<string, unknown> | null;
  metricsSummaryGate?: Promise<void> | null;
  metricsSummaryStarted?: (() => void) | null;
  pushPublicKeyStatus?: number;
  pushSubscriptionRequest?: Record<string, unknown> | null;
};

async function installApi(page: Page, state: MockState) {
  await page.addInitScript((liveEventSource) => {
    if (liveEventSource) {
      class TestEventSource {
        onopen: (() => void) | null = null;
        onmessage: (() => void) | null = null;
        onerror: (() => void) | null = null;

        constructor() {
          Object.assign(window, {
            __alertHubStreamReady: () => true,
            __emitAlertHubStreamMessage: () => this.onmessage?.(),
          });
          queueMicrotask(() => this.onopen?.());
        }

        close() {
          Object.assign(window, {
            __alertHubStreamReady: () => false,
            __emitAlertHubStreamMessage: () => undefined,
          });
        }
      }
      Object.defineProperty(window, "EventSource", {
        configurable: true,
        value: TestEventSource as unknown as typeof EventSource,
      });
    } else {
      Object.defineProperty(window, "EventSource", { configurable: true, value: undefined });
    }
    localStorage.setItem("alert-hub-api-endpoints", JSON.stringify(["https://evil.invalid"]));
  }, state.liveEventSource ?? false);

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.slice("/api/v1".length);
    const method = request.method();
    const authorization = request.headers().authorization ?? "";
    if (authorization.includes(token("late-session"))) state.lateTokenRequests.push(path);

    if (method === "POST" && path === "/auth/refresh") {
      state.refreshRequests += 1;
      const scriptedStatus = state.refreshResponseStatuses?.shift();
      if (scriptedStatus !== undefined) {
        await fulfill(
          route,
          scriptedStatus === 200
            ? {
                access_token: token("recovered-session"),
                expires_in: 900,
                user: { username: "second-admin" },
              }
            : { detail: "Transient session lookup failure" },
          scriptedStatus,
        );
        return;
      }
      if (state.refreshGate) {
        state.refreshStarted?.();
        await state.refreshGate;
        await fulfill(route, {
          access_token: token("late-session"),
          expires_in: 900,
          user: { username: "late-admin" },
        });
        return;
      }
      await fulfill(route, { detail: "No active session" }, 401);
      return;
    }
    if (method === "GET" && path === "/auth/bootstrap/status") {
      await fulfill(route, { bootstrap_required: true });
      return;
    }
    if (method === "POST" && path === "/auth/bootstrap") {
      await fulfill(route, {
        access_token: token("session-one"),
        expires_in: 900,
        user: { username: "admin" },
      });
      return;
    }
    if (method === "POST" && path === "/auth/login") {
      state.loginRequest = request.postDataJSON() as Record<string, unknown>;
      await fulfill(route, {
        access_token: token("session-two"),
        expires_in: 900,
        user: { username: "second-admin" },
      });
      return;
    }
    if (method === "GET" && path === "/push/vapid-public-key") {
      if (state.pushPublicKeyStatus && state.pushPublicKeyStatus !== 200) {
        await fulfill(
          route,
          { detail: "Web Push sender key is unavailable" },
          state.pushPublicKeyStatus,
        );
      } else {
        await fulfill(route, {
          public_key: TEST_VAPID_PUBLIC_KEY,
          vapid_public_key: TEST_VAPID_PUBLIC_KEY,
        });
      }
      return;
    }
    if (method === "POST" && path === "/push/subscriptions") {
      state.pushSubscriptionRequest = request.postDataJSON() as Record<string, unknown>;
      await fulfill(
        route,
        {
          id: "push-subscription-current",
          device_name: "MacIntel · browser",
          disabled_at: null,
        },
        201,
      );
      return;
    }
    if (method === "POST" && path === "/auth/logout") {
      state.logoutRequests += 1;
      await fulfill(route, { status: "logged_out" });
      return;
    }
    if (method === "POST" && path === "/sources") {
      state.sourceRequest = request.postDataJSON() as Record<string, unknown>;
      await fulfill(route, {
        id: "source-created",
        name: "Edge Alertmanager",
        kind: "alertmanager",
        region: "NL",
        enabled: true,
        allowed_cidrs: ["198.51.100.0/24"],
        token: "shown-once-source-token",
        webhook_url: "/ingest/v1/alertmanager/source-created",
        example:
          "receivers:\n  - name: 'Edge Alertmanager'\n    webhook_configs:\n      - url: https://YOUR_HOST/ingest/v1/alertmanager/source-created",
      });
      return;
    }
    if (method === "POST" && path === "/sources/source-created/rotate-token") {
      await fulfill(route, {
        id: "source-created",
        name: "Edge Alertmanager",
        kind: "alertmanager",
        region: "NL",
        enabled: true,
        allowed_cidrs: ["198.51.100.0/24"],
        token: "rotated-source-token",
        webhook_url: "/ingest/v1/alertmanager/source-created",
        example:
          "receivers:\n  - name: 'Edge Alertmanager'\n    webhook_configs:\n      - url: https://YOUR_HOST/ingest/v1/alertmanager/source-created",
      });
      return;
    }
    if (method === "POST" && path === "/prometheus-datasources") {
      state.datasourceRequest = request.postDataJSON() as Record<string, unknown>;
      await fulfill(
        route,
        {
          id: "prometheus-created",
          name: "Central Prometheus",
          url: "https://grafana.example.test/api/datasources/proxy/uid/prometheus",
          node_id: "ru",
          region: "RU",
          reachability_label_mode: "server",
          enabled: true,
          auth_type: "bearer",
          credentials_configured: true,
          configured_fields: ["bearer_token"],
          credentials_available: true,
        },
        201,
      );
      return;
    }
    if (method === "PATCH" && path === "/prometheus-datasources/prometheus-created") {
      state.datasourcePatchRequest = request.postDataJSON() as Record<string, unknown>;
      await fulfill(route, {
        id: "prometheus-created",
        name: "Central Prometheus",
        url: "https://grafana.example.test/api/datasources/proxy/uid/prometheus",
        node_id: "ru",
        region: "RU",
        reachability_label_mode: state.datasourcePatchRequest.reachability_label_mode,
        enabled: true,
        auth_type: "bearer",
        credentials_configured: true,
        configured_fields: ["bearer_token"],
        credentials_available: true,
      });
      return;
    }
    if (method === "PATCH" && path === "/application-settings") {
      state.applicationSettingsRequest = request.postDataJSON() as Record<string, unknown>;
      await fulfill(route, state.applicationSettingsRequest);
      return;
    }

    if ((state.transientUnauthorizedReads ?? 0) > 0 && method === "GET") {
      state.transientUnauthorizedReads = (state.transientUnauthorizedReads ?? 0) - 1;
      await fulfill(route, { detail: "transient unauthorized" }, 401);
      return;
    }
    if (state.authoritativeUnauthorized && method === "GET") {
      await fulfill(route, { detail: "session revoked" }, 401);
      return;
    }
    if (state.primaryUnavailable && method === "GET") {
      await fulfill(route, { detail: "temporarily unavailable" }, 503);
      return;
    }
    if (method === "GET" && (path === "/checks" || path.startsWith("/checks/"))) {
      const gate = state.checksGate;
      if (gate) await gate;
    }
    if (method === "GET" && (path === "/checks" || path === "/checks/summary")) {
      const checksMode = state.checksMode ?? "disabled";
      const common = {
        enabled: checksMode !== "disabled",
        data_state:
          checksMode === "disabled"
            ? "disabled"
            : checksMode === "unavailable"
              ? "unavailable"
              : "ready",
        snapshot_id: checksMode === "ready" ? "e2e-checks-snapshot" : null,
        fetched_at: checksMode === "ready" ? "2026-09-05T12:00:00Z" : null,
        evaluated_at: checksMode === "ready" ? "2026-09-05T12:00:01Z" : null,
        cache_expires_at: checksMode === "ready" ? "2026-09-05T12:00:05Z" : null,
        warning_codes: state.checksWarningCodes ?? [],
        error_code: checksMode === "unavailable" ? "prometheus_unavailable" : null,
      };
      if (checksMode === "unavailable") {
        await fulfill(
          route,
          path === "/checks"
            ? { ...common, items: [], total: 0, limit: 50, offset: 0 }
            : {
                ...common,
                total: 0,
                up: 0,
                degraded: 0,
                down: 0,
                stale: 0,
                unknown: 0,
                problem_checks: [],
              },
          503,
        );
        return;
      }
      const statusFilter = url.searchParams.get("status");
      const groupFilter = url.searchParams.get("group");
      const search = (url.searchParams.get("search") ?? "").toLowerCase();
      const filtered = (state.checksItems ?? []).filter((item) => {
        if (statusFilter && item.status !== statusFilter) return false;
        if (groupFilter && item.group !== groupFilter) return false;
        if (
          search &&
          !`${item.check_id ?? ""} ${item.name ?? ""} ${item.target ?? ""}`
            .toLowerCase()
            .includes(search)
        )
          return false;
        return true;
      });
      if (path === "/checks") {
        const limit = Number(url.searchParams.get("limit") ?? 50);
        const offset = Number(url.searchParams.get("offset") ?? 0);
        await fulfill(route, {
          ...common,
          items: filtered.slice(offset, offset + limit),
          total: filtered.length,
          limit,
          offset,
        });
        return;
      }
      state.checksSummarySearches?.push(url.search);
      const counts = Object.fromEntries(
        ["up", "degraded", "down", "stale", "unknown"].map((status) => [
          status,
          filtered.filter((item) => item.status === status).length,
        ]),
      );
      const priority = new Map([
        ["down", 0],
        ["degraded", 1],
        ["unknown", 2],
        ["stale", 3],
      ]);
      const problemChecks = filtered
        .filter((item) => item.status !== "up")
        .sort(
          (left, right) =>
            (priority.get(String(left.status)) ?? 9) - (priority.get(String(right.status)) ?? 9) ||
            String(left.check_id).localeCompare(String(right.check_id)),
        )
        .slice(0, 5);
      await fulfill(route, {
        ...common,
        total: filtered.length,
        ...counts,
        problem_checks: problemChecks,
      });
      return;
    }
    if (method === "GET" && path.startsWith("/checks/")) {
      const checksMode = state.checksMode ?? "disabled";
      const checkId = decodeURIComponent(path.slice("/checks/".length));
      const check = state.checksDetails?.[checkId] ?? null;
      const common = {
        enabled: checksMode !== "disabled",
        data_state:
          checksMode === "disabled"
            ? "disabled"
            : checksMode === "unavailable"
              ? "unavailable"
              : "ready",
        snapshot_id: checksMode === "ready" ? "e2e-checks-snapshot" : null,
        fetched_at: checksMode === "ready" ? "2026-09-05T12:00:00Z" : null,
        evaluated_at: checksMode === "ready" ? "2026-09-05T12:00:01Z" : null,
        cache_expires_at: checksMode === "ready" ? "2026-09-05T12:00:05Z" : null,
        warning_codes: state.checksWarningCodes ?? [],
        error_code: checksMode === "unavailable" ? "prometheus_unavailable" : null,
      };
      if (checksMode === "unavailable") {
        await fulfill(route, { ...common, check: null }, 503);
      } else if (checksMode === "disabled") {
        await fulfill(route, { ...common, check: null });
      } else if (!check) {
        await fulfill(route, { ...common, check: null, error_code: "check_not_found" }, 404);
      } else {
        await fulfill(route, { ...common, check });
      }
      return;
    }
    if (method === "POST" && path === "/incidents/bulk-action") {
      const body = request.postDataJSON() as Record<string, unknown>;
      state.incidentBulkRequests?.push(body);
      const action = String(body.action ?? "");
      const filters = (body.filters ?? {}) as Record<string, unknown>;
      const excluded = new Set(
        Array.isArray(body.excluded_incident_ids)
          ? body.excluded_incident_ids.map((value) => String(value))
          : [],
      );
      const matchesFilters = (incident: Record<string, unknown>) => {
        const filterStatus = String(filters.status ?? "");
        if (
          filterStatus &&
          (filterStatus === "active"
            ? incident.status === "resolved"
            : incident.status !== filterStatus)
        )
          return false;
        if (filters.severity && incident.severity !== filters.severity) return false;
        const query = String(filters.q ?? "")
          .trim()
          .toLowerCase();
        return (
          !query ||
          `${incident.title ?? ""} ${incident.description ?? ""} ${incident.source_name ?? ""}`
            .toLowerCase()
            .includes(query)
        );
      };
      const selected: Array<Record<string, unknown> | null> =
        body.selection_mode === "filter"
          ? (state.incidents ?? []).filter(
              (incident) => !excluded.has(String(incident.id)) && matchesFilters(incident),
            )
          : (Array.isArray(body.incident_ids) ? body.incident_ids : []).map(
              (incidentId) =>
                state.incidents?.find((incident) => incident.id === incidentId) ?? null,
            );
      let updated = 0;
      let unchanged = 0;
      let failed = 0;
      const nextStatus = {
        acknowledge: "acknowledged",
        resolve: "resolved",
        silence: "silenced",
      }[action];
      const requestedIds = Array.isArray(body.incident_ids) ? body.incident_ids : [];
      const results = selected.map((incident, index) => {
        if (!incident) {
          failed += 1;
          return {
            incident_id: String(requestedIds[index] ?? ""),
            outcome: "not_found",
            status: null,
            detail: "Incident not found",
          };
        }
        if (incident.status === "resolved" && nextStatus !== "resolved") {
          failed += 1;
          return {
            incident_id: incident.id,
            outcome: "conflict",
            status: "resolved",
            detail: `Resolved incident cannot be ${nextStatus}`,
          };
        }
        if (incident.status === nextStatus) {
          unchanged += 1;
          return {
            incident_id: incident.id,
            outcome: "unchanged",
            status: incident.status,
            detail: null,
          };
        }
        incident.status = nextStatus;
        updated += 1;
        return {
          incident_id: incident.id,
          outcome: "updated",
          status: nextStatus,
          detail: null,
        };
      });
      await fulfill(
        route,
        {
          action,
          selection_mode: body.selection_mode,
          matched: selected.length,
          updated,
          unchanged,
          failed,
          results,
        },
        failed ? 207 : 200,
      );
      return;
    }
    if (method === "GET" && path === "/incidents") {
      state.incidentListRequests?.push(url.search);
      state.incidentListStarted?.();
      if (state.incidentListGate) await state.incidentListGate;
      const search = String(url.searchParams.get("q") ?? "")
        .trim()
        .toLowerCase();
      const severity = url.searchParams.get("severity");
      const status = url.searchParams.get("status");
      const matchingBase = (state.incidents ?? []).filter((incident) => {
        if (severity && incident.severity !== severity) return false;
        return (
          !search ||
          `${incident.title ?? ""} ${incident.description ?? ""} ${incident.source_name ?? ""}`
            .toLowerCase()
            .includes(search)
        );
      });
      const items = matchingBase.filter((incident) =>
        status === "active"
          ? incident.status !== "resolved"
          : !status || incident.status === status,
      );
      const limit = Number(url.searchParams.get("limit") ?? 50);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const count = (incidentStatus: string) =>
        matchingBase.filter((incident) => incident.status === incidentStatus).length;
      await fulfill(route, {
        items: items.slice(offset, offset + limit),
        total: items.length,
        limit,
        offset,
        counts: {
          active: matchingBase.filter((incident) => incident.status !== "resolved").length,
          open: count("open"),
          acknowledged: count("acknowledged"),
          resolved: count("resolved"),
          silenced: count("silenced"),
          all: matchingBase.length,
        },
        bulk_limit: 500,
      });
      return;
    }
    if (method === "GET" && path.startsWith("/incidents/")) {
      const incidentId = decodeURIComponent(path.slice("/incidents/".length));
      state.incidentDetailRequests?.push(incidentId);
      const incident =
        state.incidentDetails?.[incidentId] ??
        state.incidents?.find((item) => item.id === incidentId);
      await fulfill(route, incident ?? { detail: "incident not found" }, incident ? 200 : 404);
      return;
    }
    if (method === "GET" && path === "/cluster/status") {
      const unavailable = state.clusterUnavailable;
      const payload = state.clusterStatus ?? { nodes: [], cursor: {}, cluster_event_count: 0 };
      const gate = state.clusterResponseGates?.shift();
      state.clusterRequestStarted?.();
      if (gate) await gate;
      if (unavailable) {
        await fulfill(route, { detail: "cluster telemetry unavailable" }, 503);
        return;
      }
      await fulfill(route, payload);
      return;
    }
    if (method === "PATCH" && path === "/cluster/nodes/api-down-alerts") {
      const body = request.postDataJSON() as Record<string, unknown>;
      state.clusterApiAlertRequests?.push(body);
      const requestedIds = new Set(
        Array.isArray(body.node_ids) ? body.node_ids.map((value) => String(value)) : [],
      );
      const enabled = body.enabled === true;
      const cluster = state.clusterStatus as Record<string, unknown>;
      const nodes = Array.isArray(cluster?.nodes)
        ? (cluster.nodes as Array<Record<string, unknown>>)
        : [];
      let updated = 0;
      nodes.forEach((node) => {
        if (!requestedIds.has(String(node.id))) return;
        if (node.api_down_alert_enabled !== enabled) updated += 1;
        node.api_down_alert_enabled = enabled;
      });
      await fulfill(route, {
        updated,
        unchanged: requestedIds.size - updated,
        alerts_opened: 0,
        nodes: nodes
          .filter((node) => requestedIds.has(String(node.id)))
          .map((node) => ({
            id: node.id,
            api_down_alert_enabled: node.api_down_alert_enabled,
          })),
      });
      return;
    }
    if (method === "GET" && path === "/sources") {
      const secondSession = authorization.includes(token("session-two"));
      await fulfill(route, {
        sources: secondSession
          ? [
              {
                id: "second-source",
                name: "Second-session source",
                kind: "heartbeat",
                region: "DE",
                enabled: true,
              },
            ]
          : [],
      });
      return;
    }
    if (method === "GET" && path === "/channels") {
      await fulfill(route, { channels: [] });
      return;
    }
    if (method === "GET" && path === "/routes") {
      await fulfill(route, { routes: [] });
      return;
    }
    if (method === "GET" && path === "/prometheus-datasources") {
      await fulfill(route, {
        datasources: state.datasourceRequest
          ? [
              {
                id: "prometheus-created",
                name: "Central Prometheus",
                url: "https://grafana.example.test/api/datasources/proxy/uid/prometheus",
                node_id: "ru",
                region: "RU",
                reachability_label_mode:
                  state.datasourcePatchRequest?.reachability_label_mode ?? "server",
                enabled: true,
                auth_type: "bearer",
                credentials_configured: true,
                configured_fields: ["bearer_token"],
                credentials_available: true,
              },
            ]
          : [],
      });
      return;
    }
    if (method === "GET" && path === "/devices") {
      await fulfill(route, { devices: [] });
      return;
    }
    if (method === "GET" && path === "/audit") {
      const items = state.auditItems ?? [];
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const limit = Number(url.searchParams.get("limit") ?? 100);
      if (offset > 0 && state.auditPageGate) {
        state.auditPageStarted?.();
        await state.auditPageGate;
      }
      await fulfill(route, { items: items.slice(offset, offset + limit), total: items.length });
      return;
    }
    if (method === "GET" && path === "/alert-rules") {
      await fulfill(route, {
        data_state: "partial",
        generated_at: "2026-09-07T00:00:00Z",
        totals: {
          rules: 2,
          firing_instances: 2,
          pending_instances: 1,
          unhealthy_rules: 1,
          related_incidents: 2,
        },
        rules: [
          {
            id: "rule-api-down",
            datasource_id: "prom-1",
            datasource_name: "Primary Prometheus",
            group: "platform",
            file: "platform.yml",
            name: "ApiDown",
            state: "firing",
            health: "ok",
            firing_instances: 2,
            pending_instances: 0,
            last_evaluation: "2026-09-07T00:00:00Z",
            evaluation_time_seconds: 0.012,
            last_error: null,
            related_incidents: 2,
            incidents_href: "/incidents?q=ApiDown",
          },
          {
            id: "rule-forecast",
            datasource_id: "prom-1",
            datasource_name: "Primary Prometheus",
            group: "storage",
            file: "storage.yml",
            name: "DiskForecast",
            state: "pending",
            health: "error",
            firing_instances: 0,
            pending_instances: 1,
            last_evaluation: "2026-09-07T00:00:00Z",
            evaluation_time_seconds: 0.008,
            last_error: "query evaluation failed",
            related_incidents: 0,
            incidents_href: null,
          },
        ],
        pagination: { page: 1, page_size: 25, total_items: 2, total_pages: 1 },
        errors: [
          {
            datasource_id: "prom-2",
            datasource_name: "Secondary Prometheus",
            code: "timeout",
            detail: "Prometheus request timed out",
          },
        ],
      });
      return;
    }
    if (method === "GET" && path === "/availability") {
      const window = url.searchParams.get("window") ?? "24h";
      await fulfill(route, {
        data_state: "partial",
        generated_at: "2026-09-07T00:00:00Z",
        window,
        targets: [
          {
            datasource_id: "prom-1",
            datasource_name: "Primary Prometheus",
            source: "ru",
            target: "api-core",
            observed_availability_percent: window === "24h" ? 99.98 : 99.9,
            samples_count: 100,
            last_sample_at: "2026-09-07T00:00:00Z",
            data_state: window === "7d" ? "stale" : "ok",
          },
          {
            datasource_id: "prom-1",
            datasource_name: "Primary Prometheus",
            source: "de",
            target: "portal",
            observed_availability_percent: null,
            samples_count: null,
            last_sample_at: null,
            data_state: "unknown",
          },
        ],
        errors: [],
      });
      return;
    }
    if (method === "GET" && path === "/metrics/reachability") {
      await fulfill(route, {
        status: "not_configured",
        detail: "No Prometheus datasource configured.",
        datasources: 0,
        cells: [],
        errors: [],
      });
      return;
    }
    if (method === "GET" && path === "/metrics/queries/firing_alerts") {
      await fulfill(route, {
        query: "firing_alerts",
        status: "ok",
        datasources: 1,
        samples: [],
        errors: [],
      });
      return;
    }
    if (method === "GET" && path === "/metrics/queries/key_jobs_up") {
      await fulfill(route, {
        query: "key_jobs_up",
        status: "ok",
        datasources: 1,
        samples: [
          {
            datasource_id: "prom-1",
            datasource_name: "Prometheus",
            metric: { job: "prometheus", instance: "prometheus:9090" },
            value: 1,
            timestamp: "2026-09-02T00:00:00Z",
          },
        ],
        errors: [],
      });
      return;
    }
    if (method === "GET" && path === "/metrics/queries/alert_hub_health") {
      await fulfill(route, {
        query: "alert_hub_health",
        status: "ok",
        datasources: 1,
        samples: [
          {
            datasource_id: "prom-1",
            datasource_name: "Prometheus",
            metric: { job: "alert-hub", instance: "alert-hub:8000" },
            value: 1,
            timestamp: "2026-09-02T00:00:00Z",
          },
        ],
        errors: [],
      });
      return;
    }
    if (method === "GET" && path === "/metrics/statistics") {
      await fulfill(route, {
        window: "7d",
        generated_at: "2026-09-02T12:00:00Z",
        starts_at: "2026-08-26T12:00:00Z",
        ends_at: "2026-09-02T12:00:00Z",
        bucket_seconds: 21600,
        totals: {
          incidents_started: 12,
          incidents_resolved: 9,
          active_incidents: 3,
          active_critical: 1,
          acknowledgement_rate: 83.3,
          resolution_rate: 75,
          mean_time_to_acknowledge_seconds: 540,
          mean_time_to_resolve_seconds: 4200,
          deliveries: 48,
          deliveries_succeeded: 46,
          deliveries_failed: 2,
          delivery_success_rate: 95.8,
        },
        timeline: [
          {
            starts_at: "2026-08-30T12:00:00Z",
            incidents_started: 2,
            incidents_resolved: 1,
            deliveries_succeeded: 8,
            deliveries_failed: 1,
          },
          {
            starts_at: "2026-08-31T12:00:00Z",
            incidents_started: 4,
            incidents_resolved: 3,
            deliveries_succeeded: 11,
            deliveries_failed: 0,
          },
          {
            starts_at: "2026-09-01T12:00:00Z",
            incidents_started: 3,
            incidents_resolved: 2,
            deliveries_succeeded: 14,
            deliveries_failed: 1,
          },
          {
            starts_at: "2026-09-02T06:00:00Z",
            incidents_started: 3,
            incidents_resolved: 3,
            deliveries_succeeded: 13,
            deliveries_failed: 0,
          },
        ],
        severities: [
          { severity: "critical", count: 3 },
          { severity: "warning", count: 6 },
          { severity: "info", count: 2 },
          { severity: "unknown", count: 1 },
        ],
        sources: [
          { source_id: "prometheus-eu", name: "Prometheus EU", region: "NL", count: 7 },
          { source_id: "blackbox-ru", name: "Blackbox RU", region: "RU", count: 5 },
        ],
        channels: [
          {
            channel_id: "telegram-ops",
            name: "Telegram Ops",
            kind: "telegram",
            total: 30,
            succeeded: 29,
            failed: 1,
            success_rate: 96.7,
          },
          {
            channel_id: "web-push",
            name: "Web Push",
            kind: "web_push",
            total: 18,
            succeeded: 17,
            failed: 1,
            success_rate: 94.4,
          },
        ],
      });
      return;
    }
    if (method === "GET" && path === "/metrics/summary") {
      if (state.metricsSummaryGate) {
        state.metricsSummaryStarted?.();
        await state.metricsSummaryGate;
      }
      const monitoring = state.applicationSettingsRequest ?? {};
      await fulfill(route, {
        open: 0,
        acknowledged: 0,
        critical: 0,
        deliveries_24h: 0,
        delivery_success_24h: 0,
        delivery_rate: null,
        outbox_pending: 0,
        channels_enabled: 0,
        grafana_url: Object.prototype.hasOwnProperty.call(monitoring, "grafana_url")
          ? monitoring.grafana_url
          : "https://grafana.example.test/d/alert-hub",
        key_job_globs: monitoring.key_job_globs ?? ["prometheus", "alertmanager", "blackbox*"],
        alert_hub_job_globs: monitoring.alert_hub_job_globs ?? [
          "alert-hub*",
          "alert_hub*",
          "alerthub*",
        ],
      });
      return;
    }
    await fulfill(route, { detail: `Unhandled test API ${method} ${path}` }, 404);
  });
}

async function installFakePushClient(
  page: Page,
  initialPermission: "default" | "denied" | "granted",
  staleApplicationServerKey = false,
  delaySubscription = false,
) {
  await page.addInitScript(
    ({ delaySubscribe, permission, staleKey, publicKey }) => {
      const decode = (value: string) => {
        const padding = "=".repeat((4 - (value.length % 4)) % 4);
        const decoded = atob((value + padding).replace(/-/g, "+").replace(/_/g, "/"));
        return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
      };
      const expectedKey = decode(publicKey);
      const oldKey = expectedKey.slice();
      if (staleKey) oldKey[oldKey.length - 1] ^= 1;
      let releaseSubscription: () => void = () => undefined;
      const subscriptionGate = delaySubscribe
        ? new Promise<void>((resolve) => {
            releaseSubscription = resolve;
          })
        : Promise.resolve();
      const counters = {
        permissionRequests: 0,
        subscribeCalls: 0,
        unsubscribeCalls: 0,
        releaseSubscription: () => releaseSubscription(),
      };
      const exposedWindow = window as unknown as {
        __pushTest: typeof counters;
        Notification: typeof Notification;
        PushManager: typeof PushManager;
      };
      exposedWindow.__pushTest = counters;

      class TestNotification {
        static permission: NotificationPermission = permission;

        static async requestPermission() {
          counters.permissionRequests += 1;
          return TestNotification.permission;
        }
      }
      Object.defineProperty(exposedWindow, "Notification", {
        configurable: true,
        value: TestNotification,
      });
      Object.defineProperty(exposedWindow, "PushManager", {
        configurable: true,
        value: class TestPushManager {},
      });

      type TestSubscription = {
        endpoint: string;
        options: { applicationServerKey: ArrayBuffer };
        toJSON: () => PushSubscriptionJSON;
        unsubscribe: () => Promise<boolean>;
      };
      let subscription: TestSubscription | null = null;
      const makeSubscription = (applicationServerKey: ArrayBuffer): TestSubscription => ({
        endpoint: "https://push.example.test/subscription/current",
        options: { applicationServerKey },
        toJSON: () => ({
          endpoint: "https://push.example.test/subscription/current",
          expirationTime: null,
          keys: { auth: "AQIDBAUGBwgJCgsMDQ4PEA", p256dh: publicKey },
        }),
        unsubscribe: async () => {
          counters.unsubscribeCalls += 1;
          subscription = null;
          return true;
        },
      });
      subscription = delaySubscribe ? null : makeSubscription(oldKey.buffer);
      const registration = {
        active: { postMessage: () => undefined },
        pushManager: {
          getSubscription: async () => subscription,
          subscribe: async (options: PushSubscriptionOptionsInit) => {
            counters.subscribeCalls += 1;
            await subscriptionGate;
            const key = options.applicationServerKey;
            if (typeof key === "string" || key == null || !ArrayBuffer.isView(key)) {
              throw new Error("missing application server key");
            }
            const keyBytes = new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
            subscription = makeSubscription(keyBytes.slice().buffer);
            return subscription;
          },
        },
      };
      const serviceWorker = {
        controller: null,
        getRegistration: async () => registration,
        ready: Promise.resolve(registration),
        register: async () => registration,
      };
      Object.defineProperty(navigator, "serviceWorker", {
        configurable: true,
        value: serviceWorker,
      });
    },
    {
      delaySubscribe: delaySubscription,
      permission: initialPermission,
      publicKey: TEST_VAPID_PUBLIC_KEY,
      staleKey: staleApplicationServerKey,
    },
  );
}

async function signIn(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Запуск кластера" })).toBeVisible();
  await page.getByRole("button", { name: "Войти" }).first().click();
  await page.getByLabel("Имя пользователя").fill("second-admin");
  await page.getByLabel("Пароль", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Войти" }).last().click();
  await expect(page.getByRole("heading", { name: "Состояние системы" })).toBeVisible();
}

function checksFixtures() {
  const longCheckId = `simple-check-${"very-long-segment-".repeat(6)}`;
  const common = {
    last_checked_at: "2026-09-05T12:00:00Z",
    oldest_checked_at: "2026-09-05T11:59:58Z",
    sources_total: 2,
    sources_up: 1,
    stale_results: 0,
    data_incomplete: false,
    latency_seconds: 0.42,
    scenarios: ["availability"],
    active_alerts: 0,
    diagnostic_codes: [],
  };
  const items = [
    {
      ...common,
      check_id: longCheckId,
      name: "Simple check",
      group: "basics",
      target: null,
      status: "up",
      status_reason: null,
      sources_total: 1,
      sources_up: 1,
      latency_seconds: null,
    },
    {
      ...common,
      check_id: "complex-check",
      name: "Complex customer path",
      group: "customer-paths",
      target: "Checkout",
      status: "degraded",
      status_reason: "mixed_results",
      sources_total: 1,
      sources_up: 0,
      instances_total: 3,
      instances_up: 1,
      instances_stale: 1,
      instances: [
        { instance_id: "eu-west", source: "remnawave-service", status: "up" },
        { instance_id: "us-east", source: "remnawave-service", status: "down" },
        {
          instance_id: "de-central",
          source: "remnawave-service",
          status: "stale",
          stale: true,
        },
      ],
      active_alerts: 1,
      diagnostic_codes: ["conflicting_ttfb"],
    },
    {
      ...common,
      check_id: "down-check",
      name: "Down check",
      group: "customer-paths",
      target: "Billing",
      status: "down",
      status_reason: "confirmed_failures",
      sources_up: 0,
    },
    {
      ...common,
      check_id: "stale-check",
      name: "Stale check",
      group: null,
      target: null,
      status: "stale",
      status_reason: "expired_measurements",
      stale_results: 2,
      sources_up: 0,
      latency_seconds: null,
    },
    {
      ...common,
      check_id: "unknown-check",
      name: "Unknown check",
      group: null,
      target: null,
      status: "unknown",
      status_reason: "insufficient_sources",
      sources_up: 0,
      data_incomplete: true,
      latency_seconds: null,
      active_alerts: null,
    },
  ];
  return {
    longCheckId,
    items,
    details: {
      [longCheckId]: {
        ...items[0],
        results: [
          {
            source: null,
            scenario: null,
            variant: null,
            target: null,
            status: "up",
            status_reason: null,
            state: "success",
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: null,
            ttfb_seconds: null,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: ["conflicting_ttfb", "future_executor_signal"],
            canaries: [],
            targets: [],
            assertions: [],
            error_reasons: [],
          },
        ],
        parts: [],
        related_alerts: [],
        incidents: [],
        alerts_available: true,
        related_alerts_total: 0,
        incidents_total: 0,
        relations_incomplete: false,
        relation_warning_codes: [],
        grafana_url: null,
      },
      "complex-check": {
        ...items[1],
        results: [
          {
            source: "remnawave-service",
            instance_id: "eu-west",
            scenario: "purchase",
            variant: "member",
            target: "Checkout",
            status: "up",
            status_reason: null,
            state: "success",
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0.31,
            ttfb_seconds: 0.12,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [],
            targets: [],
            assertions: [],
            error_reasons: [],
          },
          {
            source: "remnawave-service",
            instance_id: "us-east",
            scenario: "purchase",
            variant: "guest",
            target: "Checkout",
            status: "down",
            status_reason: "invalid_data",
            state: "failure",
            success: false,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0.42,
            ttfb_seconds: 0.18,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [{ canary: "control", success: true, status_reason: null }],
            targets: [
              {
                target_id: "checkout-primary",
                name: "Checkout primary",
                state: "success",
                success: true,
                duration_seconds: 0.22,
                ttfb_seconds: 0.1,
                status_reason: null,
              },
              {
                target_id: "checkout-backup",
                name: "Checkout backup",
                state: "error",
                success: null,
                duration_seconds: null,
                ttfb_seconds: null,
                status_reason: "executor_error",
              },
            ],
            assertions: [
              {
                key: "egress_match",
                name: "Expected egress",
                state: "mismatch",
                success: false,
                status_reason: null,
              },
            ],
            error_reasons: [
              { reason: "timeout", count: 3 },
              { reason: "future_reason", count: 2 },
            ],
          },
          {
            source: "remnawave-service",
            instance_id: "eu-west",
            scenario: "refund",
            variant: null,
            target: "Checkout",
            status: "up",
            status_reason: null,
            state: "success",
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0,
            ttfb_seconds: null,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [],
            targets: [],
            assertions: [],
            error_reasons: [],
          },
          {
            source: "remnawave-service",
            instance_id: "de-central",
            scenario: "purchase",
            variant: "member",
            target: "Checkout",
            status: "stale",
            status_reason: "expired_measurements",
            state: "stale",
            success: null,
            last_run_at: "2026-09-05T11:30:00Z",
            duration_seconds: null,
            ttfb_seconds: null,
            stale: true,
            data_incomplete: true,
            diagnostic_codes: ["missing_current_result"],
            canaries: [],
            targets: [],
            assertions: [],
            error_reasons: [],
          },
        ],
        parts: [],
        related_alerts: [
          {
            id: "alert-checkout",
            name: "Checkout path failed",
            severity: "critical",
            status: "firing",
            starts_at: "2026-09-05T11:58:00Z",
            last_event_at: "2026-09-05T12:00:00Z",
            resolved_at: null,
            href: "/incidents/incident-checkout",
          },
        ],
        incidents: [],
        alerts_available: true,
        related_alerts_total: 2,
        incidents_total: 3,
        relations_incomplete: true,
        relation_warning_codes: ["related_alerts_truncated", "related_incidents_truncated"],
        grafana_url: "https://grafana.example.test/d/checks?var-check_id=complex-check",
      },
    },
  };
}

test("incidents use stable skeletons and keep tab counts while a filter loads", async ({
  page,
}) => {
  const incidents = [
    {
      id: "incident-loading-active",
      title: "Loading active",
      description: "Active incident used by the loading-state regression.",
      severity: "critical",
      status: "open",
      source_name: "Prometheus",
      region: "RU",
      target: "api-one",
      starts_at: "2026-09-05T11:58:00Z",
      last_event_at: "2026-09-05T12:00:00Z",
      labels: {},
      annotations: {},
    },
    {
      id: "incident-loading-resolved",
      title: "Loading resolved",
      description: "Resolved incident used by the loading-state regression.",
      severity: "warning",
      status: "resolved",
      source_name: "Heartbeat",
      region: "DE",
      target: "api-two",
      starts_at: "2026-09-05T11:30:00Z",
      last_event_at: "2026-09-05T11:50:00Z",
      labels: {},
      annotations: {},
    },
  ];
  const state: MockState = {
    authoritativeUnauthorized: false,
    incidentListRequests: [],
    incidents,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  const firstGate = deferredGate();
  const firstStarted = deferredGate();
  state.incidentListGate = firstGate.promise;
  state.incidentListStarted = firstStarted.release;
  await page.locator(".sidebar__nav").getByRole("button", { name: "Инциденты" }).click();
  await firstStarted.promise;

  await expect(page.locator(".incidents-page-skeleton")).toBeVisible();
  await expect(page.locator(".incident-table-skeleton")).toBeVisible();
  await expect(page.locator(".hub-skeleton-count")).toHaveCount(4);
  await expect(page.getByText(/••••/)).toHaveCount(0);

  firstGate.release();
  state.incidentListGate = null;
  state.incidentListStarted = null;
  await expect(page.getByText("Loading active", { exact: true })).toBeVisible();
  const activeTab = page.locator(".incident-tabs").getByRole("button", { name: /^Активные/ });
  const resolvedTab = page.locator(".incident-tabs").getByRole("button", { name: /^Решённые/ });
  const allTab = page.locator(".incident-tabs").getByRole("button", { name: /^Все/ });
  await expect(activeTab).toContainText("1");
  await expect(resolvedTab).toContainText("1");
  await expect(allTab).toContainText("2");

  const filterGate = deferredGate();
  const filterStarted = deferredGate();
  state.incidentListGate = filterGate.promise;
  state.incidentListStarted = filterStarted.release;
  await resolvedTab.click();
  await filterStarted.promise;

  await expect(page.locator(".incident-table-skeleton")).toBeVisible();
  await expect(activeTab).toContainText("1");
  await expect(resolvedTab).toContainText("1");
  await expect(allTab).toContainText("2");
  await expect(page.getByText("Loading active", { exact: true })).toHaveCount(0);

  filterGate.release();
  state.incidentListGate = null;
  state.incidentListStarted = null;
  await expect(page.getByText("Loading resolved", { exact: true })).toBeVisible();
  await expect(page.locator(".incident-table-skeleton")).toHaveCount(0);
});

test("incidents load once without waiting for metrics and report partial bulk results", async ({
  page,
}) => {
  const metricsGate = deferredGate();
  const metricsStarted = deferredGate();
  const incidents = [
    {
      id: "incident-active-one",
      title: "Active one",
      description: "First active incident",
      severity: "critical",
      status: "open",
      source_name: "Prometheus",
      region: "RU",
      target: "api-one",
      starts_at: "2026-09-05T11:58:00Z",
      last_event_at: "2026-09-05T12:00:00Z",
      labels: {},
      annotations: {},
    },
    {
      id: "incident-resolved",
      title: "Already resolved",
      description: "Resolved incident",
      severity: "warning",
      status: "resolved",
      source_name: "Prometheus",
      region: "NL",
      target: "api-two",
      starts_at: "2026-09-05T11:30:00Z",
      last_event_at: "2026-09-05T11:50:00Z",
      labels: {},
      annotations: {},
    },
    {
      id: "incident-active-two",
      title: "Active two",
      description: "Second active incident",
      severity: "info",
      status: "open",
      source_name: "Heartbeat",
      region: "DE",
      target: "api-three",
      starts_at: "2026-09-05T10:00:00Z",
      last_event_at: "2026-09-05T10:05:00Z",
      labels: {},
      annotations: {},
    },
    ...Array.from({ length: 49 }, (_, index) => ({
      id: `incident-extra-${index}`,
      title: `Extra incident ${index}`,
      description: "Additional active incident",
      severity: "info",
      status: "open",
      source_name: "Heartbeat",
      region: "DE",
      target: `extra-${index}`,
      starts_at: "2026-09-05T09:00:00Z",
      last_event_at: "2026-09-05T09:05:00Z",
      labels: {},
      annotations: {},
    })),
  ];
  const state: MockState = {
    authoritativeUnauthorized: false,
    incidentBulkRequests: [],
    incidentListRequests: [],
    incidents,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  const requestsBeforeRoute = state.incidentListRequests?.length ?? 0;
  state.metricsSummaryGate = metricsGate.promise;
  state.metricsSummaryStarted = metricsStarted.release;
  await page.locator(".sidebar__nav").getByRole("button", { name: "Инциденты" }).click();
  await metricsStarted.promise;

  // The route owns one filtered list request and publishes it while the global
  // monitoring refresh is still blocked.
  await expect(page.getByText("Active one", { exact: true })).toBeVisible();
  expect((state.incidentListRequests?.length ?? 0) - requestsBeforeRoute).toBe(1);
  await page.waitForTimeout(100);
  expect((state.incidentListRequests?.length ?? 0) - requestsBeforeRoute).toBe(1);
  metricsGate.release();
  state.metricsSummaryGate = null;

  await page.locator(".incident-tabs").getByRole("button", { name: /^Все/ }).click();
  await expect(page.getByText("Already resolved", { exact: true })).toBeVisible();
  await page.getByLabel("Выбрать текущую страницу").check();
  await page.getByRole("button", { name: "Выбрать все 52 результатов" }).click();
  await page.getByRole("combobox", { name: "Действие", exact: true }).selectOption("acknowledge");
  await page.getByRole("button", { name: "Применить", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText(
    "Изменено: 51 · без изменений: 0 · ошибок: 1",
  );
  await expect(page.getByRole("alert")).toContainText("Resolved incident cannot be acknowledged");
  expect(state.incidentBulkRequests?.[0]).toMatchObject({
    action: "acknowledge",
    selection_mode: "filter",
    filters: {},
  });

  await page.getByLabel("Выбрать Active two").check();
  await page.getByRole("combobox", { name: "Действие", exact: true }).selectOption("resolve");
  let resolveConfirmation = "";
  page.once("dialog", async (dialog) => {
    resolveConfirmation = dialog.message();
    await dialog.dismiss();
  });
  await page.getByRole("button", { name: "Применить", exact: true }).click();
  await expect.poll(() => resolveConfirmation).toContain("нового firing-события");
  expect(state.incidentBulkRequests).toHaveLength(1);

  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Применить", exact: true }).click();
  await expect.poll(() => state.incidentBulkRequests?.length ?? 0).toBe(2);
  await expect(page.getByRole("status")).toContainText("Изменено: 1");

  await page.locator(".sidebar__nav").getByRole("button", { name: "Кластер" }).click();
  await expect(page.getByRole("link", { name: "Открыть дашборд приложения" })).toHaveAttribute(
    "href",
    "https://grafana.example.test/d/alert-hub",
  );
  await expect(page.locator('a[href="/metrics"], a[href$="/metrics"]')).toHaveCount(0);
});

test("peer incident snapshots allow explicit IDs but never filter-wide bulk mutations", async ({
  page,
}) => {
  const peerBase = "https://trusted-peer.example.test";
  const incidents = Array.from({ length: 52 }, (_, index) => ({
    id: `incident-peer-${index}`,
    title: `Peer incident ${index}`,
    description: "Visible through the trusted read peer.",
    severity: index === 0 ? "critical" : "warning",
    status: "open",
    source_name: "Prometheus",
    region: "EU",
    target: `peer-target-${index}`,
    starts_at: "2026-09-05T11:58:00Z",
    last_event_at: "2026-09-05T12:00:00Z",
    labels: {},
    annotations: {},
  }));
  const state: MockState = {
    authoritativeUnauthorized: false,
    clusterStatus: {
      cluster_event_count: 1,
      cursor: { peer: 1 },
      nodes: [
        {
          id: "peer",
          name: "Trusted peer",
          region: "EU",
          health: "healthy",
          public_api_url: peerBase,
        },
      ],
    },
    incidentBulkRequests: [],
    incidentListRequests: [],
    incidents,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await page.route(
    /^https:\/\/trusted-peer\.example\.test\/api\/v1\/incidents(?:\?.*)?$/,
    async (route) => {
      const request = route.request();
      const origin = request.headers().origin ?? "*";
      const corsHeaders = {
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Alert-Hub-Cache-Partition",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Origin": origin,
      };
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers: corsHeaders });
        return;
      }
      const url = new URL(request.url());
      const limit = Number(url.searchParams.get("limit") ?? 50);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: corsHeaders,
        body: JSON.stringify({
          items: incidents.slice(offset, offset + limit),
          total: incidents.length,
          limit,
          offset,
          counts: {
            active: incidents.length,
            open: incidents.filter((incident) => incident.status === "open").length,
            acknowledged: incidents.filter((incident) => incident.status === "acknowledged").length,
            resolved: 0,
            silenced: 0,
            all: incidents.length,
          },
          bulk_limit: 500,
        }),
      });
    },
  );
  await signIn(page);
  await expect
    .poll(() =>
      page.evaluate((peer) => {
        const saved = JSON.parse(localStorage.getItem("alert-hub-api-endpoints") ?? "[]");
        return Array.isArray(saved) && saved.includes(peer);
      }, peerBase),
    )
    .toBe(true);

  state.primaryUnavailable = true;
  await page.locator(".sidebar__nav").getByRole("button", { name: "Инциденты" }).click();
  await expect(page.getByText("Peer incident 0", { exact: true })).toBeVisible();
  await page.getByLabel("Выбрать текущую страницу").check();
  await expect(
    page.getByText(/Выбор всех результатов доступен после свежего ответа/),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Выбрать все 52 результатов" })).toHaveCount(0);

  await page.getByRole("button", { name: "Применить", exact: true }).click();
  await expect.poll(() => state.incidentBulkRequests?.length ?? 0).toBe(1);
  expect(state.incidentBulkRequests?.[0]).toMatchObject({
    action: "acknowledge",
    selection_mode: "ids",
  });
  expect(state.incidentBulkRequests?.[0]?.incident_ids).toHaveLength(50);
  expect(state.incidentBulkRequests?.some((request) => request.selection_mode === "filter")).toBe(
    false,
  );

  await expect(page.getByText(/Изменено: 50/)).toBeVisible();
  await expect(page.locator(".incidents-page")).toHaveAttribute("aria-busy", "false");
  await expect(page.getByText("Peer incident 0", { exact: true })).toBeVisible();
  await page.getByLabel("Выбрать текущую страницу").check();
  await expect(
    page.getByText(/Выбор всех результатов доступен после свежего ответа/),
  ).toBeVisible();
  state.primaryUnavailable = false;
  await page.getByRole("button", { name: "Обновить список" }).click();
  await expect(page.getByRole("button", { name: "Выбрать все 52 результатов" })).toBeVisible();
  await page.getByRole("button", { name: "Выбрать все 52 результатов" }).click();
  await expect(page.getByText(/Выбраны все результаты фильтра/)).toBeVisible();
  expect(state.incidentBulkRequests?.some((request) => request.selection_mode === "filter")).toBe(
    false,
  );
});

test("incident filters and SSE refresh keep bulk actions aligned with the visible snapshot", async ({
  page,
}) => {
  const incidents = [
    {
      id: "incident-filter-one",
      title: "Filter one",
      description: "First filter incident",
      severity: "critical",
      status: "open",
      source_name: "Prometheus",
      region: "RU",
      target: "api-one",
      starts_at: "2026-09-05T11:58:00Z",
      last_event_at: "2026-09-05T12:00:00Z",
      labels: {},
      annotations: {},
    },
    {
      id: "incident-filter-two",
      title: "Filter two",
      description: "Second filter incident",
      severity: "warning",
      status: "open",
      source_name: "Heartbeat",
      region: "DE",
      target: "api-two",
      starts_at: "2026-09-05T11:57:00Z",
      last_event_at: "2026-09-05T11:59:00Z",
      labels: {},
      annotations: {},
    },
  ];
  const state: MockState = {
    authoritativeUnauthorized: false,
    incidentBulkRequests: [],
    incidentListRequests: [],
    incidents,
    lateTokenRequests: [],
    liveEventSource: true,
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);
  await page.locator(".sidebar__nav").getByRole("button", { name: "Инциденты" }).click();
  await expect(page.getByText("Filter one", { exact: true })).toBeVisible();

  const search = page.getByPlaceholder("Название, описание, источник или метка…");
  const requestsBeforeEquivalentSearch = state.incidentListRequests?.length ?? 0;
  await search.fill("   ");
  await page.waitForTimeout(350);
  await expect(page.locator(".incidents-page")).toHaveAttribute("aria-busy", "false");
  await expect(page.getByLabel("Выбрать Filter one")).toBeEnabled();
  expect(state.incidentListRequests).toHaveLength(requestsBeforeEquivalentSearch);

  state.primaryUnavailable = true;
  await search.fill("missing incident");
  await expect(page.getByRole("alert")).toContainText("503");
  await expect(page.getByText("Filter one", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Выбрать текущую страницу")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Применить", exact: true })).toHaveCount(0);
  expect(state.incidentBulkRequests).toHaveLength(0);

  state.primaryUnavailable = false;
  await page.getByRole("button", { name: "Повторить", exact: true }).first().click();
  await expect(page.getByRole("heading", { name: "Ничего не найдено" })).toBeVisible();
  await page.getByLabel("Очистить поиск").click();
  await expect(page.getByText("Filter one", { exact: true })).toBeVisible();

  await expect
    .poll(() =>
      page.evaluate(() =>
        Boolean(
          (
            window as unknown as {
              __alertHubStreamReady?: () => boolean;
            }
          ).__alertHubStreamReady?.(),
        ),
      ),
    )
    .toBe(true);
  await page.getByLabel("Выбрать Filter one").check();
  const listGate = deferredGate();
  const listStarted = deferredGate();
  const requestsBeforeStream = state.incidentListRequests?.length ?? 0;
  state.incidentListGate = listGate.promise;
  state.incidentListStarted = listStarted.release;
  await page.evaluate(() =>
    (
      window as unknown as {
        __emitAlertHubStreamMessage: () => void;
      }
    ).__emitAlertHubStreamMessage(),
  );
  await listStarted.promise;

  expect((state.incidentListRequests?.length ?? 0) - requestsBeforeStream).toBe(1);
  await expect(page.locator(".incidents-page")).toHaveAttribute("aria-busy", "true");
  await expect(page.getByLabel("Выбрать Filter one")).toBeDisabled();
  await expect(page.getByRole("combobox", { name: "Действие", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Применить", exact: true })).toBeDisabled();

  listGate.release();
  state.incidentListGate = null;
  state.incidentListStarted = null;
  await expect(page.getByLabel("Выбрать Filter one")).not.toBeChecked();
  await expect(page.getByRole("button", { name: "Применить", exact: true })).toHaveCount(0);
  await expect(page.locator(".incidents-page")).toHaveAttribute("aria-busy", "false");
});

test("SSE refreshes an incident detail that is absent from the global top-100 snapshot", async ({
  page,
}) => {
  const outsideIncident: Record<string, unknown> = {
    id: "incident-outside-top-100",
    title: "Outside top 100",
    description: "Loaded only through the exact detail endpoint.",
    severity: "critical",
    status: "open",
    source_name: "Prometheus",
    region: "RU",
    target: "outside",
    starts_at: "2026-09-05T11:58:00Z",
    last_event_at: "2026-09-05T12:00:00Z",
    labels: {},
    annotations: {},
    timeline: [
      {
        id: "outside-event-1",
        event_type: "firing",
        label: "Outside incident fired",
        detail: "Initial event",
        occurred_at: "2026-09-05T12:00:00Z",
        origin_node_id: "ru",
      },
    ],
  };
  const state: MockState = {
    authoritativeUnauthorized: false,
    incidentDetailRequests: [],
    incidentDetails: { "incident-outside-top-100": outsideIncident },
    incidentListRequests: [],
    incidents: Array.from({ length: 100 }, (_, index) => ({
      id: `incident-filler-${index}`,
      title: `Filler ${index}`,
      severity: "info",
      status: "open",
      source_name: "Heartbeat",
      starts_at: "2026-09-05T10:00:00Z",
      last_event_at: "2026-09-05T10:00:00Z",
    })),
    lateTokenRequests: [],
    liveEventSource: true,
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);
  await page.evaluate(() => {
    window.history.pushState({}, "", "/incidents/incident-outside-top-100");
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
  await expect(page.getByRole("heading", { name: "Outside top 100" })).toBeVisible();
  await expect(page.getByText("Outside incident fired")).toBeVisible();
  const detailRequestsBeforeStream = state.incidentDetailRequests?.length ?? 0;
  const listRequestsBeforeStream = state.incidentListRequests?.length ?? 0;
  Object.assign(outsideIncident, {
    title: "Outside top 100 refreshed",
    status: "resolved",
    last_event_at: "2026-09-05T12:01:00Z",
    timeline: [
      ...((outsideIncident.timeline as unknown[]) ?? []),
      {
        id: "outside-event-2",
        event_type: "resolved",
        label: "Outside incident resolved",
        detail: "Fresh detail response",
        occurred_at: "2026-09-05T12:01:00Z",
        origin_node_id: "ru",
      },
    ],
  });
  await expect
    .poll(() =>
      page.evaluate(() =>
        Boolean(
          (
            window as unknown as {
              __alertHubStreamReady?: () => boolean;
            }
          ).__alertHubStreamReady?.(),
        ),
      ),
    )
    .toBe(true);
  await page.evaluate(() =>
    (
      window as unknown as {
        __emitAlertHubStreamMessage: () => void;
      }
    ).__emitAlertHubStreamMessage(),
  );

  await expect(page.getByRole("heading", { name: "Outside top 100 refreshed" })).toBeVisible();
  await expect(page.getByText("Outside incident resolved")).toBeVisible();
  expect((state.incidentDetailRequests?.length ?? 0) - detailRequestsBeforeStream).toBe(1);
  expect(state.incidentListRequests).toHaveLength(listRequestsBeforeStream);
});

test("Checks dashboard, filters, grouping, matrix details, links, and mobile accessibility", async ({
  page,
}) => {
  const fixtures = checksFixtures();
  const dashboardGate = deferredGate();
  const state: MockState = {
    authoritativeUnauthorized: false,
    checksDetails: fixtures.details,
    checksGate: dashboardGate.promise,
    checksItems: fixtures.items,
    checksMode: "ready",
    checksSummarySearches: [],
    checksWarningCodes: ["check_ttfb_unavailable"],
    incidents: [
      {
        id: "incident-checkout",
        title: "Checkout incident",
        description: "The synthetic customer path is failing.",
        severity: "critical",
        status: "open",
        source_name: "Prometheus",
        region: "EU",
        target: "Checkout",
        starts_at: "2026-09-05T11:58:00Z",
        last_event_at: "2026-09-05T12:00:00Z",
        labels: { check_id: "must-not-become-a-link" },
        annotations: {},
        timeline: [],
        related_checks: [{ check_id: "complex-check", href: "/checks/complex-check" }],
        checks_relation_state: "available",
      },
    ],
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  const widget = page.locator(".checks-widget");
  await expect(widget.getByRole("heading", { name: "Автоматизированные проверки" })).toBeVisible();
  await expect(widget.locator(".checks-widget-skeleton")).toBeVisible();
  await expect(
    widget.locator(".checks-problem-row:not(.checks-problem-row--skeleton)"),
  ).toHaveCount(0);
  dashboardGate.release();
  state.checksGate = null;
  await expect(widget.locator(".checks-problem-row").first()).toContainText("Down check");
  await expect(widget.locator(".checks-summary__item--up strong")).toHaveText("1");
  await expect(widget.getByText("Метрика TTFB временно недоступна")).toBeVisible();

  const listGate = deferredGate();
  state.checksGate = listGate.promise;
  await page.locator(".sidebar__nav").getByRole("button", { name: "Checks" }).click();

  await expect(page.getByRole("heading", { name: "Checks", level: 1 })).toBeVisible();
  await expect(page.locator(".checks-summary-loading")).toBeVisible();
  await expect(page.locator(".checks-list-skeleton")).toBeVisible();
  await expect(page.locator(".checks-table tbody tr")).toHaveCount(0);
  listGate.release();
  state.checksGate = null;
  await expect(page.getByRole("heading", { name: "customer-paths" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Без группы" })).toBeVisible();
  const complexCoverage = page.getByRole("link", {
    name: "Открыть Check Complex customer path",
  });
  await expect(
    complexCoverage.locator(".check-coverage-counts > span").filter({ hasText: "Sources" }),
  ).toContainText("0/1");
  await expect(
    complexCoverage.locator(".check-coverage-counts > span").filter({ hasText: "Instances" }),
  ).toContainText("1/3");
  await expect(complexCoverage.locator(".check-instance-coverage")).toContainText("de-central");

  await page.setViewportSize({ width: 390, height: 844 });
  const longIdRow = page.getByRole("link", { name: "Открыть Check Simple check" });
  await expect(longIdRow.locator(".check-identity__id")).toHaveText(fixtures.longCheckId);
  await expect(longIdRow.locator("button, a")).toHaveCount(0);
  await longIdRow.focus();
  await expect(longIdRow).toBeFocused();
  const detailGate = deferredGate();
  state.checksGate = detailGate.promise;
  await longIdRow.press("Enter");
  await expect(page.locator(".check-detail-skeleton")).toBeVisible();
  await expect(page.getByText("Simple check", { exact: true })).toHaveCount(0);
  detailGate.release();
  state.checksGate = null;
  await expect(page.getByRole("heading", { name: "Simple check" })).toBeVisible();
  await expect(page.locator(".check-detail-hero .check-identity__id")).toHaveText(
    fixtures.longCheckId,
  );
  await expect(page.getByText("Источники вернули разные значения TTFB")).toBeVisible();
  await expect(page.getByText("Неизвестный диагностический сигнал")).toBeVisible();
  await expect(page.getByText("synthetic_check_ttfb_seconds").first()).toBeVisible();
  await expect(page.getByText("Что делать").first()).toBeVisible();
  await expect(page.locator(".check-detail-summary > div").first().locator("small")).toHaveCount(0);
  await expect(page.getByRole("link", { name: /Grafana/ })).toHaveCount(0);
  const longIdOverflow = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
  }));
  expect(longIdOverflow.documentWidth).toBe(longIdOverflow.viewportWidth);
  await page.locator(".breadcrumb-button").click();
  await expect(page.getByRole("link", { name: "Открыть Check Simple check" })).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 900 });

  await page
    .locator(".checks-summary")
    .getByRole("button", { name: /Не работает/ })
    .click();
  await expect(page.locator(".checks-table tbody tr")).toHaveCount(1);
  await expect(page.locator(".checks-table tbody tr")).toContainText("Down check");
  await expect(page.locator(".checks-summary__item--all strong")).toHaveText("5");
  await expect(page.locator(".checks-summary__item--up strong")).toHaveText("1");
  await page.locator(".checks-summary").getByRole("button", { name: /Всего/ }).click();
  await page.getByRole("search").getByPlaceholder("ID, название или Target…").fill("No match");
  await page.getByRole("search").getByRole("button", { name: "Найти" }).click();
  await expect(page.getByRole("heading", { name: "Ничего не найдено" })).toBeVisible();
  await expect(page.getByText(/Подключите совместимого исполнителя/)).toHaveCount(0);
  await page.locator(".checks-state").getByRole("button", { name: "Сбросить фильтры" }).click();
  await expect(page.locator(".checks-table tbody tr")).toHaveCount(fixtures.items.length);
  await page.getByRole("search").getByPlaceholder("ID, название или Target…").fill("Complex");
  await page.getByRole("search").getByRole("button", { name: "Найти" }).click();
  await expect(page.locator(".checks-table tbody tr")).toHaveCount(1);
  await expect(page.getByText("Источники вернули разные значения TTFB")).toBeVisible();
  expect(state.checksSummarySearches?.some((search) => search.includes("status="))).toBe(false);
  expect(state.checksSummarySearches?.at(-1)).toBe("?search=Complex");
  await page.getByRole("link", { name: "Открыть Check Complex customer path" }).click();

  await expect(page.getByRole("heading", { name: "Complex customer path" })).toBeVisible();
  await expect(page.getByText("Успешные Instances")).toBeVisible();
  await expect(page.locator(".check-detail-summary")).toContainText("1/3");
  await expect(page.locator(".check-detail-summary")).toContainText("de-central");
  await expect(page.getByRole("region", { name: "Матрица Instance × Scenario" })).toBeVisible();
  const variantSummary = page.locator("summary").filter({ hasText: "Variant · guest" });
  await variantSummary.focus();
  await expect(variantSummary).toBeFocused();
  await variantSummary.press("Enter");
  expect(
    await variantSummary.evaluate((element) => getComputedStyle(element).outlineStyle),
  ).not.toBe("none");
  await expect(page.getByText("control")).toBeVisible();
  await expect(page.getByText("Checkout primary")).toBeVisible();
  await expect(page.getByText("checkout-primary")).toBeVisible();
  await expect(page.getByText("Checkout backup")).toBeVisible();
  await expect(page.getByText("Ошибка выполнения")).toBeVisible();
  await expect(page.getByText("Expected egress")).toBeVisible();
  await expect(page.getByText("egress_match")).toBeVisible();
  await expect(page.getByText("Не совпадает")).toBeVisible();
  await expect(page.getByText("Накопительные счётчики ошибок")).toBeVisible();
  await expect(page.getByText(/это не текст текущей ошибки/)).toBeVisible();
  await expect(page.getByText("Тайм-аут")).toBeVisible();
  await expect(page.getByText("future_reason")).toBeVisible();
  await expect(page.getByLabel("Тайм-аут: 3")).toHaveText("×3");
  const grafanaLink = page.getByRole("link", { name: /Grafana/ });
  await expect(grafanaLink).toHaveAttribute(
    "href",
    "https://grafana.example.test/d/checks?var-check_id=complex-check",
  );
  await expect(grafanaLink).toHaveAttribute("target", "_blank");
  await expect(grafanaLink).toHaveAttribute("rel", "noopener noreferrer");
  await expect(page.getByText("Checkout path failed")).toBeVisible();
  await expect(page.getByText(/Получено активных алертов/)).toContainText("1/2");
  await expect(page.getByText("related_alerts_truncated")).toBeVisible();
  await expect(page.getByText("related_incidents_truncated")).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  const overflow = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
  }));
  expect(overflow.documentWidth).toBe(overflow.viewportWidth);
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
  await page.getByRole("button", { name: /Подробнее/ }).click();
  await expect(page.getByRole("heading", { name: "Checkout incident" })).toBeVisible();
  const relatedChecks = page.getByRole("navigation", { name: "Связанные Checks" });
  await expect(relatedChecks).toContainText("complex-check");
  await expect(relatedChecks.getByRole("button", { name: /must-not-become-a-link/ })).toHaveCount(
    0,
  );
});

test("Checks disabled route is explicit and a refresh failure clears the previous success", async ({
  page,
}) => {
  const fixtures = checksFixtures();
  const state: MockState = {
    authoritativeUnauthorized: false,
    checksDetails: fixtures.details,
    checksItems: fixtures.items,
    checksMode: "disabled",
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);
  await expect(page.locator(".sidebar__nav").getByRole("button", { name: "Checks" })).toHaveCount(
    0,
  );
  await page.evaluate(() => {
    history.pushState({}, "", "/checks");
    dispatchEvent(new PopStateEvent("popstate"));
  });
  await expect(page.getByText("Модуль Checks отключён")).toBeVisible();

  state.checksMode = "ready";
  state.checksWarningCodes = ["check_ttfb_unavailable"];
  await page.getByRole("button", { name: "Обновить", exact: true }).click();
  await expect(page.getByText("Simple check")).toBeVisible();
  await page.getByRole("link", { name: "Открыть Check Simple check" }).click();
  await expect(page.locator(".check-detail-hero")).toContainText("Работает");

  const failureGate = deferredGate();
  state.checksGate = failureGate.promise;
  state.checksMode = "unavailable";
  await page.locator(".check-detail-actions").getByRole("button", { name: "Обновить" }).click();
  await expect(page.locator(".check-detail-skeleton")).toBeVisible();
  await expect(page.getByText("Simple check", { exact: true })).toHaveCount(0);
  failureGate.release();
  state.checksGate = null;
  await expect(page.getByText("Результаты Checks недоступны")).toBeVisible();
  await expect(page.locator(".check-detail-hero")).toHaveCount(0);
  await expect(page.getByText(/Прежний успешный результат скрыт/)).toBeVisible();
  await expect(page.getByText("check_ttfb_unavailable")).toBeVisible();
});

test("Alerts separates rules and instances, surfaces partial and stale data, and stays responsive", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    incidents: [],
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  await page.locator(".sidebar__nav").getByRole("button", { name: "Алерты" }).click();
  await expect(page).toHaveURL(/\/alerts$/);
  await expect(page.getByRole("heading", { name: "Алерты", exact: true })).toBeVisible();
  const cards = page.locator(".alerts-kpi");
  await expect(cards).toHaveCount(4);
  await expect(cards.nth(0)).toContainText("2");
  await expect(cards.nth(1)).toContainText("2");
  await expect(cards.nth(2)).toContainText("1");
  await expect(cards.nth(3)).toContainText("1");
  await expect(page.getByText("Данные получены частично", { exact: true })).toBeVisible();
  await expect(page.getByText("ApiDown", { exact: true })).toBeVisible();
  await expect(page.getByText("DiskForecast", { exact: true })).toBeVisible();
  await expect(page.getByText("Устарело", { exact: true }).first()).toBeVisible();
  await expect(page.locator(".availability-value--unknown").first()).toHaveText("—");
  await expect(page.getByText("Secondary Prometheus", { exact: true })).toBeVisible();

  const search = page.getByPlaceholder("Поиск по имени правила");
  await search.focus();
  await expect(search).toBeFocused();
  await page.getByRole("button", { name: "Инциденты: 2" }).click();
  await expect(page).toHaveURL(/\/incidents\?q=ApiDown$/);
  await expect(page.getByRole("textbox", { name: /Поиск инцидентов/ })).toHaveValue("ApiDown");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Алерты", exact: true }).click();
  await expect(page.locator(".alerts-table").first().locator("tbody tr").first()).toBeVisible();
  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth);

  await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
});

test("Web Push surfaces node errors, rotates stale keys, and binds the login device", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    loginRequest: null,
    logoutRequests: 0,
    primaryUnavailable: false,
    pushPublicKeyStatus: 503,
    pushSubscriptionRequest: null,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installFakePushClient(page, "granted", true);
  await installApi(page, state);
  await signIn(page);

  await page.getByRole("button", { name: "Включить оповещения" }).click();
  const dialog = page.getByRole("dialog", { name: "Включить уведомления" });
  await dialog.getByRole("button", { name: "Проверить подписку" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Web Push sender key is unavailable");
  await expect(dialog.locator(".permission-message--success")).toHaveCount(0);

  state.pushPublicKeyStatus = 200;
  await dialog.getByRole("button", { name: "Проверить подписку" }).click();
  await expect(dialog.getByRole("status")).toContainText("Устройство подписано");
  expect(state.pushSubscriptionRequest).toMatchObject({
    endpoint: "https://push.example.test/subscription/current",
    keys: { auth: "AQIDBAUGBwgJCgsMDQ4PEA", p256dh: TEST_VAPID_PUBLIC_KEY },
  });
  expect(state.pushSubscriptionRequest?.device_name).toBe(state.loginRequest?.device_name);
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (
            window as unknown as {
              __pushTest: { subscribeCalls: number; unsubscribeCalls: number };
            }
          ).__pushTest,
      ),
    )
    .toMatchObject({ subscribeCalls: 1, unsubscribeCalls: 1 });
});

test("Web Push explains blocked permission without retrying the browser prompt", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installFakePushClient(page, "denied");
  await installApi(page, state);
  await signIn(page);

  await page.getByRole("button", { name: "Включить оповещения" }).click();
  const dialog = page.getByRole("dialog", { name: "Включить уведомления" });
  await expect(dialog.getByRole("alert")).toContainText("настройки сайта");
  await dialog.getByRole("button", { name: "Как вернуть разрешение" }).click();
  await expect(dialog.getByRole("alert")).toContainText("настройки сайта");
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __pushTest: { permissionRequests: number } }).__pushTest
          .permissionRequests,
    ),
  ).toBe(0);
});

test("Web Push cancels a delayed browser subscription when the authenticated session changes", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    pushSubscriptionRequest: null,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installFakePushClient(page, "granted", false, true);
  await installApi(page, state);
  await signIn(page);

  await page.getByRole("button", { name: "Включить оповещения" }).click();
  const dialog = page.getByRole("dialog", { name: "Включить уведомления" });
  await dialog.getByRole("button", { name: "Проверить подписку" }).click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (
            window as unknown as {
              __pushTest: { subscribeCalls: number };
            }
          ).__pushTest.subscribeCalls,
      ),
    )
    .toBe(1);
  await expect(dialog.getByRole("button", { name: "Закрыть" })).toBeDisabled();
  await expect(dialog.getByRole("button", { name: "Позже" })).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();

  await page.evaluate(() => window.dispatchEvent(new Event("alert-hub:session-expired")));
  await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
  await page.getByLabel("Имя пользователя").fill("second-admin");
  await page.getByLabel("Пароль", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Войти" }).last().click();
  await expect(page.getByRole("heading", { name: "Состояние системы" })).toBeVisible();

  await page.evaluate(() =>
    (
      window as unknown as {
        __pushTest: { releaseSubscription: () => void };
      }
    ).__pushTest.releaseSubscription(),
  );
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (
            window as unknown as {
              __pushTest: { unsubscribeCalls: number };
            }
          ).__pushTest.unsubscribeCalls,
      ),
    )
    .toBe(1);
  expect(state.pushSubscriptionRequest).toBeNull();
});

test("Web Push cancels a delayed subscription when silent refresh replaces the session id", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    pushSubscriptionRequest: null,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installFakePushClient(page, "granted", false, true);
  await installApi(page, state);
  await signIn(page);

  await page.getByRole("button", { name: "Включить оповещения" }).click();
  const dialog = page.getByRole("dialog", { name: "Включить уведомления" });
  await dialog.getByRole("button", { name: "Проверить подписку" }).click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (
            window as unknown as {
              __pushTest: { subscribeCalls: number };
            }
          ).__pushTest.subscribeCalls,
      ),
    )
    .toBe(1);

  const refreshRequestsBeforeSessionReplacement = state.refreshRequests;
  state.authoritativeUnauthorized = true;
  state.refreshGate = Promise.resolve();
  await page
    .getByRole("button", { name: "Обновить данные кластера" })
    .evaluate((button: HTMLButtonElement) => button.click());
  await expect
    .poll(() => state.refreshRequests)
    .toBeGreaterThan(refreshRequestsBeforeSessionReplacement);
  await expect.poll(() => state.lateTokenRequests.length).toBeGreaterThan(0);

  await page.evaluate(() =>
    (
      window as unknown as {
        __pushTest: { releaseSubscription: () => void };
      }
    ).__pushTest.releaseSubscription(),
  );
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (
            window as unknown as {
              __pushTest: { unsubscribeCalls: number };
            }
          ).__pushTest.unsubscribeCalls,
      ),
    )
    .toBe(1);
  await expect(dialog.getByRole("alert")).toContainText("изменилась активная сессия");
  expect(state.pushSubscriptionRequest).toBeNull();
});

test("a backgrounded session revalidates and recovers from a transient 401", async ({ page }) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  const refreshesBeforeRecovery = state.refreshRequests;
  state.transientUnauthorizedReads = 1;
  state.refreshResponseStatuses = [401, 200];
  await page.getByRole("button", { name: "Обновить данные кластера" }).click();

  await expect.poll(() => state.refreshRequests).toBe(refreshesBeforeRecovery + 2);
  await expect(page.getByRole("heading", { name: "Состояние системы" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Вход в систему" })).toHaveCount(0);

  const refreshesBeforeActivation = state.refreshRequests;
  state.refreshResponseStatuses = [200];
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect.poll(() => state.refreshRequests).toBe(refreshesBeforeActivation + 1);
  await expect(page.getByRole("heading", { name: "Состояние системы" })).toBeVisible();
});

test("bootstrap, deep-link navigation, live source creation, failover trust, and logout isolation", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  const evilRequests: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).origin === "https://evil.invalid") {
      evilRequests.push(request.url());
    }
  });
  await installApi(page, state);

  await page.goto("/sources");
  const manifest = await page.evaluate(async () => {
    const response = await fetch("/manifest.webmanifest");
    return response.json() as Promise<Record<string, unknown>>;
  });
  expect(manifest).toMatchObject({
    background_color: "#0A0A0B",
    description: "Распределённый мониторинг инцидентов и отказоустойчивая доставка оповещений.",
    name: "E2E Operations",
    shortcuts: [
      { name: "Активные инциденты", short_name: "Инциденты", url: "/incidents" },
      { name: "Состояние кластера", short_name: "Кластер", url: "/cluster" },
    ],
    theme_color: "#0A0A0B",
  });
  await expect(page).toHaveTitle("E2E Operations — Центр мониторинга");
  await expect(page.getByRole("heading", { name: "Запуск кластера" })).toBeVisible();
  await page.getByLabel("Токен первичной настройки").fill("one-time-bootstrap-token");
  await page.getByLabel("Имя пользователя").fill("admin");
  await page.getByLabel("Пароль", { exact: true }).fill("correct-horse-battery");
  await page.getByLabel("Повторите пароль").fill("correct-horse-battery");
  await page.getByRole("button", { name: "Создать администратора" }).click();

  await expect(page).toHaveURL(/\/sources$/);
  await expect(page.getByRole("heading", { name: "Источники", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Добавить источник" }).click();
  const sourceDialog = page.getByRole("dialog", { name: "Добавить источник" });
  await expect(sourceDialog).toBeVisible();
  await sourceDialog.getByRole("button", { name: /Продолжить/ }).click();
  await sourceDialog.getByLabel("Название источника").fill("Edge Alertmanager");
  await sourceDialog.getByLabel("Ближайший регион").fill("NL");
  await sourceDialog.getByLabel(/Разрешённый IP/).fill("198.51.100.0/24");
  await sourceDialog.getByRole("button", { name: "Создать источник" }).click();
  await expect(sourceDialog.getByRole("heading", { name: "Источник создан" })).toBeVisible();
  await expect(sourceDialog.getByText("shown-once-source-token")).toBeVisible();
  const browserOrigin = await page.evaluate(() => window.location.origin);
  const absoluteWebhook = `${browserOrigin}/ingest/v1/alertmanager/source-created`;
  await expect(sourceDialog.getByText(absoluteWebhook, { exact: true })).toBeVisible();
  await expect(sourceDialog.getByText(/https:\/\/YOUR_HOST/)).toHaveCount(0);
  await expect(sourceDialog.getByText(/Готовый фрагмент receiver для Alertmanager/)).toBeVisible();
  expect(state.sourceRequest).toMatchObject({
    name: "Edge Alertmanager",
    kind: "alertmanager",
    region: "NL",
    allowed_cidrs: ["198.51.100.0/24"],
  });
  await sourceDialog.getByRole("button", { name: "Я сохранил токен" }).click();
  await expect(page.getByText(absoluteWebhook, { exact: true })).toBeVisible();
  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Обновить токен" }).click();
  const rotatedDialog = page.getByRole("dialog", { name: "Новый токен источника" });
  await expect(rotatedDialog.getByText("rotated-source-token")).toBeVisible();
  await expect(rotatedDialog.getByText(absoluteWebhook, { exact: true })).toBeVisible();
  await expect(rotatedDialog.getByText(/https:\/\/YOUR_HOST/)).toHaveCount(0);
  await rotatedDialog.getByRole("button", { name: "Я сохранил новый токен" }).click();

  await page.getByRole("button", { name: "Обзор" }).click();
  await expect(page.getByRole("heading", { name: "Статистика за 7 дней" })).toBeVisible();
  await expect(
    page.locator(".statistics-kpi").filter({ hasText: "Началось инцидентов" }),
  ).toContainText("12");
  await expect(page.locator(".statistics-chart")).toHaveCount(2);
  await expect(page.getByText("Prometheus EU", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Подробнее в Grafana" })).toHaveAttribute(
    "href",
    "https://grafana.example.test/d/alert-hub",
  );
  await expect(page.getByRole("heading", { name: "Состояние по данным Prometheus" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Доступность по регионам" }).first(),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Активные тревоги" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Выбранные ключевые job" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Синхронизация и состояние Alert Hub" }),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Открыть Grafana" })).toHaveAttribute(
    "href",
    "https://grafana.example.test/d/alert-hub",
  );
  await page.getByRole("button", { name: "Источники" }).click();

  state.primaryUnavailable = true;
  await page.getByRole("button", { name: "Обновить данные кластера" }).click();
  await expect(page.locator(".connection-banner")).toContainText("Узлы API недоступны");
  expect(evilRequests).toEqual([]);
  state.primaryUnavailable = false;

  await page.getByRole("button", { name: "Выйти из Alert Hub" }).click();
  await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
  await page.getByLabel("Имя пользователя").fill("second-admin");
  await page.getByLabel("Пароль", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Войти" }).last().click();

  await expect(page.getByText("Second-session source")).toBeVisible();
  await expect(page.getByText("Edge Alertmanager")).toHaveCount(0);

  state.authoritativeUnauthorized = true;
  await page.getByRole("button", { name: "Обновить данные кластера" }).click();
  await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
  await expect(page.getByText("Second-session source")).toHaveCount(0);
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem("alert-hub-session-partition-v1")))
    .toBeNull();
});

test("creates a Prometheus datasource with explicit server reachability labels", async ({
  page,
}) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    datasourcePatchRequest: null,
    datasourceRequest: null,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  await page.getByRole("button", { name: "Доступность" }).click();
  await page.getByRole("button", { name: "Добавить Prometheus" }).click();
  const datasourceDialog = page.getByRole("dialog", {
    name: "Добавить источник данных Prometheus",
  });
  await datasourceDialog.getByLabel("Название источника").fill("Central Prometheus");
  await datasourceDialog
    .getByLabel("Prometheus HTTPS URL")
    .fill("https://grafana.example.test/api/datasources/proxy/uid/prometheus");
  await datasourceDialog.getByLabel("ID обслуживающего узла · необязательно").fill("ru");
  await datasourceDialog.getByLabel("Регион · необязательно").fill("RU");
  await datasourceDialog.getByLabel("Метки матрицы доступности").selectOption("server");
  await datasourceDialog.getByLabel("Аутентификация").selectOption("bearer");
  await datasourceDialog.getByLabel("Bearer-токен · только для записи").fill("grafana-token");
  await datasourceDialog.getByRole("button", { name: "Добавить источник" }).click();

  const labelModeSelect = page.getByLabel("Метки матрицы для Central Prometheus");
  await expect(labelModeSelect).toHaveValue("server");
  expect(state.datasourceRequest).toMatchObject({
    name: "Central Prometheus",
    node_id: "ru",
    region: "RU",
    reachability_label_mode: "server",
    credentials: { auth_type: "bearer", bearer_token: "grafana-token" },
  });

  await labelModeSelect.selectOption("canonical");
  await expect
    .poll(() => state.datasourcePatchRequest)
    .toEqual({
      reachability_label_mode: "canonical",
    });
  await expect(labelModeSelect).toHaveValue("canonical");
});

test("updates the Grafana link and safe job patterns from settings", async ({ page }) => {
  const state: MockState = {
    applicationSettingsRequest: null,
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);

  await page.getByRole("button", { name: "Настройки", exact: true }).click();
  await page.getByLabel("Ссылка на Grafana").fill("https://grafana.example.test/");
  await page.getByRole("button", { name: "Сохранить мониторинг" }).click();
  await expect(page.getByRole("alert")).toContainText("HTTPS-ссылку на конкретный дашборд Grafana");
  expect(state.applicationSettingsRequest).toBeNull();

  await page.getByLabel("Ссылка на Grafana").fill("https://grafana.example.test/d/new-operations");
  await page.getByLabel("Ключевые сервисы · job").fill("vless_blackbox_*, vps_nodes");
  await page.getByLabel("Сервисы Alert Hub · job").fill("alert-hub-api-*");
  await page.getByRole("button", { name: "Сохранить мониторинг" }).click();

  await expect(page.getByRole("status")).toContainText("Настройки мониторинга сохранены");
  expect(state.applicationSettingsRequest).toEqual({
    grafana_url: "https://grafana.example.test/d/new-operations",
    key_job_globs: ["vless_blackbox_*", "vps_nodes"],
    alert_hub_job_globs: ["alert-hub-api-*"],
  });
  await page.getByRole("button", { name: "Обзор", exact: true }).click();
  await expect(page.getByRole("link", { name: "Открыть Grafana" })).toHaveAttribute(
    "href",
    "https://grafana.example.test/d/new-operations",
  );
});

test("logout waits for an in-flight refresh and rejects its stale token", async ({ page }) => {
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await page.goto("/sources");
  await page.getByRole("button", { name: "Войти" }).click();
  await page.getByLabel("Имя пользователя").fill("second-admin");
  await page.getByLabel("Пароль", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Войти" }).last().click();
  await expect(page.getByText("Second-session source")).toBeVisible();

  let releaseRefresh: () => void = () => undefined;
  state.refreshGate = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });
  const refreshStarted = new Promise<void>((resolve) => {
    state.refreshStarted = resolve;
  });
  state.authoritativeUnauthorized = true;
  await page.getByRole("button", { name: "Обновить данные кластера" }).click();
  await refreshStarted;
  await page.getByRole("button", { name: "Выйти из Alert Hub" }).click();
  releaseRefresh();

  await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
  expect(state.logoutRequests).toBe(1);
  expect(state.lateTokenRequests).toEqual([]);
  await expect
    .poll(() =>
      page.evaluate(() => ({
        hint: localStorage.getItem("alert-hub-session-partition-v1"),
        tombstone: localStorage.getItem("alert-hub-local-logout-v1"),
      })),
    )
    .toMatchObject({ hint: null, tombstone: expect.any(String) });

  const refreshCount = state.refreshRequests;
  await page.reload();
  await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
  expect(state.refreshRequests).toBe(refreshCount);
  expect(state.lateTokenRequests).toEqual([]);
});

test("renders live cluster telemetry and groups repeated historical audit failures", async ({
  page,
}) => {
  const now = new Date().toISOString();
  const repeatedFailures = ["audit-1", "audit-2", "audit-3"].map((id) => ({
    id,
    action: "Cluster Auth Failed",
    action_code: "cluster_auth_failed",
    detail: 'System operation · {"client_ip":"192.0.2.10"}',
    actor: "system",
    node_id: "ru",
    occurred_at: now,
    request_id: `request-${id}`,
    tone: "danger",
  }));
  const otherAuditEvents = Array.from({ length: 100 }, (_, index) => ({
    id: `audit-${index + 4}`,
    action: "Login Succeeded",
    action_code: "login_succeeded",
    detail: `Session ${index + 1}`,
    actor: "operator",
    node_id: "ru",
    occurred_at: now,
    request_id: `request-${index + 4}`,
    tone: "success",
  }));
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
    liveEventSource: true,
    clusterStatus: {
      cluster_event_count: 28,
      cursor: { ru: 10, nl: 9, de: 9 },
      nodes: ["ru", "nl", "de"].map((id) => ({
        id,
        name: id.toUpperCase(),
        region: id,
        health: "healthy",
        sync_lag_seconds: 0,
        outbox_pending: id === "ru" ? 0 : null,
        last_seen_at: now,
        software_version: "v0.1.4",
      })),
    },
    auditItems: [...repeatedFailures, ...otherAuditEvents],
  };
  await installApi(page, state);
  await page.goto("/audit");
  await page.getByLabel("Токен первичной настройки").fill("one-time-bootstrap-token");
  await page.getByLabel("Имя пользователя").fill("admin");
  await page.getByLabel("Пароль", { exact: true }).fill("correct-horse-battery");
  await page.getByLabel("Повторите пароль").fill("correct-horse-battery");
  // Install the fake clock after the anonymous bootstrap probe has settled, but
  // before authenticated data hooks create their polling intervals.
  await page.clock.install({ time: new Date(now) });
  await page.getByRole("button", { name: "Создать администратора" }).click();

  await expect(page.getByText(/Синхронизация 0\.0 сек\./)).toBeVisible();
  await expect(page.getByText("3 работают · 0 с проблемами · 0 без данных")).toBeVisible();
  await expect(page.getByText("3/3 узлов работают.")).toBeVisible();
  await expect(page.getByText("Отклонённая попытка входа в кластер")).toHaveCount(1);
  await expect(page.getByLabel("3 одинаковых событий в этой группе")).toBeVisible();
  await expect(page.getByText("Загружено 100/103")).toBeVisible();

  await page.getByRole("button", { name: "Загрузить старые события (100/103)" }).click();
  await expect(page.getByText("Загружено 103/103")).toBeVisible();
  await expect(page.getByRole("button", { name: /Загрузить старые события/ })).toHaveCount(0);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Скачать загруженный JSONL" }).click();
  const download = await downloadPromise;
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const exported = await readFile(downloadPath!, "utf8");
  const exportedRows = exported
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(exportedRows).toHaveLength(103);
  expect(exportedRows[0]).toMatchObject({ request_id: "request-audit-1" });

  let releaseStaleCluster: () => void = () => undefined;
  state.clusterResponseGates = [
    new Promise<void>((resolve) => {
      releaseStaleCluster = resolve;
    }),
  ];
  const staleClusterStarted = new Promise<void>((resolve) => {
    state.clusterRequestStarted = resolve;
  });
  await page.getByRole("button", { name: "Обновить данные кластера" }).click();
  await staleClusterStarted;

  state.clusterUnavailable = true;
  await page.clock.fastForward(30000);
  await expect(page.getByText(/Синхронизация нет телеметрии/)).toBeVisible();
  await expect(page.getByText("0/3 узлов работают.")).toBeVisible();

  state.clusterUnavailable = false;
  releaseStaleCluster();
  await expect(page.locator(".refresh-button")).not.toHaveClass(/is-spinning/);
  await expect(page.getByText(/Синхронизация нет телеметрии/)).toBeVisible();
  state.clusterRequestStarted = null;
  state.clusterStatus = {
    ...(state.clusterStatus as Record<string, unknown>),
    nodes: ["ru", "nl", "de"].map((id) => ({
      id,
      name: id.toUpperCase(),
      region: id,
      health: id === "de" ? "degraded" : "healthy",
      sync_lag_seconds: id === "de" ? null : 0,
      last_seen_at: now,
      software_version: "v0.1.4",
    })),
  };
  await page.clock.fastForward(30000);
  await expect(page.getByText(/Синхронизация Есть проблемы/)).toBeVisible();
  await expect(page.getByText("2 работают · 1 с проблемами · 0 без данных")).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByLabel("Период журнала")).toBeVisible();
});

test("configures per-node API-down alerts and enables every selected node", async ({ page }) => {
  const now = new Date().toISOString();
  const state: MockState = {
    authoritativeUnauthorized: false,
    clusterApiAlertRequests: [],
    clusterStatus: {
      cluster_event_count: 12,
      cursor: { ru: 4, nl: 4, de: 4 },
      nodes: ["ru", "nl", "de"].map((id) => ({
        id,
        name: id.toUpperCase(),
        region: id,
        health: id === "de" ? "offline" : "healthy",
        sync_lag_seconds: id === "de" ? null : 0,
        last_seen_at: now,
        software_version: "v0.1.4",
        api_down_alert_enabled: false,
      })),
    },
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
  };
  await installApi(page, state);
  await signIn(page);
  await page.locator(".sidebar__nav").getByRole("button", { name: "Кластер" }).click();

  await expect(page.getByRole("heading", { name: "Алерты о падении API" })).toBeVisible();
  const alertPanel = page.locator(".cluster-api-alerts");
  await expect(alertPanel.locator(".cluster-api-alerts__count")).toContainText("Включено: 0/3");
  const [panelHeaderBox, panelBodyBox, introBox, actionsBox] = await Promise.all([
    alertPanel.locator(".panel__header").boundingBox(),
    alertPanel.locator(".cluster-api-alerts__body").boundingBox(),
    alertPanel.locator(".cluster-api-alerts__intro").boundingBox(),
    alertPanel.locator(".cluster-api-alerts__actions").boundingBox(),
  ]);
  expect(panelHeaderBox).not.toBeNull();
  expect(panelBodyBox).not.toBeNull();
  expect(introBox).not.toBeNull();
  expect(actionsBox).not.toBeNull();
  expect(panelBodyBox!.y).toBeGreaterThanOrEqual(panelHeaderBox!.y + panelHeaderBox!.height - 1);
  expect(actionsBox!.y).toBeGreaterThanOrEqual(introBox!.y + introBox!.height - 1);

  const deSwitch = page.getByRole("switch", { name: "Алерт о падении API для DE" });
  const deControl = deSwitch.locator("xpath=..");
  await expect(deControl).toContainText("выключен");
  const offSwitchColor = await deSwitch.evaluate(
    (element) => window.getComputedStyle(element).backgroundColor,
  );
  const offThumbTransform = await deSwitch
    .locator(".toggle__thumb")
    .evaluate((element) => window.getComputedStyle(element).transform);
  const offThumbColor = await deSwitch
    .locator(".toggle__thumb")
    .evaluate((element) => window.getComputedStyle(element).backgroundColor);
  const switchBox = await deSwitch.boundingBox();
  expect(switchBox?.width).toBe(42);
  expect(switchBox?.height).toBe(24);
  expect(offThumbColor).toBe("rgb(139, 139, 149)");
  await page.getByRole("button", { name: "Выбрать все" }).click();
  await expect(page.getByText("Выбрано: 3")).toBeVisible();
  await page.getByRole("button", { name: "Включить выбранным" }).click();

  await expect(alertPanel.locator(".cluster-api-alerts__count")).toContainText("Включено: 3/3");
  await expect(page.getByRole("switch")).toHaveCount(3);
  for (const control of await page.getByRole("switch").all()) {
    await expect(control).toHaveAttribute("aria-checked", "true");
  }
  await expect(deControl).toContainText("включён");
  const onSwitchColor = await deSwitch.evaluate(
    (element) => window.getComputedStyle(element).backgroundColor,
  );
  const onThumbTransform = await deSwitch
    .locator(".toggle__thumb")
    .evaluate((element) => window.getComputedStyle(element).transform);
  expect(onSwitchColor).toBe(offSwitchColor);
  await expect(deSwitch.locator(".toggle__thumb")).toHaveCSS(
    "background-color",
    "rgb(34, 197, 94)",
  );
  expect(onThumbTransform).not.toBe(offThumbTransform);
  expect(state.clusterApiAlertRequests?.[0]).toEqual({
    node_ids: ["ru", "nl", "de"],
    enabled: true,
  });

  await deSwitch.click();
  await expect(alertPanel.locator(".cluster-api-alerts__count")).toContainText("Включено: 2/3");
  await expect(deSwitch).toHaveAttribute("aria-checked", "false");
  await expect(deControl).toContainText("выключен");
  expect(state.clusterApiAlertRequests?.[1]).toEqual({ node_ids: ["de"], enabled: false });

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(alertPanel).toBeVisible();
  const [mobileIntroBox, mobileActionsBox] = await Promise.all([
    alertPanel.locator(".cluster-api-alerts__intro").boundingBox(),
    alertPanel.locator(".cluster-api-alerts__actions").boundingBox(),
  ]);
  expect(mobileIntroBox).not.toBeNull();
  expect(mobileActionsBox).not.toBeNull();
  expect(mobileActionsBox!.y).toBeGreaterThanOrEqual(
    mobileIntroBox!.y + mobileIntroBox!.height - 1,
  );
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );

  for (const visualCase of [
    { theme: "dark", width: 1440, height: 900 },
    { theme: "light", width: 1440, height: 900 },
    { theme: "dark", width: 820, height: 1000 },
    { theme: "light", width: 820, height: 1000 },
    { theme: "dark", width: 390, height: 844 },
    { theme: "light", width: 390, height: 844 },
  ]) {
    await page.setViewportSize({ width: visualCase.width, height: visualCase.height });
    await page.evaluate((theme) => {
      document.documentElement.dataset.theme = theme;
    }, visualCase.theme);
    const layout = await alertPanel.evaluate((panel) => {
      const bounds = panel.getBoundingClientRect();
      const intro = panel.querySelector<HTMLElement>(".cluster-api-alerts__intro > p");
      const header = panel.querySelector<HTMLElement>(".panel__header");
      return {
        headerBackgroundImage: header ? window.getComputedStyle(header).backgroundImage : "",
        introFontSize: intro ? Number.parseFloat(window.getComputedStyle(intro).fontSize) : 0,
        noHorizontalOverflow: document.documentElement.scrollWidth <= window.innerWidth,
        panelLeft: bounds.left,
        panelRight: bounds.right,
        viewportWidth: window.innerWidth,
      };
    });
    expect(layout.noHorizontalOverflow).toBe(true);
    expect(layout.panelLeft).toBeGreaterThanOrEqual(0);
    expect(layout.panelRight).toBeLessThanOrEqual(layout.viewportWidth + 1);
    expect(layout.headerBackgroundImage).toBe("none");
    expect(layout.introFontSize).toBeGreaterThanOrEqual(14);
  }
});

test("rebases pure audit prepends and safely resets for an interior insertion", async ({
  page,
}) => {
  const now = new Date().toISOString();
  const originalItems = Array.from({ length: 205 }, (_, index) => ({
    id: `stable-audit-${index}`,
    action: "Stable audit event",
    action_code: "stable_audit_event",
    detail: `Stable event ${index}`,
    actor: "operator",
    node_id: "ru",
    occurred_at: now,
    request_id: `stable-request-${index}`,
    tone: "neutral",
  }));
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
    auditItems: originalItems,
  };
  await installApi(page, state);
  await page.goto("/audit");
  await page.getByLabel("Токен первичной настройки").fill("one-time-bootstrap-token");
  await page.getByLabel("Имя пользователя").fill("admin");
  await page.getByLabel("Пароль", { exact: true }).fill("correct-horse-battery");
  await page.getByLabel("Повторите пароль").fill("correct-horse-battery");
  await page.getByRole("button", { name: "Создать администратора" }).click();
  await expect(page.getByText("Загружено 100/205")).toBeVisible();

  const newestItems = Array.from({ length: 3 }, (_, index) => ({
    id: `new-audit-${index}`,
    action: "New audit event",
    action_code: "new_audit_event",
    detail: `New event ${index}`,
    actor: "system",
    node_id: "ru",
    occurred_at: now,
    request_id: `new-request-${index}`,
    tone: "success",
  }));
  state.auditItems = [...newestItems, ...originalItems];

  await page.getByRole("button", { name: "Загрузить старые события (100/205)" }).click();
  await expect(page.getByText("Загружено 200/208")).toBeVisible();
  await expect(page.getByText("New audit event")).toHaveCount(3);
  await page.getByRole("button", { name: "Загрузить старые события (200/208)" }).click();
  await expect(page.getByText("Загружено 208/208")).toBeVisible();
  await expect(page.getByRole("button", { name: /Загрузить старые события/ })).toHaveCount(0);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Скачать загруженный JSONL" }).click();
  const download = await downloadPromise;
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const exported = await readFile(downloadPath!, "utf8");
  const exportedRequestIds = exported
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line).request_id as string);
  expect(exportedRequestIds).toHaveLength(208);
  expect(exportedRequestIds.slice(0, 3)).toEqual([
    "new-request-0",
    "new-request-1",
    "new-request-2",
  ]);
  expect(new Set(exportedRequestIds)).toEqual(
    new Set([
      ...newestItems.map((item) => item.request_id),
      ...originalItems.map((item) => item.request_id),
    ]),
  );

  const interiorItem = {
    id: "interior-audit",
    action: "Interior audit event",
    action_code: "interior_audit_event",
    detail: "A delayed record entered the already loaded ordering",
    actor: "system",
    node_id: "nl",
    occurred_at: now,
    request_id: "interior-request",
    tone: "warning",
  };
  const reorderedItems = [...state.auditItems!];
  reorderedItems.splice(50, 0, interiorItem);
  state.auditItems = reorderedItems;

  await page.getByRole("button", { name: "Обновить данные кластера" }).click();
  await expect(page.getByText("Загружено 100/209")).toBeVisible();
  await expect(page.getByText("Interior audit event")).toBeVisible();
  await page.getByRole("button", { name: "Загрузить старые события (100/209)" }).click();
  await expect(page.getByText("Загружено 200/209")).toBeVisible();
  await page.getByRole("button", { name: "Загрузить старые события (200/209)" }).click();
  await expect(page.getByText("Загружено 209/209")).toBeVisible();

  const interiorDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Скачать загруженный JSONL" }).click();
  const interiorDownload = await interiorDownloadPromise;
  const interiorDownloadPath = await interiorDownload.path();
  expect(interiorDownloadPath).not.toBeNull();
  const interiorExport = await readFile(interiorDownloadPath!, "utf8");
  const interiorRequestIds = interiorExport
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line).request_id as string);
  expect(interiorRequestIds).toHaveLength(209);
  expect(new Set(interiorRequestIds)).toEqual(new Set(["interior-request", ...exportedRequestIds]));
});

test("discards a delayed audit page after the authenticated session changes", async ({ page }) => {
  const now = new Date().toISOString();
  const oldSessionItems = Array.from({ length: 101 }, (_, index) => ({
    id: `old-audit-${index}`,
    action: "Old session event",
    action_code: "old_session_event",
    detail: index === 100 ? "old-session-private-marker" : `Old session ${index}`,
    actor: "old-operator",
    node_id: "ru",
    occurred_at: now,
    request_id: `old-request-${index}`,
    tone: "neutral",
  }));
  const state: MockState = {
    authoritativeUnauthorized: false,
    lateTokenRequests: [],
    logoutRequests: 0,
    primaryUnavailable: false,
    refreshGate: null,
    refreshRequests: 0,
    refreshStarted: null,
    sourceRequest: null,
    auditItems: oldSessionItems,
  };
  await installApi(page, state);
  await page.goto("/audit");
  await page.getByLabel("Токен первичной настройки").fill("one-time-bootstrap-token");
  await page.getByLabel("Имя пользователя").fill("admin");
  await page.getByLabel("Пароль", { exact: true }).fill("correct-horse-battery");
  await page.getByLabel("Повторите пароль").fill("correct-horse-battery");
  await page.getByRole("button", { name: "Создать администратора" }).click();
  await expect(page.getByText("Загружено 100/101")).toBeVisible();

  let releaseOldPage: () => void = () => undefined;
  state.auditPageGate = new Promise<void>((resolve) => {
    releaseOldPage = resolve;
  });
  const oldPageStarted = new Promise<void>((resolve) => {
    state.auditPageStarted = resolve;
  });
  await page.getByRole("button", { name: "Загрузить старые события (100/101)" }).click();
  await oldPageStarted;

  await page.getByRole("button", { name: "Выйти из Alert Hub" }).click();
  await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
  state.auditItems = [
    {
      id: "new-session-audit",
      action: "New session event",
      action_code: "new_session_event",
      detail: "new-session-only-marker",
      actor: "new-operator",
      node_id: "nl",
      occurred_at: now,
      request_id: "new-request",
      tone: "success",
    },
  ];
  await page.getByLabel("Имя пользователя").fill("second-admin");
  await page.getByLabel("Пароль", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Войти" }).last().click();
  await expect(page.getByText("New session event")).toBeVisible();
  await expect(page.getByText("Загружено 1/1")).toBeVisible();

  releaseOldPage();
  state.auditPageGate = null;
  await expect(page.getByText("old-session-private-marker")).toHaveCount(0);
  await expect(page.getByText("Загружено 1/1")).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Скачать загруженный JSONL" }).click();
  const download = await downloadPromise;
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const exported = await readFile(downloadPath!, "utf8");
  expect(
    exported
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line)),
  ).toEqual([expect.objectContaining({ request_id: "new-request" })]);
});

test("demo shell is accessible and responsive on a phone viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 768 });
  await page.addInitScript(() => {
    Object.defineProperty(window, "EventSource", { configurable: true, value: undefined });
    window.localStorage.setItem("alert-hub-ui-theme", "dark");
  });
  await page.route("**/api/v1/auth/refresh", (route) => fulfill(route, {}, 401));
  await page.route("**/api/v1/auth/bootstrap/status", (route) =>
    fulfill(route, { bootstrap_required: false }),
  );

  await page.goto("/");
  await expect(
    page.getByRole("img", { name: "Три автономных узла с синхронизацией журнала событий" }),
  ).toBeVisible();
  await expect(page.getByText("append-only синхронизация")).toBeVisible();
  const authVisuals = await page.evaluate(() => {
    const center = (selector: string) => {
      const rect = document.querySelector<HTMLElement>(selector)!.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    };
    const left = center(".auth-node--1 > span");
    const right = center(".auth-node--2 > span");
    const bottom = center(".auth-node--3 > span");
    const hub = center(".auth-topology__center .brand-mark");
    const bottomNode = document.querySelector<HTMLElement>(".auth-node--3 > span")!;
    const centerLabel = document.querySelector<HTMLElement>(".auth-topology__center small")!;
    const brand = document.querySelector<HTMLElement>(".auth-story > .brand")!;
    const languageSwitch = document.querySelector<HTMLElement>(".auth-language-switch")!;
    return {
      brandLanguageTopOffset: Math.abs(
        brand.getBoundingClientRect().top - languageSwitch.getBoundingClientRect().top,
      ),
      bottomOffset: Math.abs(bottom.x - (left.x + right.x) / 2),
      centerLabelGap:
        bottomNode.getBoundingClientRect().top - centerLabel.getBoundingClientRect().bottom,
      hubOffset: Math.abs(hub.x - bottom.x),
      nodeTopOffset: Math.abs(left.y - right.y),
      signInTabBackground: getComputedStyle(
        document.querySelector<HTMLElement>(".auth-tabs button.active")!,
      ).backgroundColor,
      submitBackground: getComputedStyle(document.querySelector<HTMLElement>(".auth-submit")!)
        .backgroundColor,
    };
  });
  expect(authVisuals).toMatchObject({
    signInTabBackground: "rgb(35, 35, 39)",
    submitBackground: "rgb(228, 228, 231)",
  });
  expect(authVisuals.nodeTopOffset).toBeLessThan(1);
  expect(authVisuals.brandLanguageTopOffset).toBeLessThan(1);
  expect(authVisuals.bottomOffset).toBeLessThan(1);
  expect(authVisuals.hubOffset).toBeLessThan(1);
  expect(authVisuals.centerLabelGap).toBeGreaterThan(8);
  const authLayout = await page.evaluate(() => ({
    clientHeight: document.documentElement.clientHeight,
    demoButtonWhiteSpace: getComputedStyle(
      document.querySelector<HTMLElement>(".auth-demo button")!,
    ).whiteSpace,
    rootLocked: document.documentElement.classList.contains("auth-open"),
    scrollHeight: document.documentElement.scrollHeight,
  }));
  expect(authLayout).toMatchObject({
    clientHeight: authLayout.scrollHeight,
    demoButtonWhiteSpace: "nowrap",
    rootLocked: true,
  });
  await expect(page.locator(".auth-screen .language-switch")).toBeVisible();
  await expect(page.locator(".auth-story > .brand small")).toHaveText("Центр мониторинга");
  await expect(page.getByRole("button", { name: "RU", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: /Открыть демо/ }).click();
  await expect(page.getByRole("main")).toBeVisible();
  await expect(page.locator(".overview-page .language-switch")).toHaveCount(0);
  await expect(page.getByRole("status").getByText("демо-режим", { exact: true })).toBeVisible();
  await expect(page.locator("html")).not.toHaveClass(/auth-open/);
  await expect(page.getByLabel("Grafana не настроена")).toBeVisible();
  await expect(page.getByRole("link", { name: "Открыть Grafana" })).toHaveCount(0);
  await expect(page.locator(".mobile-nav")).toBeVisible();
  const overflow = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
    offenders: [...document.querySelectorAll<HTMLElement>("body *")]
      .filter((element) => element.getBoundingClientRect().right > window.innerWidth + 1)
      .slice(0, 10)
      .map((element) => ({
        className: element.className,
        right: element.getBoundingClientRect().right,
        tag: element.tagName,
      })),
  }));
  expect(overflow, JSON.stringify(overflow)).toMatchObject({
    documentWidth: overflow.viewportWidth,
  });

  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  const serious = results.violations.filter((violation) =>
    ["serious", "critical"].includes(violation.impact ?? ""),
  );
  expect(serious).toEqual([]);

  await page.getByRole("button", { name: "Ещё" }).click();
  await page.getByRole("button", { name: "Каналы", exact: true }).click();
  await expect(page.locator(".delivery-ring")).toBeVisible();
  const deliveryRingLayout = await page.evaluate(() => {
    const ring = document.querySelector<HTMLElement>(".delivery-ring")!.getBoundingClientRect();
    const label = document
      .querySelector<HTMLElement>(".delivery-ring > span")!
      .getBoundingClientRect();
    return {
      bottomFits: label.bottom <= ring.bottom,
      leftFits: label.left >= ring.left,
      rightFits: label.right <= ring.right,
      topFits: label.top >= ring.top,
    };
  });
  expect(deliveryRingLayout).toEqual({
    bottomFits: true,
    leftFits: true,
    rightFits: true,
    topFits: true,
  });
  const deliveryRingAtOneHundred = await page.locator(".delivery-ring > span").evaluate((label) => {
    label.firstChild!.textContent = "100.0";
    const ring = label.parentElement!.getBoundingClientRect();
    const value = label.getBoundingClientRect();
    return {
      bottomFits: value.bottom <= ring.bottom - 10,
      leftFits: value.left >= ring.left + 10,
      rightFits: value.right <= ring.right - 10,
      topFits: value.top >= ring.top + 10,
    };
  });
  expect(deliveryRingAtOneHundred).toEqual({
    bottomFits: true,
    leftFits: true,
    rightFits: true,
    topFits: true,
  });

  await page.getByRole("button", { name: "Ещё" }).click();
  await page.getByRole("button", { name: "Настройки", exact: true }).click();
  await expect(page.getByRole("group", { name: "Тема интерфейса" })).toBeVisible();
  await expect(page.locator(".app-header .language-switch")).toHaveCount(0);
  await page.getByRole("button", { name: "Светлая", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#FFFFFF");
  expect(await page.evaluate(() => localStorage.getItem("alert-hub-ui-theme"))).toBe("light");

  await page.locator(".mobile-nav").getByRole("button", { name: "Инциденты" }).click();
  await expect(page.locator(".search-field")).toHaveCSS("background-color", "rgb(255, 255, 255)");
  await page.locator(".mobile-nav").getByRole("button", { name: "Ещё" }).click();
  await page.getByRole("button", { name: "Источники", exact: true }).click();
  await expect(page.locator(".section-summary-bar")).toHaveCSS(
    "background-color",
    "rgb(248, 250, 252)",
  );
  await page.locator(".mobile-nav").getByRole("button", { name: "Ещё" }).click();
  await page.getByRole("button", { name: "Кластер", exact: true }).click();
  await expect(page.locator(".cluster-summary-bar")).toHaveCSS(
    "background-color",
    "rgb(248, 250, 252)",
  );
  await page.locator(".mobile-nav").getByRole("button", { name: "Ещё" }).click();
  await page.getByRole("button", { name: "Журнал действий", exact: true }).click();
  await expect(page.locator(".audit-panel .search-field")).toHaveCSS(
    "background-color",
    "rgb(255, 255, 255)",
  );
  await expect(page.locator(".audit-panel .search-field")).toHaveCSS("overflow", "hidden");
  await expect(page.locator(".audit-panel .search-field input")).toHaveCSS(
    "text-overflow",
    "ellipsis",
  );
  await expect(page.locator(".segmented")).toHaveCSS("background-color", "rgb(248, 250, 252)");
  await page.locator(".mobile-nav").getByRole("button", { name: "Ещё" }).click();
  await page.getByRole("button", { name: "Настройки", exact: true }).click();
  await page.getByRole("button", { name: "EN", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
  await expect(page.locator(".sidebar .brand small")).toHaveText("Monitoring center");
  await expect(page).toHaveTitle("E2E Operations — Monitoring center");
  await expect(page.getByRole("button", { name: "EN", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

test.describe("service-worker offline lifecycle", () => {
  test.use({ serviceWorkers: "allow" });

  test("cold offline reopen is partitioned and read-only, then logout leaves a tombstone", async ({
    context,
    page,
  }) => {
    let recoverSession = false;
    let refreshNetworkFailure = false;
    await context.route("**/api/v1/auth/refresh", (route) => {
      if (refreshNetworkFailure) return route.abort("failed");
      return recoverSession
        ? fulfill(route, { access_token: token("recovered-session"), expires_in: 900 })
        : fulfill(route, {}, 401);
    });
    await context.route("**/api/v1/auth/me", (route) =>
      fulfill(route, { username: "recovered-admin" }),
    );
    await context.route("**/api/v1/auth/bootstrap/status", (route) =>
      fulfill(route, { bootstrap_required: false }),
    );
    await context.route("**/api/v1/incidents?*", (route) =>
      refreshNetworkFailure
        ? route.abort("failed")
        : fulfill(route, {
            items: [
              {
                id: "offline-list-live",
                title: "Recovered live list incident",
                description: "Fresh list loaded after session recovery.",
                severity: "warning",
                status: "acknowledged",
                source_name: "Prometheus",
                region: "EU",
                target: "offline-list-target",
                starts_at: "2026-09-02T11:00:00Z",
                last_event_at: "2026-09-02T12:05:00Z",
                labels: {},
                annotations: {},
              },
            ],
            total: 1,
            limit: 50,
            offset: 0,
            counts: {
              active: 1,
              open: 0,
              acknowledged: 1,
              resolved: 0,
              silenced: 0,
              all: 1,
            },
            bulk_limit: 500,
          }),
    );
    await context.route("**/api/v1/incidents/offline-detail", (route) =>
      refreshNetworkFailure
        ? route.abort("failed")
        : fulfill(route, {
            id: "offline-detail",
            title: "Recovered live incident",
            description: "Fresh detail loaded after session recovery.",
            severity: "warning",
            status: "acknowledged",
            source_name: "Prometheus",
            region: "EU",
            target: "offline-target",
            starts_at: "2026-09-02T11:00:00Z",
            last_event_at: "2026-09-02T12:05:00Z",
            labels: {},
            annotations: {},
            timeline: [
              {
                id: "offline-event-live",
                event_type: "acknowledged",
                label: "Recovered detail refreshed",
                detail: "Live response",
                occurred_at: "2026-09-02T12:05:00Z",
                origin_node_id: "eu",
              },
            ],
          }),
    );
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
    await page.evaluate(async () => {
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) {
        await new Promise<void>((resolve) => {
          navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), {
            once: true,
          });
        });
      }
    });

    await page.evaluate(async () => {
      const partition = "offline_session_123";
      localStorage.setItem(
        "alert-hub-session-partition-v1",
        JSON.stringify({ partition, savedAt: Date.now(), version: 1 }),
      );
      localStorage.removeItem("alert-hub-local-logout-v1");
      const shell = await caches.open("alert-hub-v7-shell");
      const shellUrls = [
        "/",
        ...[...document.querySelectorAll<HTMLScriptElement>("script[src]")].map(
          (element) => element.src,
        ),
        ...[...document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]')].map(
          (element) => element.href,
        ),
      ];
      await Promise.all([...new Set(shellUrls)].map((url) => shell.add(url)));
      const readCache = await caches.open(`alert-hub-v2-read-model-${partition}`);
      const entries: Record<string, unknown> = {
        "/api/v1/incidents?limit=100&view=compact": { incidents: [] },
        "/api/v1/incidents?limit=50&offset=0&view=compact&status=active": {
          items: [
            {
              id: "offline-list-cached",
              title: "Offline cached list incident",
              description: "Loaded from the dedicated partitioned incident-list cache.",
              severity: "critical",
              status: "open",
              source_name: "Prometheus",
              region: "EU",
              target: "offline-list-target",
              starts_at: "2026-09-02T11:00:00Z",
              last_event_at: "2026-09-02T12:00:00Z",
              labels: {},
              annotations: {},
            },
          ],
          total: 1,
          limit: 50,
          offset: 0,
          counts: {
            active: 1,
            open: 1,
            acknowledged: 0,
            resolved: 0,
            silenced: 0,
            all: 1,
          },
          bulk_limit: 500,
        },
        "/api/v1/incidents/offline-detail": {
          id: "offline-detail",
          title: "Offline cached incident",
          description: "Loaded from the partitioned authenticated read cache.",
          severity: "critical",
          status: "open",
          source_name: "Prometheus",
          region: "EU",
          target: "offline-target",
          starts_at: "2026-09-02T11:00:00Z",
          last_event_at: "2026-09-02T12:00:00Z",
          labels: {},
          annotations: {},
          timeline: [
            {
              id: "offline-event-cached",
              event_type: "firing",
              label: "Cached detail event",
              detail: "Partition-bound cached response",
              occurred_at: "2026-09-02T12:00:00Z",
              origin_node_id: "eu",
            },
          ],
        },
        "/api/v1/cluster/status": { cluster_event_count: 0, cursor: {}, nodes: [] },
        "/api/v1/sources": {
          sources: [
            {
              enabled: true,
              id: "offline-source",
              kind: "generic_json",
              name: "Offline cached source",
              region: "EU",
            },
          ],
        },
        "/api/v1/channels": { channels: [] },
        "/api/v1/routes": { routes: [] },
        "/api/v1/prometheus-datasources": { datasources: [] },
        "/api/v1/devices": { devices: [] },
        "/api/v1/audit?limit=100": { items: [] },
        "/api/v1/metrics/reachability": {
          cells: [],
          datasources: 0,
          detail: "No datasource in cached snapshot.",
          errors: [],
          status: "not_configured",
        },
        "/api/v1/metrics/summary": {
          acknowledged: 0,
          channels_enabled: 0,
          critical: 0,
          deliveries_24h: 0,
          delivery_rate: null,
          delivery_success_24h: 0,
          open: 0,
          outbox_pending: 0,
        },
        "/api/v1/metrics/queries/firing_alerts": {
          datasources: 1,
          errors: [],
          samples: [],
          status: "ok",
        },
        "/api/v1/metrics/queries/key_jobs_up": {
          datasources: 1,
          errors: [],
          samples: [],
          status: "ok",
        },
        "/api/v1/metrics/queries/alert_hub_health": {
          datasources: 1,
          errors: [],
          samples: [],
          status: "ok",
        },
        "/api/v1/metrics/statistics?window=7d": {
          window: "7d",
          generated_at: "2026-09-02T12:00:00Z",
          starts_at: "2026-08-26T12:00:00Z",
          ends_at: "2026-09-02T12:00:00Z",
          bucket_seconds: 21600,
          totals: {
            incidents_started: 0,
            incidents_resolved: 0,
            active_incidents: 0,
            active_critical: 0,
            acknowledgement_rate: null,
            resolution_rate: null,
            mean_time_to_acknowledge_seconds: null,
            mean_time_to_resolve_seconds: null,
            deliveries: 0,
            deliveries_succeeded: 0,
            deliveries_failed: 0,
            delivery_success_rate: null,
          },
          timeline: [],
          severities: [],
          sources: [],
          channels: [],
        },
      };
      await Promise.all(
        Object.entries(entries).map(([path, body]) =>
          readCache.put(
            new Request(new URL(path, window.location.origin)),
            new Response(JSON.stringify(body), {
              headers: { "Content-Type": "application/json" },
            }),
          ),
        ),
      );
    });

    await page.close();
    refreshNetworkFailure = true;
    await context.setOffline(true);
    const offlinePage = await context.newPage();
    await offlinePage.goto("/incidents");
    await expect(
      offlinePage.getByRole("heading", { name: "Инциденты", exact: true }),
    ).toBeVisible();
    await expect(
      offlinePage.getByText("Offline cached list incident", { exact: true }),
    ).toBeVisible();
    await expect(offlinePage.getByLabel("Выбрать Offline cached list incident")).toBeDisabled();
    await expect(offlinePage.getByRole("button", { name: "Применить", exact: true })).toHaveCount(
      0,
    );
    await expect(offlinePage.locator(".connection-banner")).toContainText("Нет подключения");

    await offlinePage.locator(".sidebar__nav").getByRole("button", { name: "Источники" }).click();
    await expect(
      offlinePage.getByRole("heading", { name: "Источники", exact: true }),
    ).toBeVisible();
    await expect(offlinePage.getByText("Offline cached source")).toBeVisible();
    await expect(offlinePage.locator(".connection-banner")).toContainText("Нет подключения");
    await expect(offlinePage.getByRole("button", { name: "Добавить источник" })).toBeDisabled();
    await expect(offlinePage.getByRole("button", { name: "Обновить токен" })).toBeDisabled();
    await expect
      .poll(() => offlinePage.evaluate(() => Boolean(navigator.serviceWorker.controller)))
      .toBe(true);

    await offlinePage.goto("/incidents/offline-detail");
    await expect(
      offlinePage.getByRole("heading", { name: "Offline cached incident" }),
    ).toBeVisible();
    await expect(offlinePage.getByText("Cached detail event")).toBeVisible();
    await expect(offlinePage.getByRole("button", { name: "Принять в работу" })).toBeDisabled();

    recoverSession = true;
    refreshNetworkFailure = false;
    await context.setOffline(false);
    await offlinePage.getByRole("button", { name: "Обновить данные кластера" }).click();
    await expect(offlinePage.getByLabel("Текущая учётная запись")).toContainText("recovered-admin");
    await expect(
      offlinePage.getByRole("heading", { name: "Recovered live incident" }),
    ).toBeVisible();
    await expect(offlinePage.getByText("Recovered detail refreshed")).toBeVisible();
    await offlinePage.locator(".sidebar__nav").getByRole("button", { name: "Инциденты" }).click();
    await expect(
      offlinePage.getByText("Recovered live list incident", { exact: true }),
    ).toBeVisible();
    await expect(offlinePage.getByLabel("Выбрать Recovered live list incident")).toBeEnabled();
    await offlinePage.locator(".sidebar__nav").getByRole("button", { name: "Источники" }).click();
    await expect(offlinePage.getByRole("button", { name: "Добавить источник" })).toBeEnabled();
    await context.setOffline(true);

    await offlinePage.getByRole("button", { name: "Выйти из Alert Hub" }).click();
    await expect(offlinePage.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
    await expect
      .poll(() =>
        offlinePage.evaluate(() => ({
          hint: localStorage.getItem("alert-hub-session-partition-v1"),
          tombstone: localStorage.getItem("alert-hub-local-logout-v1"),
        })),
      )
      .toMatchObject({ hint: null, tombstone: expect.any(String) });
    await offlinePage.reload();
    await expect(offlinePage.getByRole("heading", { name: "Вход в систему" })).toBeVisible();
    await context.setOffline(false);
  });
});

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
  checksDetails?: Record<string, Record<string, unknown>>;
  checksItems?: Array<Record<string, unknown>>;
  checksMode?: "disabled" | "ready" | "unavailable";
  checksWarningCodes?: string[];
  incidents?: Array<Record<string, unknown>>;
  lateTokenRequests: string[];
  logoutRequests: number;
  primaryUnavailable: boolean;
  refreshGate: Promise<void> | null;
  refreshRequests: number;
  refreshStarted: (() => void) | null;
  datasourcePatchRequest?: Record<string, unknown> | null;
  datasourceRequest?: Record<string, unknown> | null;
  sourceRequest: Record<string, unknown> | null;
  liveEventSource?: boolean;
  loginRequest?: Record<string, unknown> | null;
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
          queueMicrotask(() => this.onopen?.());
        }

        close() {}
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

    if (state.authoritativeUnauthorized && method === "GET") {
      await fulfill(route, { detail: "session revoked" }, 401);
      return;
    }
    if (state.primaryUnavailable && method === "GET") {
      await fulfill(route, { detail: "temporarily unavailable" }, 503);
      return;
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
    if (method === "GET" && path === "/incidents") {
      await fulfill(route, { incidents: state.incidents ?? [] });
      return;
    }
    if (method === "GET" && path.startsWith("/incidents/")) {
      const incidentId = decodeURIComponent(path.slice("/incidents/".length));
      const incident = state.incidents?.find((item) => item.id === incidentId);
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
      check_id: "simple-check",
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
      active_alerts: 1,
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
    items,
    details: {
      "simple-check": {
        ...items[0],
        results: [
          {
            source: null,
            scenario: null,
            variant: null,
            target: null,
            status: "up",
            status_reason: null,
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: null,
            ttfb_seconds: null,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [],
            assertions: [],
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
            source: "eu-west",
            scenario: "purchase",
            variant: "member",
            target: "Checkout",
            status: "up",
            status_reason: null,
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0.31,
            ttfb_seconds: 0.12,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [],
            assertions: [],
          },
          {
            source: "us-east",
            scenario: "purchase",
            variant: "guest",
            target: "Checkout",
            status: "down",
            status_reason: "invalid_data",
            success: false,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0.42,
            ttfb_seconds: 0.18,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [{ canary: "control", success: true, status_reason: null }],
            assertions: [{ key: "egress_match", success: false, status_reason: "mismatch" }],
          },
          {
            source: "eu-west",
            scenario: "refund",
            variant: null,
            target: "Checkout",
            status: "up",
            status_reason: null,
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0,
            ttfb_seconds: null,
            stale: false,
            data_incomplete: false,
            diagnostic_codes: [],
            canaries: [],
            assertions: [],
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

test("Checks dashboard, filters, grouping, matrix details, links, and mobile accessibility", async ({
  page,
}) => {
  const fixtures = checksFixtures();
  const state: MockState = {
    authoritativeUnauthorized: false,
    checksDetails: fixtures.details,
    checksItems: fixtures.items,
    checksMode: "ready",
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
  await expect(widget.locator(".checks-problem-row").first()).toContainText("Down check");
  await expect(widget.locator(".checks-summary__item--up strong")).toHaveText("1");
  await expect(widget.getByText("check_ttfb_unavailable")).toBeVisible();
  await page.locator(".sidebar__nav").getByRole("button", { name: "Checks" }).click();

  await expect(page.getByRole("heading", { name: "Checks", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "customer-paths" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Без группы" })).toBeVisible();
  await page
    .locator(".checks-summary")
    .getByRole("button", { name: /Не работает/ })
    .click();
  await expect(page.locator(".checks-table tbody tr")).toHaveCount(1);
  await expect(page.locator(".checks-table tbody tr")).toContainText("Down check");
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
  await page.getByRole("button", { name: "Открыть Check Complex customer path" }).click();

  await expect(page.getByRole("heading", { name: "Complex customer path" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Матрица Source × Scenario" })).toBeVisible();
  const variantSummary = page.locator("summary").filter({ hasText: "Variant · guest" });
  await variantSummary.focus();
  await expect(variantSummary).toBeFocused();
  await variantSummary.press("Enter");
  expect(
    await variantSummary.evaluate((element) => getComputedStyle(element).outlineStyle),
  ).not.toBe("none");
  await expect(page.getByText("control")).toBeVisible();
  await expect(page.getByText("egress_match")).toBeVisible();
  await expect(page.getByRole("link", { name: /Grafana/ })).toHaveAttribute(
    "href",
    /var-check_id=complex-check/,
  );
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
  await page.getByRole("button", { name: "Открыть Check Simple check" }).click();
  await expect(page.locator(".check-detail-hero")).toContainText("Работает");

  state.checksMode = "unavailable";
  await page.locator(".check-detail-actions").getByRole("button", { name: "Обновить" }).click();
  await expect(page.getByText("Результаты Checks недоступны")).toBeVisible();
  await expect(page.locator(".check-detail-hero")).toHaveCount(0);
  await expect(page.getByText(/Прежний успешный результат скрыт/)).toBeVisible();
  await expect(page.getByText("check_ttfb_unavailable")).toBeVisible();
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
  await page.locator(".mobile-nav").getByRole("button", { name: "Кластер" }).click();
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
        "/api/v1/incidents?limit=100": { incidents: [] },
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
    await offlinePage.goto("/sources");
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

    recoverSession = true;
    refreshNetworkFailure = false;
    await context.setOffline(false);
    await offlinePage.getByRole("button", { name: "Обновить данные кластера" }).click();
    await expect(offlinePage.getByLabel("Текущая учётная запись")).toContainText("recovered-admin");
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

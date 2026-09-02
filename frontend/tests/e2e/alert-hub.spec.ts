import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

function token(sessionId: string) {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode({ sid: sessionId, exp: 4_102_444_800 })}.test`;
}

async function fulfill(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

type MockState = {
  authoritativeUnauthorized: boolean;
  lateTokenRequests: string[];
  logoutRequests: number;
  primaryUnavailable: boolean;
  refreshGate: Promise<void> | null;
  refreshRequests: number;
  refreshStarted: (() => void) | null;
  sourceRequest: Record<string, unknown> | null;
};

async function installApi(page: Page, state: MockState) {
  await page.addInitScript(() => {
    Object.defineProperty(window, "EventSource", { configurable: true, value: undefined });
    localStorage.setItem("alert-hub-api-endpoints", JSON.stringify(["https://evil.invalid"]));
  });

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
      await fulfill(route, {
        access_token: token("session-two"),
        expires_in: 900,
        user: { username: "second-admin" },
      });
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

    if (state.authoritativeUnauthorized && method === "GET") {
      await fulfill(route, { detail: "session revoked" }, 401);
      return;
    }
    if (state.primaryUnavailable && method === "GET") {
      await fulfill(route, { detail: "temporarily unavailable" }, 503);
      return;
    }

    if (method === "GET" && path === "/incidents") {
      await fulfill(route, { incidents: [] });
      return;
    }
    if (method === "GET" && path === "/cluster/status") {
      await fulfill(route, { nodes: [], cursor: {}, cluster_event_count: 0 });
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
      await fulfill(route, { datasources: [] });
      return;
    }
    if (method === "GET" && path === "/devices") {
      await fulfill(route, { devices: [] });
      return;
    }
    if (method === "GET" && path === "/audit") {
      await fulfill(route, { items: [] });
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
    if (method === "GET" && path === "/metrics/summary") {
      await fulfill(route, {
        open: 0,
        acknowledged: 0,
        critical: 0,
        deliveries_24h: 0,
        delivery_success_24h: 0,
        delivery_rate: null,
        outbox_pending: 0,
        channels_enabled: 0,
        grafana_url: "https://grafana.example.test/d/alert-hub",
      });
      return;
    }
    await fulfill(route, { detail: `Unhandled test API ${method} ${path}` }, 404);
  });
}

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
    if (request.url().startsWith("https://evil.invalid")) evilRequests.push(request.url());
  });
  await installApi(page, state);

  await page.goto("/sources");
  await expect(page).toHaveTitle("E2E Operations — Distributed operations console");
  await expect(page.getByRole("heading", { name: "Bootstrap the cluster" })).toBeVisible();
  await page.getByLabel("Bootstrap token").fill("one-time-bootstrap-token");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("correct-horse-battery");
  await page.getByLabel("Confirm password").fill("correct-horse-battery");
  await page.getByRole("button", { name: "Create administrator" }).click();

  await expect(page).toHaveURL(/\/sources$/);
  await expect(page.getByRole("heading", { name: "Sources", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Add source" }).click();
  const sourceDialog = page.getByRole("dialog", { name: "Add source" });
  await expect(sourceDialog).toBeVisible();
  await sourceDialog.getByRole("button", { name: /Continue/ }).click();
  await sourceDialog.getByLabel("Source name").fill("Edge Alertmanager");
  await sourceDialog.getByLabel("Nearest region").fill("NL");
  await sourceDialog.getByLabel(/Allowed source IP/).fill("198.51.100.0/24");
  await sourceDialog.getByRole("button", { name: "Create source" }).click();
  await expect(sourceDialog.getByRole("heading", { name: "Source created" })).toBeVisible();
  await expect(sourceDialog.getByText("shown-once-source-token")).toBeVisible();
  const browserOrigin = await page.evaluate(() => window.location.origin);
  const absoluteWebhook = `${browserOrigin}/ingest/v1/alertmanager/source-created`;
  await expect(sourceDialog.getByText(absoluteWebhook, { exact: true })).toBeVisible();
  await expect(sourceDialog.getByText(/https:\/\/YOUR_HOST/)).toHaveCount(0);
  await expect(sourceDialog.getByText(/Ready Alertmanager receiver fragment/)).toBeVisible();
  expect(state.sourceRequest).toMatchObject({
    name: "Edge Alertmanager",
    kind: "alertmanager",
    region: "NL",
    allowed_cidrs: ["198.51.100.0/24"],
  });
  await sourceDialog.getByRole("button", { name: "I saved the token" }).click();
  await expect(page.getByText(absoluteWebhook, { exact: true })).toBeVisible();
  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Rotate token" }).click();
  const rotatedDialog = page.getByRole("dialog", { name: "Rotated source token" });
  await expect(rotatedDialog.getByText("rotated-source-token")).toBeVisible();
  await expect(rotatedDialog.getByText(absoluteWebhook, { exact: true })).toBeVisible();
  await expect(rotatedDialog.getByText(/https:\/\/YOUR_HOST/)).toHaveCount(0);
  await rotatedDialog.getByRole("button", { name: "I saved the new token" }).click();

  await page.getByRole("button", { name: "Overview" }).click();
  await expect(
    page.getByRole("heading", { name: "Prometheus operational evidence" }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Regional reachability" }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Firing alerts" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Prometheus / Alertmanager / Blackbox" }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Alert Hub sync / app health" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open Grafana" })).toHaveAttribute(
    "href",
    "https://grafana.example.test/d/alert-hub",
  );
  await page.getByRole("button", { name: "Sources" }).click();

  state.primaryUnavailable = true;
  await page.getByRole("button", { name: "Refresh cluster data" }).click();
  await expect(page.locator(".connection-banner")).toContainText("API nodes are unavailable");
  expect(evilRequests).toEqual([]);
  state.primaryUnavailable = false;

  await page.getByRole("button", { name: "Log out of Alert Hub" }).click();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await page.getByLabel("Username").fill("second-admin");
  await page.getByLabel("Password", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Sign in" }).last().click();

  await expect(page.getByText("Second-session source")).toBeVisible();
  await expect(page.getByText("Edge Alertmanager")).toHaveCount(0);

  state.authoritativeUnauthorized = true;
  await page.getByRole("button", { name: "Refresh cluster data" }).click();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page.getByText("Second-session source")).toHaveCount(0);
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem("alert-hub-session-partition-v1")))
    .toBeNull();
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
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("Username").fill("second-admin");
  await page.getByLabel("Password", { exact: true }).fill("second-password");
  await page.getByRole("button", { name: "Sign in" }).last().click();
  await expect(page.getByText("Second-session source")).toBeVisible();

  let releaseRefresh: () => void = () => undefined;
  state.refreshGate = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });
  const refreshStarted = new Promise<void>((resolve) => {
    state.refreshStarted = resolve;
  });
  state.authoritativeUnauthorized = true;
  await page.getByRole("button", { name: "Refresh cluster data" }).click();
  await refreshStarted;
  await page.getByRole("button", { name: "Log out of Alert Hub" }).click();
  releaseRefresh();

  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  expect(state.refreshRequests).toBe(refreshCount);
  expect(state.lateTokenRequests).toEqual([]);
});

test("demo shell is accessible and responsive on a phone viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => {
    Object.defineProperty(window, "EventSource", { configurable: true, value: undefined });
  });
  await page.route("**/api/v1/auth/refresh", (route) => fulfill(route, {}, 401));
  await page.route("**/api/v1/auth/bootstrap/status", (route) =>
    fulfill(route, { bootstrap_required: false }),
  );

  await page.goto("/");
  await page.getByRole("button", { name: /Open demo snapshot/ }).click();
  await expect(page.getByRole("main")).toBeVisible();
  await expect(page.getByLabel("Grafana not configured")).toBeVisible();
  await expect(page.getByRole("link", { name: "Open Grafana" })).toHaveCount(0);
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
    await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
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
      const shell = await caches.open("alert-hub-v3-shell");
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
    await expect(offlinePage.getByRole("heading", { name: "Sources", exact: true })).toBeVisible();
    await expect(offlinePage.getByText("Offline cached source")).toBeVisible();
    await expect(offlinePage.locator(".connection-banner")).toContainText("Offline mode");
    await expect(offlinePage.getByRole("button", { name: "Add source" })).toBeDisabled();
    await expect(offlinePage.getByRole("button", { name: "Rotate token" })).toBeDisabled();
    await expect
      .poll(() => offlinePage.evaluate(() => Boolean(navigator.serviceWorker.controller)))
      .toBe(true);

    recoverSession = true;
    refreshNetworkFailure = false;
    await context.setOffline(false);
    await offlinePage.getByRole("button", { name: "Refresh cluster data" }).click();
    await expect(offlinePage.getByLabel("Signed-in account")).toContainText("recovered-admin");
    await expect(offlinePage.getByRole("button", { name: "Add source" })).toBeEnabled();
    await context.setOffline(true);

    await offlinePage.getByRole("button", { name: "Log out of Alert Hub" }).click();
    await expect(offlinePage.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await expect
      .poll(() =>
        offlinePage.evaluate(() => ({
          hint: localStorage.getItem("alert-hub-session-partition-v1"),
          tombstone: localStorage.getItem("alert-hub-local-logout-v1"),
        })),
      )
      .toMatchObject({ hint: null, tombstone: expect.any(String) });
    await offlinePage.reload();
    await expect(offlinePage.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await context.setOffline(false);
  });
});

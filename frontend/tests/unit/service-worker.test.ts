import { readFileSync } from "node:fs";
import vm from "node:vm";
import { describe, expect, it, vi } from "vitest";

const origin = "https://hub.example.test";

type TestRequest = {
  destination: string;
  headers: Headers;
  method: string;
  mode: string;
  url: string;
};

type FetchEvent = {
  request: TestRequest;
  respondWith: (response: Promise<Response>) => void;
};

type NotificationOptions = {
  actions?: Array<{ action: string; title: string }>;
  data?: Record<string, unknown>;
  renotify?: boolean;
  tag?: string;
};

function request(path: string, mode = "cors", destination = ""): TestRequest {
  return {
    destination,
    headers: new Headers(),
    method: "GET",
    mode,
    url: new URL(path, origin).href,
  };
}

function cacheKey(value: string | TestRequest | Request) {
  const raw = typeof value === "string" ? value : value.url;
  return new URL(raw, origin).href;
}

class MemoryCache {
  readonly entries = new Map<string, Response>();

  async add(value: string | Request) {
    this.entries.set(cacheKey(value), new Response("precache"));
  }

  async match(value: string | TestRequest | Request) {
    return this.entries.get(cacheKey(value))?.clone();
  }

  async put(value: string | TestRequest | Request, response: Response) {
    this.entries.set(cacheKey(value), response.clone());
  }
}

function responseWithUrl(body: BodyInit, init: ResponseInit, url: string) {
  const response = new Response(body, init);
  Object.defineProperty(response, "url", { configurable: true, value: url });
  return response;
}

function createHarness() {
  const listeners: Record<string, (event: unknown) => void> = {};
  const stores = new Map<string, MemoryCache>();
  const networkCalls: Array<{ cache?: RequestCache; url: string }> = [];
  const notifications: Array<{ options: NotificationOptions; title: string }> = [];
  const navigations: string[] = [];
  const focusedClients: string[] = [];
  const openedWindows: string[] = [];
  const controls = {
    apiStatus: 200,
    manifestHangs: false,
    manifestOffline: false,
    navigationFails: false,
    navigationReturnsNull: false,
    navigationResponse: "html" as "external" | "html" | "text",
    networkOffline: false,
  };
  const caches = {
    delete: async (name: string) => stores.delete(name),
    keys: async () => [...stores.keys()],
    match: async (value: string | TestRequest | Request) => {
      for (const cache of stores.values()) {
        const response = await cache.match(value);
        if (response) return response;
      }
      return undefined;
    },
    open: async (name: string) => {
      let cache = stores.get(name);
      if (!cache) {
        cache = new MemoryCache();
        stores.set(name, cache);
      }
      return cache;
    },
  };
  const fetch = async (value: string | TestRequest | Request, init?: RequestInit) => {
    const url = typeof value === "string" ? new URL(value, origin).href : value.url;
    networkCalls.push({ cache: init?.cache, url });
    const pathname = new URL(url).pathname;
    if (
      controls.networkOffline ||
      (controls.manifestOffline && pathname === "/manifest.webmanifest")
    )
      throw new TypeError("offline");
    if (controls.manifestHangs && pathname === "/manifest.webmanifest") {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("The operation was aborted.", "AbortError")),
          { once: true },
        );
      });
    }
    if (pathname === "/runtime-config.js") return new Response("fresh-runtime-config");
    if (pathname === "/manifest.webmanifest") {
      return new Response('{"name":"Network Hub"}', {
        headers: { "Content-Type": "application/manifest+json" },
      });
    }
    if (pathname.startsWith("/api/v1/")) {
      return new Response('{"sources":[{"id":"cached-source"}]}', {
        headers: { "Content-Type": "application/json" },
        status: controls.apiStatus,
      });
    }
    if (["/incidents", "/settings"].includes(pathname)) {
      if (controls.navigationResponse === "text") {
        return responseWithUrl(
          "not an SPA document",
          { headers: { "Content-Type": "text/plain" } },
          url,
        );
      }
      const responseUrl =
        controls.navigationResponse === "external" ? "https://evil.invalid/login" : url;
      return responseWithUrl(
        "<!doctype html><title>fresh SPA shell</title>",
        {
          headers: { "Content-Type": "text/html" },
        },
        responseUrl,
      );
    }
    return new Response("backend-metrics");
  };
  const navigatedWindowClient = {
    focus: async () => {
      focusedClients.push("navigated");
    },
  };
  const windowClient = {
    focus: async () => {
      focusedClients.push("original");
    },
    navigate: async (url: string) => {
      navigations.push(url);
      if (controls.navigationFails) throw new Error("stale window client");
      return controls.navigationReturnsNull ? null : navigatedWindowClient;
    },
    url: `${origin}/settings`,
  };
  const self = {
    addEventListener: (name: string, listener: (event: unknown) => void) => {
      listeners[name] = listener;
    },
    clients: {
      claim: async () => undefined,
      matchAll: async () => [windowClient],
      openWindow: async (url: string) => {
        openedWindows.push(url);
      },
    },
    location: { origin },
    registration: {
      setAppBadge: async () => undefined,
      showNotification: async (title: string, options: NotificationOptions) => {
        notifications.push({ options, title });
      },
    },
    skipWaiting: async () => undefined,
  };
  vm.runInNewContext(readFileSync("public/sw.js", "utf8"), {
    AbortController,
    Headers,
    Request,
    Response,
    URL,
    caches,
    clearTimeout,
    fetch,
    self,
    setTimeout,
  });
  return {
    caches,
    controls,
    focusedClients,
    listeners,
    navigations,
    networkCalls,
    notifications,
    openedWindows,
  };
}

async function dispatchFetch(listener: (event: unknown) => void, testRequest: TestRequest) {
  let response: Promise<Response> | undefined;
  listener({
    request: testRequest,
    respondWith: (value: Promise<Response>) => {
      response = value;
    },
  } satisfies FetchEvent);
  return response;
}

async function dispatchWaitable(
  listener: (event: unknown) => void,
  event: Record<string, unknown>,
) {
  let pending: Promise<unknown> = Promise.resolve();
  listener({
    ...event,
    waitUntil: (value: Promise<unknown>) => {
      pending = value;
    },
  });
  await pending;
}

describe("service worker fetch boundaries", () => {
  it("does not intercept backend or unknown navigations as SPA shell requests", async () => {
    const { caches, listeners } = createHarness();
    const shell = await caches.open("alert-hub-v6-shell");
    await shell.put("/", new Response("known-good-shell"));

    const metricsResponse = await dispatchFetch(
      listeners.fetch,
      request("/metrics", "navigate", "document"),
    );
    expect(metricsResponse).toBeUndefined();
    expect(await (await shell.match("/"))?.text()).toBe("known-good-shell");
  });

  it("never caches or substitutes the VAPID public key", async () => {
    const { listeners } = createHarness();
    const vapidResponse = await dispatchFetch(
      listeners.fetch,
      request("/api/v1/push/vapid-public-key"),
    );
    expect(vapidResponse).toBeUndefined();
  });

  it("keeps runtime config network-only while manifest branding has an offline fallback", async () => {
    const { caches, controls, listeners, networkCalls } = createHarness();
    const shell = await caches.open("alert-hub-v6-shell");
    await shell.put("/runtime-config.js", new Response("stale-runtime-config"));

    const runtime = await dispatchFetch(
      listeners.fetch,
      request("/runtime-config.js", "cors", "script"),
    );
    expect(await (await runtime)?.text()).toBe("fresh-runtime-config");
    expect(await (await shell.match("/runtime-config.js"))?.text()).toBe("stale-runtime-config");
    expect(networkCalls.at(-1)).toMatchObject({ cache: "no-store" });

    const manifestRequest = request("/manifest.webmanifest", "cors", "manifest");
    const onlineManifest = await dispatchFetch(listeners.fetch, manifestRequest);
    expect(await (await onlineManifest)?.json()).toEqual({ name: "Network Hub" });
    expect(networkCalls.at(-1)).toMatchObject({ cache: "no-store" });
    controls.manifestOffline = true;
    const offlineManifest = await dispatchFetch(listeners.fetch, manifestRequest);
    expect(await (await offlineManifest)?.json()).toEqual({ name: "Network Hub" });
  });

  it("only replaces the offline shell with same-origin HTML from an SPA route", async () => {
    const { caches, controls, listeners } = createHarness();
    const shell = await caches.open("alert-hub-v6-shell");
    const response = await dispatchFetch(
      listeners.fetch,
      request("/incidents", "navigate", "document"),
    );
    expect(await (await response)?.text()).toContain("fresh SPA shell");
    const knownGood = await (await shell.match("/"))?.text();
    expect(knownGood).toContain("fresh SPA shell");

    controls.navigationResponse = "text";
    await dispatchFetch(listeners.fetch, request("/settings", "navigate", "document"));
    expect(await (await shell.match("/"))?.text()).toBe(knownGood);

    controls.navigationResponse = "external";
    await dispatchFetch(listeners.fetch, request("/settings", "navigate", "document"));
    expect(await (await shell.match("/"))?.text()).toBe(knownGood);
  });

  it("partitions verified JSON reads and falls back for network errors or 5xx, never 401", async () => {
    const { controls, listeners } = createHarness();
    const apiRequest = request("/api/v1/sources");
    apiRequest.headers.set("Authorization", "Bearer must-not-become-a-cache-key");
    apiRequest.headers.set("X-Alert-Hub-Cache-Partition", "session_partition_123");

    const online = await dispatchFetch(listeners.fetch, apiRequest);
    expect(await (await online)?.json()).toEqual({ sources: [{ id: "cached-source" }] });
    controls.apiStatus = 503;
    const unavailable = await dispatchFetch(listeners.fetch, apiRequest);
    expect((await unavailable)?.headers.get("X-Alert-Hub-Cache")).toBe("hit");
    expect(await (await unavailable)?.json()).toEqual({ sources: [{ id: "cached-source" }] });

    controls.apiStatus = 401;
    const unauthorized = await dispatchFetch(listeners.fetch, apiRequest);
    expect((await unauthorized)?.status).toBe(401);
    expect((await unauthorized)?.headers.get("X-Alert-Hub-Cache")).toBeNull();

    controls.networkOffline = true;
    const offline = await dispatchFetch(listeners.fetch, apiRequest);
    expect((await offline)?.headers.get("X-Alert-Hub-Cache")).toBe("hit");
  });
});

describe("service worker push contract", () => {
  it("shows a fallback notification when runtime branding stalls", async () => {
    vi.useFakeTimers();
    try {
      const { controls, listeners, notifications } = createHarness();
      controls.manifestHangs = true;
      const pushed = dispatchWaitable(listeners.push, {
        data: {
          json: () => ({ body: "A visible notification must not wait for branding." }),
        },
      });

      await vi.advanceTimersByTimeAsync(750);
      await pushed;
      expect(notifications).toHaveLength(1);
      expect(notifications[0]).toMatchObject({
        title: "Alert Hub: incident",
        options: { body: "A visible notification must not wait for branding." },
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("uses backend nested data/tag and confines notification clicks to SPA routes", async () => {
    const {
      caches,
      controls,
      focusedClients,
      listeners,
      navigations,
      notifications,
      openedWindows,
    } = createHarness();
    controls.manifestOffline = true;
    const shell = await caches.open("alert-hub-v6-shell");
    await shell.put(
      "/manifest.webmanifest",
      new Response('{"name":"Cached Operations"}', {
        headers: { "Content-Type": "application/manifest+json" },
      }),
    );

    await dispatchWaitable(listeners.push, {
      data: {
        json: () => ({
          body: "The checkout alert is firing.",
          data: {
            event_id: "event-42",
            incident_id: "incident-42",
            url: "/incidents/incident-42?from=push",
          },
          renotify: false,
          severity: "critical",
          status: "firing",
          tag: "incident-incident-42",
          title: "Cached Operations · FIRING",
        }),
      },
    });

    expect(notifications).toHaveLength(1);
    expect(notifications[0]).toMatchObject({
      options: {
        data: { incidentId: "incident-42", url: "/incidents/incident-42?from=push" },
        renotify: false,
        tag: "incident-incident-42",
      },
      title: "Cached Operations · FIRING",
    });
    expect(notifications[0].options.actions).toEqual([{ action: "open", title: "Open incident" }]);

    let closed = false;
    await dispatchWaitable(listeners.notificationclick, {
      notification: {
        close: () => {
          closed = true;
        },
        data: { url: "https://evil.invalid/phish" },
      },
    });
    expect(closed).toBe(true);
    expect(navigations).toEqual([`${origin}/incidents`]);
    expect(focusedClients).toEqual(["navigated"]);
    expect(openedWindows).toEqual([]);

    controls.navigationFails = true;
    await dispatchWaitable(listeners.notificationclick, {
      notification: {
        close: () => undefined,
        data: { url: "/incidents/incident-42" },
      },
    });
    expect(openedWindows).toEqual([`${origin}/incidents/incident-42`]);
  });

  it("opens a new app window when navigation returns no client", async () => {
    const { controls, focusedClients, listeners, navigations, openedWindows } = createHarness();
    controls.navigationReturnsNull = true;

    await dispatchWaitable(listeners.notificationclick, {
      notification: {
        close: () => undefined,
        data: { url: "/incidents/incident-42" },
      },
    });

    expect(navigations).toEqual([`${origin}/incidents/incident-42`]);
    expect(focusedClients).toEqual([]);
    expect(openedWindows).toEqual([`${origin}/incidents/incident-42`]);
  });
});

describe("service worker cache lifecycle", () => {
  it("accepts only same-origin build assets for the cold-offline shell", async () => {
    const { caches, listeners } = createHarness();
    await dispatchWaitable(listeners.message, {
      data: {
        type: "CACHE_SHELL_ASSETS",
        urls: [
          `${origin}/assets/index-safe.js`,
          `${origin}/runtime-config.js`,
          "https://evil.invalid/assets/index.js",
        ],
      },
    });
    const shell = await caches.open("alert-hub-v6-shell");
    expect(await shell.match(`${origin}/assets/index-safe.js`)).toBeDefined();
    expect(await shell.match(`${origin}/runtime-config.js`)).toBeUndefined();
    expect(await shell.match("https://evil.invalid/assets/index.js")).toBeUndefined();
  });

  it("prunes old session partitions and clears all authenticated read caches", async () => {
    const { caches, listeners } = createHarness();
    await caches.open("alert-hub-v2-read-model-session_one");
    await caches.open("alert-hub-v2-read-model-session_two");
    await caches.open("unrelated-cache");

    await dispatchWaitable(listeners.message, {
      data: { keep: "session_one", type: "PRUNE_READ_CACHES" },
    });
    expect(await caches.keys()).toEqual(["alert-hub-v2-read-model-session_one", "unrelated-cache"]);

    await dispatchWaitable(listeners.message, { data: { type: "CLEAR_READ_CACHE" } });
    expect(await caches.keys()).toEqual(["unrelated-cache"]);
  });
});

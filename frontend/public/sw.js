/* Alert Hub application shell and notification worker. */
const SHELL_CACHE = "alert-hub-v3-shell";
// Keep the authenticated read-cache prefix stable so a service-worker upgrade
// does not erase a verified session partition needed for a cold offline start.
const DATA_CACHE = "alert-hub-v2-read-model";
const SHELL = ["/", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"];
const SPA_ROUTE =
  /^\/(?:$|incidents(?:\/[^/]+)?|reachability|sources|channels|devices|cluster|audit|settings)\/?$/;

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => Promise.allSettled(SHELL.map((url) => cache.add(url))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== SHELL_CACHE && !key.startsWith(DATA_CACHE))
            .map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

function isReadableApi(url, request) {
  if (request.method !== "GET" || !url.pathname.startsWith("/api/v1/")) return false;
  return !url.pathname.includes("/auth/") && !url.pathname.endsWith("/stream");
}

async function readThrough(request) {
  const partition = request.headers.get("X-Alert-Hub-Cache-Partition");
  const cache =
    partition && /^[a-zA-Z0-9_-]{8,128}$/.test(partition)
      ? await caches.open(`${DATA_CACHE}-${partition}`)
      : null;
  // Never persist a bearer token or the private partition header in CacheStorage.
  // The opaque cache namespace provides isolation; the key only needs the URL.
  const cacheKey = new Request(request.url, { method: "GET" });
  const cachedResponse = async () => {
    const cached = await cache?.match(cacheKey);
    if (!cached) return null;
    const headers = new Headers(cached.headers);
    headers.set("X-Alert-Hub-Cache", "hit");
    return new Response(await cached.blob(), {
      status: cached.status,
      statusText: cached.statusText,
      headers,
    });
  };
  try {
    const response = await fetch(request);
    if (
      cache &&
      response.ok &&
      response.headers.get("content-type")?.includes("application/json")
    ) {
      await cache.put(cacheKey, response.clone()).catch(() => undefined);
    }
    if (response.status >= 500) {
      const cached = await cachedResponse();
      if (cached) return cached;
    }
    return response;
  } catch (error) {
    const cached = await cachedResponse();
    if (!cached) throw error;
    return cached;
  }
}

async function navigateThrough(request) {
  const cache = await caches.open(SHELL_CACHE);
  try {
    const response = await fetch(request);
    const responseUrl = new URL(response.url || request.url);
    if (
      response.ok &&
      responseUrl.origin === self.location.origin &&
      SPA_ROUTE.test(responseUrl.pathname) &&
      response.headers.get("content-type")?.includes("text/html")
    ) {
      await cache.put("/", response.clone());
    }
    return response;
  } catch {
    return (await cache.match(request)) || (await cache.match("/")) || Response.error();
  }
}

function runtimeFileThrough(request) {
  return fetch(request, { cache: "no-store" });
}

async function manifestThrough(request) {
  const cache = await caches.open(SHELL_CACHE);
  try {
    const response = await fetch(request, { cache: "no-store" });
    const responseUrl = new URL(response.url || request.url);
    const contentType = response.headers.get("content-type") || "";
    if (
      response.ok &&
      responseUrl.origin === self.location.origin &&
      responseUrl.pathname === "/manifest.webmanifest" &&
      (contentType.includes("application/manifest+json") ||
        contentType.includes("application/json"))
    ) {
      await cache.put(request, response.clone()).catch(() => undefined);
    }
    return response;
  } catch (error) {
    const cached = await cache.match(request);
    if (cached) return cached;
    throw error;
  }
}

async function assetThrough(request) {
  // Vite preview and some proxies emit `Vary: Origin`; a precache fetch has no
  // Origin header while module/style requests do. The cache is same-origin and
  // restricted to static destinations, so ignoring Vary here is both safe and
  // necessary for a real cold offline load.
  const cached = await caches.match(request, { ignoreVary: true });
  if (cached) return cached;
  const response = await fetch(request);
  if (response.ok && new URL(request.url).origin === self.location.origin) {
    const cache = await caches.open(SHELL_CACHE);
    await cache.put(request, response.clone());
  }
  return response;
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (isReadableApi(url, request)) {
    event.respondWith(readThrough(request));
    return;
  }
  if (request.mode === "navigate" && SPA_ROUTE.test(url.pathname)) {
    event.respondWith(navigateThrough(request));
    return;
  }
  if (url.pathname === "/runtime-config.js") {
    event.respondWith(runtimeFileThrough(request));
    return;
  }
  if (url.pathname === "/manifest.webmanifest") {
    event.respondWith(manifestThrough(request));
    return;
  }
  if (["style", "script", "font", "image"].includes(request.destination)) {
    event.respondWith(assetThrough(request));
  }
});

self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data?.json() || {};
  } catch {
    payload = { body: event.data?.text() || "A new incident event arrived." };
  }
  event.waitUntil(
    (async () => {
      const payloadData =
        payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)
          ? payload.data
          : {};
      const incidentId =
        payloadData.incident_id ||
        payloadData.incidentId ||
        payload.incident_id ||
        payload.incidentId ||
        payload.id;
      const status = String(payload.status || payload.event_type || "firing").toLowerCase();
      const resolved = status === "resolved";
      let appName = "Alert Hub";
      try {
        let manifestResponse;
        try {
          manifestResponse = await fetch("/manifest.webmanifest", { cache: "no-store" });
          if (!manifestResponse.ok) throw new Error("manifest unavailable");
        } catch {
          manifestResponse = await caches.match("/manifest.webmanifest");
        }
        if (!manifestResponse) throw new Error("manifest unavailable");
        const manifest = await manifestResponse.json();
        if (typeof manifest.name === "string" && manifest.name.trim())
          appName = manifest.name.trim();
      } catch {
        // A visible fallback notification is more important than runtime branding.
      }
      const title =
        payload.title || (resolved ? `${appName}: incident resolved` : `${appName}: incident`);
      const fallbackUrl = incidentId
        ? `/incidents/${encodeURIComponent(incidentId)}`
        : "/incidents";
      const options = {
        body:
          payload.body ||
          payload.description ||
          (resolved
            ? "The incident is no longer firing."
            : `Open ${appName} for incident details.`),
        tag:
          typeof payload.tag === "string" && payload.tag.trim()
            ? payload.tag.trim().slice(0, 128)
            : incidentId
              ? `incident-${incidentId}`
              : "alert-hub-event",
        renotify: typeof payload.renotify === "boolean" ? payload.renotify : !resolved,
        requireInteraction: !resolved && payload.severity === "critical",
        icon: "/icon-192.png",
        badge: "/icon-192.png",
        data: {
          url: safeSpaDestination(payloadData.url, fallbackUrl),
          incidentId,
        },
        actions: incidentId ? [{ action: "open", title: "Open incident" }] : [],
      };
      await Promise.all([
        self.registration.showNotification(title, options),
        typeof self.registration.setAppBadge === "function"
          ? self.registration.setAppBadge(Number(payload.unread_count || 1)).catch(() => undefined)
          : Promise.resolve(),
      ]);
    })(),
  );
});

function safeSpaDestination(value, fallback = "/incidents") {
  try {
    const url = new URL(
      typeof value === "string" && value ? value : fallback,
      self.location.origin,
    );
    if (url.origin !== self.location.origin || !SPA_ROUTE.test(url.pathname)) return fallback;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return fallback;
  }
}

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const destination = new URL(
    safeSpaDestination(event.notification.data?.url),
    self.location.origin,
  ).href;
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(async (windows) => {
      for (const client of windows) {
        if (new URL(client.url).origin === self.location.origin) {
          await client.navigate(destination);
          return client.focus();
        }
      }
      return self.clients.openWindow(destination);
    }),
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
  if (event.data?.type === "CACHE_SHELL_ASSETS") {
    const urls = (Array.isArray(event.data.urls) ? event.data.urls : [])
      .slice(0, 16)
      .flatMap((value) => {
        try {
          const url = new URL(String(value), self.location.origin);
          return url.origin === self.location.origin && url.pathname.startsWith("/assets/")
            ? [url.href]
            : [];
        } catch {
          return [];
        }
      });
    event.waitUntil(
      caches
        .open(SHELL_CACHE)
        .then((cache) =>
          Promise.allSettled(urls.map((url) => cache.add(new Request(url, { cache: "reload" })))),
        ),
    );
  }
  if (event.data?.type === "CLEAR_READ_CACHE") {
    event.waitUntil(
      caches
        .keys()
        .then((keys) =>
          Promise.all(
            keys.filter((key) => key.startsWith(DATA_CACHE)).map((key) => caches.delete(key)),
          ),
        ),
    );
  }
  if (event.data?.type === "PRUNE_READ_CACHES") {
    const keep = String(event.data.keep || "");
    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(keep)) return;
    const keepName = `${DATA_CACHE}-${keep}`;
    event.waitUntil(
      caches
        .keys()
        .then((keys) =>
          Promise.all(
            keys
              .filter((key) => key.startsWith(DATA_CACHE) && key !== keepName)
              .map((key) => caches.delete(key)),
          ),
        ),
    );
  }
});

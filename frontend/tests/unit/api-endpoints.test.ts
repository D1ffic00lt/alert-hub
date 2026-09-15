import { describe, expect, it, vi } from "vitest";

import {
  ApiEndpointManager,
  normalizePublicApiOrigin,
  readApiRuntimeConfig,
} from "../../app/api/endpoints";

const DEAD = "https://api-de.alerts.example";
const LIVE = "https://api-ru.alerts.example";

function clientManager(fetchImpl: typeof fetch) {
  return new ApiEndpointManager(
    {
      mode: "client-failover",
      nodePublicApiUrl: DEAD,
      candidates: [DEAD, LIVE],
    },
    { fetchImpl, locationOrigin: "https://alerts.example", probeTimeoutMs: 100 },
  );
}

describe("API endpoint manager", () => {
  it("accepts only bounded, exact HTTPS origins from immutable runtime config", () => {
    expect(normalizePublicApiOrigin("HTTPS://Api-RU.Example:443/")).toBe("https://api-ru.example");
    for (const value of [
      "http://api.example",
      "https://user:secret@api.example",
      "https://api.example/path",
      "https://api.example?region=ru",
      "https://api.example\\@evil.test",
    ]) {
      expect(normalizePublicApiOrigin(value)).toBeNull();
    }
    const config = readApiRuntimeConfig({
      apiHaMode: "client-failover",
      nodePublicApiUrl: DEAD,
      publicApiCandidates: [DEAD, LIVE, ...Array.from({ length: 10 }, (_, i) => `https://n${i}.x`)],
    });
    expect(config.candidates).toHaveLength(8);
    expect(config.candidates.slice(0, 2)).toEqual([DEAD, LIVE]);
    expect(config.warning).toBeNull();

    const duplicateConfig = readApiRuntimeConfig({
      apiHaMode: "client-failover",
      nodePublicApiUrl: DEAD,
      publicApiCandidates: [LIVE, LIVE],
    });
    expect(duplicateConfig.warning).toBe("duplicate-origins");
  });

  it("diagnoses cluster nodes that collapse to one advertised API origin", () => {
    const manager = clientManager(vi.fn() as typeof fetch);

    manager.addVerifiedCandidates([LIVE, LIVE, LIVE]);

    expect(manager.snapshot()).toMatchObject({
      degraded: true,
      warning: "duplicate-origins",
    });
  });

  it("shares bounded cold-start probes and selects a healthy API before a mutation", async () => {
    const requests: Array<{ method: string; url: string }> = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requests.push({ method, url });
      if (url === `${DEAD}/health/ready`) throw new TypeError("network unavailable");
      if (url === `${LIVE}/health/ready`) return new Response("{}", { status: 200 });
      if (url === `${LIVE}/api/v1/incidents/incident-1/acknowledge`) {
        return new Response("{}", { status: 200 });
      }
      throw new Error(`unexpected request ${method} ${url}`);
    }) as typeof fetch;
    const manager = clientManager(fetchImpl);

    await Promise.all([manager.prepare(), manager.prepare()]);
    const response = await manager.fetchApi("/incidents/incident-1/acknowledge", {
      method: "POST",
    });

    expect(response.status).toBe(200);
    expect(manager.snapshot()).toMatchObject({
      activeOrigin: LIVE,
      lastSwitchAt: expect.any(Number),
      reason: "A health probe selected a healthy API endpoint",
    });
    expect(requests.filter(({ url }) => url.endsWith("/health/ready"))).toHaveLength(2);
    expect(requests.filter(({ method }) => method === "POST")).toEqual([
      { method: "POST", url: `${LIVE}/api/v1/incidents/incident-1/acknowledge` },
    ]);
  });

  it("fails over reads on network errors and 5xx, but not on an authoritative 4xx", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (new URL(url).origin === DEAD) return new Response("{}", { status: 503 });
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const manager = clientManager(fetchImpl);

    expect((await manager.fetchApi("/incidents")).status).toBe(200);
    expect(calls.filter((url) => url.includes("/api/v1/"))).toEqual([
      `${DEAD}/api/v1/incidents`,
      `${LIVE}/api/v1/incidents`,
    ]);
    expect(calls.filter((url) => url.endsWith("/health/ready"))).toEqual([`${LIVE}/health/ready`]);

    const unauthorizedFetch = vi.fn(async () => new Response("{}", { status: 401 }));
    const unauthorized = clientManager(unauthorizedFetch as typeof fetch);
    expect((await unauthorized.fetchApi("/auth/me")).status).toBe(401);
    expect(unauthorizedFetch).toHaveBeenCalledTimes(1);
  });

  it("retries a source-local Check 404 on healthy APIs without changing its identifier", async () => {
    const path = "/checks/checkout%3Aeu%2Bcanary";
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      return new Response("{}", {
        status: new URL(url).origin === DEAD ? 404 : 200,
      });
    }) as typeof fetch;
    const manager = clientManager(fetchImpl);

    const response = await manager.fetchApi(path, {}, { retryNotFound: true });

    expect(response.status).toBe(200);
    expect(calls).toEqual([`${DEAD}/api/v1${path}`, `${LIVE}/api/v1${path}`]);
    expect(manager.snapshot().activeOrigin).toBe(DEAD);
  });

  it("returns an explicit Check 404 after every healthy API reports it missing", async () => {
    const fetchImpl = vi.fn(async () => new Response("{}", { status: 404 })) as typeof fetch;
    const manager = clientManager(fetchImpl);

    expect((await manager.fetchApi("/checks/missing", {}, { retryNotFound: true })).status).toBe(
      404,
    );
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("shares recovery probing when concurrent reads fail on the active endpoint", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url === `${LIVE}/health/ready`) return new Response("{}", { status: 200 });
      if (new URL(url).origin === DEAD) return new Response("{}", { status: 503 });
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const manager = clientManager(fetchImpl);

    const responses = await Promise.all([
      manager.fetchApi("/incidents"),
      manager.fetchApi("/cluster/status"),
    ]);

    expect(responses.map((response) => response.status)).toEqual([200, 200]);
    expect(calls.filter((url) => url === `${LIVE}/health/ready`)).toHaveLength(1);
  });

  it("bounds a hanging read attempt and continues on a healthy reserve", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(
      async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const url = String(input);
        calls.push(url);
        if (url === `${DEAD}/api/v1/incidents`) {
          return await new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              "abort",
              () => reject(Object.assign(new Error("timed out"), { name: "AbortError" })),
              { once: true },
            );
          });
        }
        return new Response("{}", { status: 200 });
      },
    ) as typeof fetch;
    const manager = new ApiEndpointManager(
      {
        mode: "client-failover",
        nodePublicApiUrl: DEAD,
        candidates: [DEAD, LIVE],
      },
      {
        fetchImpl,
        locationOrigin: "https://alerts.example",
        probeTimeoutMs: 20,
        requestTimeoutMs: 5,
      },
    );

    expect((await manager.fetchApi("/incidents")).status).toBe(200);
    expect(calls).toEqual([
      `${DEAD}/api/v1/incidents`,
      `${LIVE}/health/ready`,
      `${LIVE}/api/v1/incidents`,
    ]);
  });

  it("never replays an ordinary mutation after an ambiguous network failure", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/health/ready")) return new Response("{}", { status: 200 });
      throw new TypeError("connection lost after send");
    }) as typeof fetch;
    const manager = clientManager(fetchImpl);

    await expect(manager.fetchApi("/routes", { method: "POST" })).rejects.toThrow(
      "connection lost after send",
    );
    expect(calls.filter((url) => url.endsWith("/api/v1/routes"))).toEqual([
      `${DEAD}/api/v1/routes`,
    ]);
  });

  it("may recover a refresh operation through another eligible API", async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/health/ready")) return new Response("{}", { status: 200 });
      if (new URL(url).origin === DEAD) return new Response("{}", { status: 502 });
      return new Response('{"access_token":"token"}', { status: 200 });
    }) as typeof fetch;
    const manager = clientManager(fetchImpl);

    expect(
      (await manager.fetchApi("/auth/refresh", { method: "POST" }, { replayRefresh: true })).status,
    ).toBe(200);
    expect(calls.filter((url) => url.endsWith("/api/v1/auth/refresh"))).toEqual([
      `${DEAD}/api/v1/auth/refresh`,
      `${LIVE}/api/v1/auth/refresh`,
    ]);
  });
});

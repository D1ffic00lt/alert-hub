export const API_PATH_PREFIX = "/api/v1";

export type ApiHaMode = "single" | "client-failover" | "proxy-failover" | "external";
export type ApiEndpointHealth = "unknown" | "healthy" | "backoff";

export type ApiEndpointDiagnostic = {
  origin: string;
  displayOrigin: string;
  health: ApiEndpointHealth;
  active: boolean;
  failures: number;
  retryAt: number | null;
  reason: string | null;
};

export type ApiEndpointSnapshot = {
  mode: ApiHaMode;
  activeOrigin: string;
  displayActiveOrigin: string;
  degraded: boolean;
  reason: string | null;
  warning: "duplicate-origins" | null;
  lastSwitchAt: number | null;
  endpoints: ApiEndpointDiagnostic[];
};

export type ApiRuntimeConfig = {
  mode: ApiHaMode;
  nodePublicApiUrl: string | null;
  candidates: string[];
  warning?: "duplicate-origins" | null;
};

type RuntimeConfigValue = {
  apiHaMode?: unknown;
  nodePublicApiUrl?: unknown;
  publicApiCandidates?: unknown;
};

type EndpointState = {
  failures: number;
  healthy: boolean;
  retryAt: number;
  reason: string | null;
};

type EndpointManagerOptions = {
  fetchImpl?: typeof fetch;
  now?: () => number;
  locationOrigin?: string;
  probeTimeoutMs?: number;
  requestTimeoutMs?: number;
  mutationTimeoutMs?: number;
};

const API_HA_MODES = new Set<ApiHaMode>([
  "single",
  "client-failover",
  "proxy-failover",
  "external",
]);
const MAX_API_CANDIDATES = 8;
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;

export function normalizePublicApiOrigin(value: unknown): string | null {
  if (typeof value !== "string" || !value || /[\\\s]/u.test(value)) return null;
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

export function readApiRuntimeConfig(value: RuntimeConfigValue | undefined): ApiRuntimeConfig {
  const rawMode = typeof value?.apiHaMode === "string" ? value.apiHaMode : "single";
  const mode = API_HA_MODES.has(rawMode as ApiHaMode) ? (rawMode as ApiHaMode) : "single";
  const nodePublicApiUrl = normalizePublicApiOrigin(value?.nodePublicApiUrl);
  const rawCandidates = Array.isArray(value?.publicApiCandidates) ? value.publicApiCandidates : [];
  const normalizedRuntimeCandidates = rawCandidates
    .map(normalizePublicApiOrigin)
    .filter((item): item is string => Boolean(item));
  const uniqueRuntimeCandidates = [...new Set(normalizedRuntimeCandidates)];
  const candidates = [
    ...new Set(
      [nodePublicApiUrl, ...uniqueRuntimeCandidates].filter((item): item is string =>
        Boolean(item),
      ),
    ),
  ].slice(0, MAX_API_CANDIDATES);
  return {
    mode,
    nodePublicApiUrl,
    candidates,
    warning:
      normalizedRuntimeCandidates.length === uniqueRuntimeCandidates.length
        ? null
        : "duplicate-origins",
  };
}

function defaultLocationOrigin() {
  return typeof window === "undefined" ? "https://localhost" : window.location.origin;
}

function displayOrigin(origin: string, locationOrigin: string) {
  return origin || locationOrigin;
}

export class ApiEndpointManager {
  readonly mode: ApiHaMode;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly locationOrigin: string;
  private readonly probeTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly mutationTimeoutMs: number;
  private readonly states = new Map<string, EndpointState>();
  private readonly listeners = new Set<() => void>();
  private candidates: string[];
  private activeOrigin: string;
  private prepareInFlight: Promise<string> | null = null;
  private failoverEnabled = true;
  private configurationWarning: "duplicate-origins" | null;
  private lastSwitchAt: number | null = null;
  private lastSwitchReason: string | null = null;

  constructor(config: ApiRuntimeConfig, options: EndpointManagerOptions = {}) {
    this.mode = config.mode;
    this.fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
    this.now = options.now ?? Date.now;
    this.locationOrigin = options.locationOrigin ?? defaultLocationOrigin();
    this.probeTimeoutMs = options.probeTimeoutMs ?? 2_500;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 2_500;
    this.mutationTimeoutMs = options.mutationTimeoutMs ?? 10_000;
    this.candidates =
      config.mode === "client-failover" && config.candidates.length ? config.candidates : [""];
    this.activeOrigin = this.candidates[0] ?? "";
    this.configurationWarning = config.warning ?? null;
    for (const origin of this.candidates) this.ensureState(origin);
  }

  setFailoverEnabled(enabled: boolean) {
    this.failoverEnabled = enabled;
    this.emit();
  }

  addVerifiedCandidates(values: unknown[]) {
    if (this.mode !== "client-failover") return;
    const normalized = values
      .map(normalizePublicApiOrigin)
      .filter((item): item is string => Boolean(item));
    const additions = [...new Set(normalized)];
    const warningChanged =
      normalized.length > additions.length && this.configurationWarning === null;
    if (normalized.length > additions.length) {
      this.configurationWarning = "duplicate-origins";
    }
    const next = [...new Set([...this.candidates, ...additions])].slice(0, MAX_API_CANDIDATES);
    if (next.length === this.candidates.length) {
      if (warningChanged) this.emit();
      return;
    }
    this.candidates = next;
    for (const origin of next) this.ensureState(origin);
    this.emit();
  }

  subscribe(listener: () => void) {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  snapshot(): ApiEndpointSnapshot {
    const activeState = this.ensureState(this.activeOrigin);
    const endpoints = this.candidates.map((origin) => {
      const state = this.ensureState(origin);
      const health: ApiEndpointHealth =
        state.retryAt > this.now() ? "backoff" : state.healthy ? "healthy" : "unknown";
      return {
        origin,
        displayOrigin: displayOrigin(origin, this.locationOrigin),
        health,
        active: origin === this.activeOrigin,
        failures: state.failures,
        retryAt: state.retryAt || null,
        reason: state.reason,
      };
    });
    const unavailable = endpoints.filter((endpoint) => endpoint.health === "backoff").length;
    const degraded =
      unavailable > 0 ||
      this.activeOrigin !== this.candidates[0] ||
      this.configurationWarning !== null;
    return {
      mode: this.mode,
      activeOrigin: this.activeOrigin,
      displayActiveOrigin: displayOrigin(this.activeOrigin, this.locationOrigin),
      degraded,
      reason: degraded
        ? (activeState.reason ??
          this.lastSwitchReason ??
          `${unavailable} API endpoint(s) are in backoff`)
        : null,
      warning: this.configurationWarning,
      lastSwitchAt: this.lastSwitchAt,
      endpoints,
    };
  }

  apiUrl(path: string) {
    return `${this.activeOrigin}${API_PATH_PREFIX}${path}`;
  }

  async prepare(force = false): Promise<string> {
    if (this.mode !== "client-failover" || !this.failoverEnabled) return this.activeOrigin;
    const active = this.ensureState(this.activeOrigin);
    if (!force && active.healthy && active.retryAt <= this.now()) return this.activeOrigin;
    if (this.prepareInFlight) return this.prepareInFlight;
    const pending = (async () => {
      const ordered = this.orderedCandidates(force);
      const results = await Promise.all(ordered.map((origin) => this.probe(origin)));
      const selected = ordered.find((_origin, index) => results[index]);
      if (selected !== undefined) {
        this.promote(selected, "A health probe selected a healthy API endpoint");
        return selected;
      }
      return this.activeOrigin;
    })();
    this.prepareInFlight = pending;
    try {
      return await pending;
    } finally {
      if (this.prepareInFlight === pending) this.prepareInFlight = null;
    }
  }

  async fetchApi(
    path: string,
    init: RequestInit = {},
    options: { replayRefresh?: boolean; revalidateBeforeMutation?: boolean } = {},
  ): Promise<Response> {
    const method = (init.method ?? "GET").toUpperCase();
    const safeRead = method === "GET" || method === "HEAD";
    const canReplay =
      this.mode === "client-failover" &&
      this.failoverEnabled &&
      (safeRead || options.replayRefresh === true);
    if (!safeRead && options.revalidateBeforeMutation !== false) await this.prepare();
    const attempted = new Set<string>();
    const maximumAttempts = canReplay ? this.candidates.length : 1;
    const timeoutMs =
      safeRead || options.replayRefresh ? this.requestTimeoutMs : this.mutationTimeoutMs;
    let firstRetryableResponse: Response | null = null;
    let lastError: unknown = null;
    while (attempted.size < maximumAttempts) {
      const origin = (canReplay ? this.orderedCandidates(false) : [this.activeOrigin]).find(
        (candidate) => !attempted.has(candidate),
      );
      if (origin === undefined) break;
      attempted.add(origin);
      try {
        const response = await this.fetchWithTimeout(
          `${origin}${API_PATH_PREFIX}${path}`,
          init,
          timeoutMs,
        );
        if (response.status < 500) {
          this.markHealthy(origin);
          this.promote(origin, "A request failed over after a network or server error");
          return response;
        }
        firstRetryableResponse ??= response;
        this.markFailed(origin, `HTTP ${response.status}`);
        if (!canReplay) return response;
      } catch (error) {
        if (init.signal?.aborted) throw error;
        lastError = error;
        this.markFailed(origin, error instanceof Error ? error.name : "network error");
        if (!canReplay) throw error;
      }
      if (attempted.size < maximumAttempts) await this.prepare();
    }
    if (firstRetryableResponse) return firstRetryableResponse;
    throw lastError instanceof Error ? lastError : new Error("No API endpoint responded");
  }

  private orderedCandidates(includeBackoff: boolean) {
    const ordered = [
      this.activeOrigin,
      ...this.candidates.filter((origin) => origin !== this.activeOrigin),
    ];
    if (!this.failoverEnabled) return ordered.slice(0, 1);
    const now = this.now();
    const available = ordered.filter(
      (origin) => includeBackoff || this.ensureState(origin).retryAt <= now,
    );
    return available.length ? available : ordered.slice(0, 1);
  }

  private async fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number) {
    const controller = new AbortController();
    const callerSignal = init.signal;
    const forwardCallerAbort = () => controller.abort(callerSignal?.reason);
    if (callerSignal?.aborted) forwardCallerAbort();
    else callerSignal?.addEventListener("abort", forwardCallerAbort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener("abort", forwardCallerAbort);
    }
  }

  private async probe(origin: string) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.probeTimeoutMs);
    try {
      const response = await this.fetchImpl(`${origin}/health/ready`, {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (response.ok) {
        this.markHealthy(origin);
        return true;
      }
      this.markFailed(origin, `health HTTP ${response.status}`);
      return false;
    } catch (error) {
      this.markFailed(origin, error instanceof Error ? error.name : "health network error");
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  private ensureState(origin: string) {
    let state = this.states.get(origin);
    if (!state) {
      state = { failures: 0, healthy: false, retryAt: 0, reason: null };
      this.states.set(origin, state);
    }
    return state;
  }

  private markHealthy(origin: string) {
    const state = this.ensureState(origin);
    state.failures = 0;
    state.healthy = true;
    state.retryAt = 0;
    state.reason = null;
    this.emit();
  }

  private markFailed(origin: string, reason: string) {
    const state = this.ensureState(origin);
    state.failures += 1;
    state.healthy = false;
    state.reason = reason;
    state.retryAt =
      this.now() +
      Math.min(INITIAL_BACKOFF_MS * 2 ** Math.min(state.failures - 1, 5), MAX_BACKOFF_MS);
    this.emit();
  }

  private promote(origin: string, reason: string) {
    if (origin === this.activeOrigin) return;
    this.activeOrigin = origin;
    this.lastSwitchAt = this.now();
    this.lastSwitchReason = reason;
    this.emit();
  }

  private emit() {
    for (const listener of this.listeners) listener();
  }
}

const globalRuntimeConfig = globalThis.__ALERT_HUB_CONFIG__ as RuntimeConfigValue | undefined;
export const apiEndpointManager = new ApiEndpointManager(readApiRuntimeConfig(globalRuntimeConfig));

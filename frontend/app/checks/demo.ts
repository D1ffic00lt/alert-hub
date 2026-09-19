import type { ChecksRequest, ChecksRequestResult } from "./hooks";

type DemoLanguage = "ru" | "en";
type DemoStatus = "up" | "degraded" | "down" | "stale" | "unknown";

type DemoInstance = {
  instance_id: string;
  source: string;
  status: DemoStatus;
  status_reason: string;
  last_checked_at: string | null;
  stale: boolean;
  data_incomplete: boolean;
};

type DemoResult = {
  source: string;
  instance_id: string;
  scenario: string | null;
  variant: string;
  target: string | null;
  status: DemoStatus;
  status_reason: string;
  state: string;
  success: boolean | null;
  last_run_at: string | null;
  duration_seconds: number | null;
  ttfb_seconds: number | null;
  stale: boolean;
  data_incomplete: boolean;
  diagnostic_codes: string[];
  canaries: Array<Record<string, unknown>>;
  targets: Array<Record<string, unknown>>;
  assertions: Array<Record<string, unknown>>;
  error_reasons: Array<{ reason: string; count: number }>;
};

type DemoCheckItem = {
  check_id: string;
  name: string;
  group: string | null;
  target: string | null;
  status: DemoStatus;
  status_reason: string;
  last_checked_at: string | null;
  oldest_checked_at: string | null;
  sources_total: number;
  sources_up: number;
  instances_total: number;
  instances_up: number;
  instances_stale: number;
  instances: DemoInstance[];
  stale_results: number;
  data_incomplete: boolean;
  latency_seconds: number | null;
  scenarios: string[];
  sources: string[];
  active_alerts: number | null;
  diagnostic_codes: string[];
};

type DemoCheckDetail = DemoCheckItem & {
  results: DemoResult[];
  parts: Array<Record<string, unknown>>;
  related_alerts: Array<Record<string, unknown>>;
  incidents: Array<Record<string, unknown>>;
  alerts_available: boolean;
  related_alerts_total: number;
  incidents_total: number;
  relations_incomplete: boolean;
  relation_warning_codes: string[];
  grafana_url: null;
};

const SNAPSHOT_META = {
  enabled: true,
  data_state: "ready",
  snapshot_id: "demo-checks-2026-09-01T12:45:20Z",
  fetched_at: "2026-09-01T12:45:20Z",
  evaluated_at: "2026-09-01T12:45:20Z",
  cache_expires_at: "2026-09-01T12:45:25Z",
  error_code: null,
  warning_codes: [],
} as const;

const INCIDENTS = {
  checkout: "inc-01J7ZQ4K8W8AWMRV77B9",
  vless: "inc-01J7ZNRQBGCQKD0NN06T",
  tls: "inc-01J7ZHW5D6W2C66RJ2EM",
} as const;

function localized(language: DemoLanguage, russian: string, english: string): string {
  return language === "ru" ? russian : english;
}

function instance(
  instanceId: string,
  source: string,
  status: DemoStatus,
  checkedAt: string | null,
): DemoInstance {
  return {
    instance_id: instanceId,
    source,
    status,
    status_reason:
      status === "down"
        ? "result_failed"
        : status === "stale"
          ? "expired_measurements"
          : status === "unknown"
            ? "incomplete_data"
            : status === "degraded"
              ? "mixed_results"
              : "result_up",
    last_checked_at: checkedAt,
    stale: status === "stale",
    data_incomplete: status === "unknown",
  };
}

function result(
  item: DemoCheckItem,
  source: string,
  instanceId: string,
  status: DemoStatus,
  durationSeconds: number | null,
): DemoResult {
  const success = status === "up" ? true : status === "down" ? false : null;
  return {
    source,
    instance_id: instanceId,
    scenario: item.scenarios[0] ?? null,
    variant: "default",
    target: item.target,
    status,
    status_reason:
      status === "down"
        ? "result_failed"
        : status === "stale"
          ? "expired_measurements"
          : status === "unknown"
            ? "executor_unknown"
            : status === "degraded"
              ? "mixed_results"
              : "result_up",
    state: status === "up" ? "success" : status === "down" ? "failure" : status,
    success,
    last_run_at: status === "stale" ? "2026-09-01T12:36:00Z" : item.last_checked_at,
    duration_seconds: durationSeconds,
    ttfb_seconds: durationSeconds === null ? null : Math.round(durationSeconds * 420) / 1000,
    stale: status === "stale",
    data_incomplete: status === "unknown",
    diagnostic_codes: [],
    canaries: [],
    targets: [],
    assertions: [],
    error_reasons: status === "down" ? [{ reason: "timeout", count: 2 }] : [],
  };
}

function relation(
  incidentId: string,
  title: string,
  severity: "critical" | "warning",
  status: "open" | "acknowledged",
  startsAt: string,
  lastEventAt: string,
): Pick<DemoCheckDetail, "related_alerts" | "incidents"> {
  return {
    related_alerts: [
      {
        id: `alert-${incidentId}`,
        name: title,
        severity,
        status,
        starts_at: startsAt,
        last_event_at: lastEventAt,
        resolved_at: null,
        incident_id: incidentId,
        href: `/incidents/${incidentId}`,
      },
    ],
    incidents: [
      {
        id: incidentId,
        title,
        status,
        href: `/incidents/${incidentId}`,
      },
    ],
  };
}

function buildDemoChecks(language: DemoLanguage): {
  items: DemoCheckItem[];
  details: Map<string, DemoCheckDetail>;
} {
  const fresh = "2026-09-01T12:45:20Z";
  const almostFresh = "2026-09-01T12:45:17Z";
  const stale = "2026-09-01T12:36:00Z";
  const items: DemoCheckItem[] = [
    {
      check_id: "public-api-availability",
      name: localized(language, "Доступность публичного API", "Public API availability"),
      group: localized(language, "Основные сервисы", "Core services"),
      target: "api-core",
      status: "up",
      status_reason: "all_results_up",
      last_checked_at: fresh,
      oldest_checked_at: almostFresh,
      sources_total: 3,
      sources_up: 3,
      instances_total: 3,
      instances_up: 3,
      instances_stale: 0,
      instances: [
        instance("ru-msk-01", "synthetic-ru", "up", fresh),
        instance("eu-nl-01", "synthetic-nl", "up", fresh),
        instance("eu-de-01", "synthetic-de", "up", almostFresh),
      ],
      stale_results: 0,
      data_incomplete: false,
      latency_seconds: 0.238,
      scenarios: ["availability"],
      sources: ["synthetic-de", "synthetic-nl", "synthetic-ru"],
      active_alerts: 0,
      diagnostic_codes: [],
    },
    {
      check_id: "checkout-flow",
      name: localized(language, "Покупка и оплата", "Checkout and payment"),
      group: localized(language, "Пути пользователя", "Customer journeys"),
      target: "checkout.example.net",
      status: "degraded",
      status_reason: "mixed_results",
      last_checked_at: fresh,
      oldest_checked_at: almostFresh,
      sources_total: 2,
      sources_up: 1,
      instances_total: 2,
      instances_up: 1,
      instances_stale: 0,
      instances: [
        instance("eu-nl-01", "browser-eu", "up", fresh),
        instance("ru-msk-01", "browser-ru", "down", almostFresh),
      ],
      stale_results: 0,
      data_incomplete: false,
      latency_seconds: 2.84,
      scenarios: ["purchase"],
      sources: ["browser-eu", "browser-ru"],
      active_alerts: 1,
      diagnostic_codes: [],
    },
    {
      check_id: "vless-nl-edge",
      name: localized(language, "Подключение VLESS NL", "VLESS NL connectivity"),
      group: localized(language, "Сетевые точки", "Network endpoints"),
      target: "nl-edge-02",
      status: "down",
      status_reason: "confirmed_failures",
      last_checked_at: fresh,
      oldest_checked_at: almostFresh,
      sources_total: 2,
      sources_up: 0,
      instances_total: 2,
      instances_up: 0,
      instances_stale: 0,
      instances: [
        instance("ru-msk-01", "probe-ru", "down", fresh),
        instance("eu-de-01", "probe-de", "down", almostFresh),
      ],
      stale_results: 0,
      data_incomplete: false,
      latency_seconds: null,
      scenarios: ["connectivity"],
      sources: ["probe-de", "probe-ru"],
      active_alerts: 1,
      diagnostic_codes: [],
    },
    {
      check_id: "billing-heartbeat",
      name: localized(language, "Сигнал биллинга", "Billing heartbeat"),
      group: localized(language, "Фоновые процессы", "Background jobs"),
      target: "billing-worker",
      status: "stale",
      status_reason: "expired_measurements",
      last_checked_at: stale,
      oldest_checked_at: stale,
      sources_total: 2,
      sources_up: 0,
      instances_total: 2,
      instances_up: 0,
      instances_stale: 2,
      instances: [
        instance("eu-nl-01", "worker-nl", "stale", stale),
        instance("eu-de-01", "worker-de", "stale", stale),
      ],
      stale_results: 2,
      data_incomplete: false,
      latency_seconds: null,
      scenarios: ["heartbeat"],
      sources: ["worker-de", "worker-nl"],
      active_alerts: 0,
      diagnostic_codes: [],
    },
    {
      check_id: "portal-tls",
      name: localized(language, "Срок действия TLS", "TLS certificate lifetime"),
      group: localized(language, "Внешние сервисы", "External services"),
      target: "portal.example.net",
      status: "up",
      status_reason: "all_results_up",
      last_checked_at: fresh,
      oldest_checked_at: almostFresh,
      sources_total: 3,
      sources_up: 3,
      instances_total: 3,
      instances_up: 3,
      instances_stale: 0,
      instances: [
        instance("ru-msk-01", "tls-ru", "up", fresh),
        instance("eu-nl-01", "tls-nl", "up", fresh),
        instance("eu-de-01", "tls-de", "up", almostFresh),
      ],
      stale_results: 0,
      data_incomplete: false,
      latency_seconds: 0.19,
      scenarios: ["certificate"],
      sources: ["tls-de", "tls-nl", "tls-ru"],
      active_alerts: 1,
      diagnostic_codes: [],
    },
    {
      check_id: "dns-resolution",
      name: localized(language, "Разрешение DNS", "DNS resolution"),
      group: localized(language, "Сетевые точки", "Network endpoints"),
      target: "resolver.service.local",
      status: "unknown",
      status_reason: "insufficient_sources",
      last_checked_at: fresh,
      oldest_checked_at: fresh,
      sources_total: 2,
      sources_up: 0,
      instances_total: 2,
      instances_up: 0,
      instances_stale: 0,
      instances: [
        instance("eu-nl-01", "dns-nl", "down", fresh),
        instance("eu-de-01", "dns-de", "unknown", fresh),
      ],
      stale_results: 0,
      data_incomplete: true,
      latency_seconds: null,
      scenarios: ["dns"],
      sources: ["dns-de", "dns-nl"],
      active_alerts: 0,
      diagnostic_codes: [],
    },
  ];

  const details = new Map<string, DemoCheckDetail>();
  for (const item of items) {
    const results = item.instances.map((coverage, index) =>
      result(
        item,
        coverage.source,
        coverage.instance_id,
        coverage.status,
        coverage.status === "up"
          ? Math.max(0.04, (item.latency_seconds ?? 0.2) - index * 0.03)
          : null,
      ),
    );
    let related = { related_alerts: [], incidents: [] } as Pick<
      DemoCheckDetail,
      "related_alerts" | "incidents"
    >;
    if (item.check_id === "checkout-flow") {
      related = relation(
        INCIDENTS.checkout,
        localized(language, "Высокая задержка основного API", "Core API latency breach"),
        "critical",
        "open",
        "2026-09-01T12:39:02Z",
        "2026-09-01T12:44:11Z",
      );
    } else if (item.check_id === "vless-nl-edge") {
      related = relation(
        INCIDENTS.vless,
        localized(language, "Точка VLESS недоступна", "VLESS endpoint unreachable"),
        "critical",
        "acknowledged",
        "2026-09-01T12:31:25Z",
        "2026-09-01T12:42:52Z",
      );
    } else if (item.check_id === "portal-tls") {
      related = relation(
        INCIDENTS.tls,
        localized(
          language,
          "Сертификат TLS истекает через 12 дней",
          "TLS certificate expires in 12 days",
        ),
        "warning",
        "open",
        "2026-09-01T11:58:00Z",
        "2026-09-01T12:38:00Z",
      );
    }
    details.set(item.check_id, {
      ...item,
      results,
      parts: [
        {
          scenario: item.scenarios[0] ?? null,
          variant: "default",
          status: item.status,
          status_reason: item.status === "up" ? "all_sources_up" : item.status_reason,
          sources_total: item.sources_total,
          sources_up: item.sources_up,
          stale_results: item.stale_results,
          data_incomplete: item.data_incomplete,
        },
      ],
      ...related,
      alerts_available: true,
      related_alerts_total: related.related_alerts.length,
      incidents_total: related.incidents.length,
      relations_incomplete: false,
      relation_warning_codes: [],
      grafana_url: null,
    });
  }
  return { items, details };
}

function includes(value: string | null, query: string): boolean {
  return Boolean(value?.toLocaleLowerCase().includes(query));
}

function filterChecks(items: DemoCheckItem[], searchParams: URLSearchParams): DemoCheckItem[] {
  const status = searchParams.get("status")?.trim().toLowerCase();
  const group = searchParams.get("group")?.trim() ?? "";
  const source = searchParams.get("source")?.trim() ?? "";
  const target = searchParams.get("target")?.trim() ?? "";
  const scenario = searchParams.get("scenario")?.trim() ?? "";
  const search = searchParams.get("search")?.trim().toLocaleLowerCase() ?? "";
  return items.filter((item) => {
    if (status && item.status !== status) return false;
    if (group && item.group !== group) return false;
    if (source && !item.sources.includes(source)) return false;
    if (target && item.target !== target) return false;
    if (scenario && !item.scenarios.includes(scenario)) return false;
    if (
      search &&
      ![item.name, item.check_id, item.target].some((value) => includes(value, search))
    ) {
      return false;
    }
    return true;
  });
}

function summaryPayload(items: DemoCheckItem[]): Record<string, unknown> {
  const count = (status: DemoStatus) => items.filter((item) => item.status === status).length;
  const priority: Record<DemoStatus, number> = {
    down: 0,
    degraded: 1,
    unknown: 2,
    stale: 3,
    up: 4,
  };
  return {
    ...SNAPSHOT_META,
    total: items.length,
    up: count("up"),
    degraded: count("degraded"),
    down: count("down"),
    stale: count("stale"),
    unknown: count("unknown"),
    problem_checks: [...items]
      .filter((item) => item.status !== "up")
      .sort(
        (left, right) =>
          priority[left.status] - priority[right.status] ||
          left.check_id.localeCompare(right.check_id),
      )
      .slice(0, 5),
    last_known: null,
  };
}

export function createDemoChecksRequest(language: DemoLanguage): ChecksRequest {
  const fixture = buildDemoChecks(language);
  return async (path: string, signal: AbortSignal): Promise<ChecksRequestResult> => {
    if (signal.aborted) throw new DOMException("The request was aborted", "AbortError");
    const url = new URL(path, "https://demo.alert-hub.invalid");
    if (url.pathname === "/checks/summary") {
      return {
        status: 200,
        payload: summaryPayload(filterChecks(fixture.items, url.searchParams)),
      };
    }
    if (url.pathname === "/checks" || url.pathname === "/checks/") {
      const filtered = filterChecks(fixture.items, url.searchParams);
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")) || 50));
      const offset = Math.max(0, Number(url.searchParams.get("offset")) || 0);
      return {
        status: 200,
        payload: {
          ...SNAPSHOT_META,
          items: filtered.slice(offset, offset + limit),
          total: filtered.length,
          limit,
          offset,
          last_known: null,
        },
      };
    }
    const match = /^\/checks\/([^/]+)$/u.exec(url.pathname);
    if (!match) return { status: 404, payload: {} };
    const checkId = decodeURIComponent(match[1] ?? "");
    return {
      status: fixture.details.has(checkId) ? 200 : 404,
      payload: {
        ...SNAPSHOT_META,
        check: fixture.details.get(checkId) ?? null,
        last_known: null,
      },
    };
  };
}

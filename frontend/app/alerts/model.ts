export type AlertRulesDataState = "ok" | "partial" | "unavailable" | "not_configured";
export type AlertRuleState = "firing" | "pending" | "inactive";
export type AlertRuleFilter = AlertRuleState | "error" | "all";
export type AvailabilityWindow = "24h" | "7d" | "30d";
export type AvailabilityDataState = "ok" | "stale" | "unknown";

export type DatasourceError = {
  datasourceId: string;
  datasourceName: string;
  code: string;
  detail: string;
};

export type AlertRule = {
  id: string;
  datasourceId: string;
  datasourceName: string;
  group: string;
  file: string;
  name: string;
  state: AlertRuleState;
  health: string;
  firingInstances: number;
  pendingInstances: number;
  lastEvaluation: string | null;
  evaluationTimeSeconds: number | null;
  lastError: string | null;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  relatedIncidents: number;
  incidentsHref: string | null;
};

export type AlertRulesSnapshot = {
  dataState: AlertRulesDataState;
  generatedAt: string | null;
  totals: {
    rules: number;
    firingInstances: number;
    pendingInstances: number;
    unhealthyRules: number;
    relatedIncidents: number;
  };
  rules: AlertRule[];
  errors: DatasourceError[];
  pagination: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
  };
};

export type AvailabilityTarget = {
  datasourceId: string;
  datasourceName: string;
  source: string;
  target: string;
  window: AvailabilityWindow;
  observedAvailabilityPercent: number | null;
  samplesCount: number | null;
  lastSampleAt: string | null;
  dataState: AvailabilityDataState;
};

export type AvailabilitySnapshot = {
  dataState: AlertRulesDataState;
  generatedAt: string | null;
  window: AvailabilityWindow;
  targets: AvailabilityTarget[];
  errors: DatasourceError[];
};

export type AvailabilityRow = {
  key: string;
  datasourceId: string;
  datasourceName: string;
  source: string;
  target: string;
  windows: Partial<Record<AvailabilityWindow, AvailabilityTarget>>;
};

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function number(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function nullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function stringRecord(value: unknown): Record<string, string> {
  return Object.fromEntries(
    Object.entries(record(value)).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

function dataState(value: unknown): AlertRulesDataState {
  return ["ok", "partial", "unavailable", "not_configured"].includes(String(value))
    ? (value as AlertRulesDataState)
    : "unavailable";
}

function datasourceError(value: unknown): DatasourceError {
  const item = record(value);
  return {
    datasourceId: String(item.datasource_id ?? ""),
    datasourceName: String(item.datasource_name ?? "Prometheus"),
    code: String(item.code ?? "prometheus_error"),
    detail: String(item.detail ?? "Prometheus datasource could not be queried"),
  };
}

export function buildAlertRulesPath(filters: {
  datasourceId: string;
  state: AlertRuleFilter;
  query: string;
  page: number;
  pageSize: number;
}): string {
  const params = new URLSearchParams({
    page: String(filters.page),
    page_size: String(filters.pageSize),
  });
  if (filters.datasourceId) params.set("datasource_id", filters.datasourceId);
  if (filters.state !== "all") params.set("state", filters.state);
  if (filters.query.trim()) params.set("q", filters.query.trim());
  return `/alert-rules?${params.toString()}`;
}

export function normalizeAlertRules(payload: unknown): AlertRulesSnapshot {
  const body = record(payload);
  const totals = record(body.totals);
  const pagination = record(body.pagination);
  return {
    dataState: dataState(body.data_state),
    generatedAt: nullableString(body.generated_at),
    totals: {
      rules: number(totals.rules),
      firingInstances: number(totals.firing_instances),
      pendingInstances: number(totals.pending_instances),
      unhealthyRules: number(totals.unhealthy_rules),
      relatedIncidents: number(totals.related_incidents),
    },
    rules: list(body.rules).map((value) => {
      const item = record(value);
      const rawState = String(item.state);
      const state: AlertRuleState = ["firing", "pending", "inactive"].includes(rawState)
        ? (rawState as AlertRuleState)
        : "inactive";
      return {
        id: String(item.id ?? ""),
        datasourceId: String(item.datasource_id ?? ""),
        datasourceName: String(item.datasource_name ?? "Prometheus"),
        group: String(item.group ?? ""),
        file: String(item.file ?? ""),
        name: String(item.name ?? "Unnamed rule"),
        state,
        health: String(item.health ?? "unknown"),
        firingInstances: number(item.firing_instances),
        pendingInstances: number(item.pending_instances),
        lastEvaluation: nullableString(item.last_evaluation),
        evaluationTimeSeconds: nullableNumber(item.evaluation_time_seconds),
        lastError: nullableString(item.last_error),
        labels: stringRecord(item.labels),
        annotations: stringRecord(item.annotations),
        relatedIncidents: number(item.related_incidents),
        incidentsHref: nullableString(item.incidents_href),
      };
    }),
    errors: list(body.errors).map(datasourceError),
    pagination: {
      page: Math.max(1, Math.trunc(number(pagination.page, 1))),
      pageSize: Math.max(1, Math.trunc(number(pagination.page_size, 25))),
      totalItems: Math.max(0, Math.trunc(number(pagination.total_items))),
      totalPages: Math.max(0, Math.trunc(number(pagination.total_pages))),
    },
  };
}

export function normalizeAvailability(
  payload: unknown,
  requestedWindow: AvailabilityWindow,
): AvailabilitySnapshot {
  const body = record(payload);
  return {
    dataState: dataState(body.data_state),
    generatedAt: nullableString(body.generated_at),
    window: requestedWindow,
    targets: list(body.targets).map((value) => {
      const item = record(value);
      const rawState = String(item.data_state);
      const targetState: AvailabilityDataState = ["ok", "stale", "unknown"].includes(rawState)
        ? (rawState as AvailabilityDataState)
        : "unknown";
      return {
        datasourceId: String(item.datasource_id ?? ""),
        datasourceName: String(item.datasource_name ?? "Prometheus"),
        source: String(item.source ?? item.region ?? "Unknown"),
        target: String(item.target ?? "Unknown"),
        window: requestedWindow,
        observedAvailabilityPercent: nullableNumber(item.observed_availability_percent),
        samplesCount: nullableNumber(item.samples_count),
        lastSampleAt: nullableString(item.last_sample_at),
        dataState: targetState,
      };
    }),
    errors: list(body.errors).map(datasourceError),
  };
}

export function mergeAvailability(snapshots: AvailabilitySnapshot[]): AvailabilityRow[] {
  const rows = new Map<string, AvailabilityRow>();
  for (const snapshot of snapshots) {
    for (const target of snapshot.targets) {
      const key = `${target.datasourceId}\u0000${target.source}\u0000${target.target}`;
      const existing = rows.get(key) ?? {
        key,
        datasourceId: target.datasourceId,
        datasourceName: target.datasourceName,
        source: target.source,
        target: target.target,
        windows: {},
      };
      existing.windows[target.window] = target;
      rows.set(key, existing);
    }
  }
  return [...rows.values()].sort(
    (left, right) =>
      left.target.localeCompare(right.target) ||
      left.source.localeCompare(right.source) ||
      left.datasourceName.localeCompare(right.datasourceName) ||
      left.datasourceId.localeCompare(right.datasourceId),
  );
}

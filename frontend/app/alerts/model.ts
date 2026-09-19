export type AlertRulesDataState = "ok" | "partial" | "empty" | "unavailable" | "not_configured";
export type AlertRuleState = "firing" | "pending" | "error" | "inactive";
export type AlertRuleFilter = AlertRuleState | "error" | "all";
export type AvailabilityWindow = "24h" | "7d" | "30d";
export type AvailabilityDataState = "ok" | "stale" | "unknown";
export type AlertHistoryWindow = "24h" | "7d" | "30d";
export type AlertHistoryState = "inactive" | "pending" | "firing" | "unknown";

export type DatasourceError = {
  datasourceId: string;
  datasourceName: string;
  code: string;
  detail: string;
};

export const UNCATEGORIZED_FILTER = "__alert_hub_uncategorized__";

export type AlertRuleReplica = {
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

export type AlertRule = {
  id: string;
  name: string;
  category: string | null;
  state: AlertRuleState;
  firingInstances: number;
  pendingInstances: number;
  hasError: boolean;
  datasourceCount: number;
  relatedIncidents: number;
  replicas: AlertRuleReplica[];
};

export type AlertRulesSnapshot = {
  dataState: AlertRulesDataState;
  generatedAt: string | null;
  lastSuccessfulRefresh: string | null;
  totals: {
    rules: number;
    firingRules: number;
    pendingRules: number;
    errorRules: number;
    datasources: number;
    relatedIncidents: number;
  };
  filteredRules: number;
  categories: string[];
  hasUncategorized: boolean;
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

export type AlertHistoryBucket = {
  startsAt: string;
  endsAt: string;
};

export type AlertHistorySeries = {
  datasourceId: string;
  datasourceName: string;
  name: string;
  category: string | null;
  states: AlertHistoryState[];
  muted: Array<boolean | null>;
  muteSource: "alert_hub" | null;
};

export type AlertHistorySnapshot = {
  dataState: AlertRulesDataState;
  generatedAt: string | null;
  window: AlertHistoryWindow;
  bucketSeconds: number;
  buckets: AlertHistoryBucket[];
  datasources: Array<{ id: string; name: string }>;
  series: AlertHistorySeries[];
  errors: DatasourceError[];
};

export type AlertRuleHistory = {
  states: AlertHistoryState[];
  muted: Array<boolean | null>;
  quietPercent: number | null;
  coveragePercent: number;
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

function validDateString(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null;
  return Number.isNaN(new Date(value).getTime()) ? null : value;
}

function stringRecord(value: unknown): Record<string, string> {
  return Object.fromEntries(
    Object.entries(record(value)).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

function dataState(value: unknown): AlertRulesDataState {
  return ["ok", "partial", "empty", "unavailable", "not_configured"].includes(String(value))
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
  category: string;
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
  if (filters.category === UNCATEGORIZED_FILTER) params.set("uncategorized", "true");
  else if (filters.category) params.set("category", filters.category);
  if (filters.state !== "all") params.set("state", filters.state);
  if (filters.query.trim()) params.set("q", filters.query.trim());
  return `/alert-rules?${params.toString()}`;
}

export function buildAlertHistoryPath(window: AlertHistoryWindow): string {
  if (!["24h", "7d", "30d"].includes(window)) throw new Error("Unsupported alert history window");
  return `/alert-history?window=${window}`;
}

export function normalizeAlertRules(payload: unknown): AlertRulesSnapshot {
  const body = record(payload);
  const totals = record(body.totals);
  const pagination = record(body.pagination);
  return {
    dataState: dataState(body.data_state),
    generatedAt: nullableString(body.generated_at),
    lastSuccessfulRefresh: nullableString(body.last_successful_refresh),
    totals: {
      rules: number(totals.rules),
      firingRules: number(totals.firing_rules),
      pendingRules: number(totals.pending_rules),
      errorRules: number(totals.error_rules),
      datasources: number(totals.datasources),
      relatedIncidents: number(totals.related_incidents),
    },
    filteredRules: number(body.filtered_rules),
    categories: list(body.categories)
      .filter((value): value is string => typeof value === "string" && Boolean(value))
      .sort((left, right) => left.localeCompare(right)),
    hasUncategorized: body.has_uncategorized === true,
    rules: list(body.rules).map((value) => {
      const item = record(value);
      const rawState = String(item.state);
      const state: AlertRuleState = ["firing", "pending", "error", "inactive"].includes(rawState)
        ? (rawState as AlertRuleState)
        : "inactive";
      return {
        id: String(item.id ?? ""),
        name: String(item.name ?? "Unnamed rule"),
        category: nullableString(item.category),
        state,
        firingInstances: number(item.firing_instances),
        pendingInstances: number(item.pending_instances),
        hasError: item.has_error === true,
        datasourceCount: number(item.datasource_count),
        relatedIncidents: number(item.related_incidents),
        replicas: list(item.replicas).map((value) => {
          const replica = record(value);
          const rawReplicaState = String(replica.state);
          const replicaState: Exclude<AlertRuleState, "error"> = [
            "firing",
            "pending",
            "inactive",
          ].includes(rawReplicaState)
            ? (rawReplicaState as Exclude<AlertRuleState, "error">)
            : "inactive";
          return {
            id: String(replica.id ?? ""),
            datasourceId: String(replica.datasource_id ?? ""),
            datasourceName: String(replica.datasource_name ?? "Prometheus"),
            group: String(replica.group ?? ""),
            file: String(replica.file ?? ""),
            name: String(replica.name ?? item.name ?? "Unnamed rule"),
            state: replicaState,
            health: String(replica.health ?? "unknown"),
            firingInstances: number(replica.firing_instances),
            pendingInstances: number(replica.pending_instances),
            lastEvaluation: nullableString(replica.last_evaluation),
            evaluationTimeSeconds: nullableNumber(replica.evaluation_time_seconds),
            lastError: nullableString(replica.last_error),
            labels: stringRecord(replica.labels),
            annotations: stringRecord(replica.annotations),
            relatedIncidents: number(replica.related_incidents),
            incidentsHref: nullableString(replica.incidents_href),
          };
        }),
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

export function normalizeAlertHistory(
  payload: unknown,
  requestedWindow: AlertHistoryWindow,
): AlertHistorySnapshot {
  const body = record(payload);
  const rawBuckets = list(body.buckets)
    .flatMap((value) => {
      const item = record(value);
      const startsAt = validDateString(item.starts_at);
      const endsAt = validDateString(item.ends_at);
      if (!startsAt || !endsAt || new Date(startsAt).getTime() >= new Date(endsAt).getTime())
        return [];
      return [{ startsAt, endsAt }];
    })
    .slice(0, 60);
  const bucketCount = rawBuckets.length;
  const rawWindow = String(body.window);
  const window: AlertHistoryWindow = ["24h", "7d", "30d"].includes(rawWindow)
    ? (rawWindow as AlertHistoryWindow)
    : requestedWindow;
  const datasources = list(body.datasources).flatMap((value) => {
    const item = record(value);
    const id = String(item.id ?? "").trim();
    if (!id) return [];
    return [{ id, name: String(item.name ?? "Prometheus") }];
  });
  const validState = (value: unknown): AlertHistoryState =>
    ["inactive", "pending", "firing", "unknown"].includes(String(value))
      ? (value as AlertHistoryState)
      : "unknown";
  return {
    dataState: dataState(body.data_state),
    generatedAt: validDateString(body.generated_at),
    window,
    bucketSeconds: Math.max(0, Math.trunc(number(body.bucket_seconds))),
    buckets: rawBuckets,
    datasources,
    series: list(body.series).flatMap((value) => {
      const item = record(value);
      const datasourceId = String(item.datasource_id ?? "").trim();
      const name = String(item.name ?? "").trim();
      if (!datasourceId || !name) return [];
      const states = list(item.states).slice(0, bucketCount).map(validState);
      while (states.length < bucketCount) states.push("unknown");
      const muted = list(item.muted)
        .slice(0, bucketCount)
        .map((entry) => (typeof entry === "boolean" ? entry : null));
      while (muted.length < bucketCount) muted.push(null);
      return [
        {
          datasourceId,
          datasourceName: String(item.datasource_name ?? "Prometheus"),
          name,
          category: nullableString(item.category),
          states,
          muted,
          muteSource: item.mute_source === "alert_hub" ? "alert_hub" : null,
        } satisfies AlertHistorySeries,
      ];
    }),
    errors: list(body.errors).map(datasourceError),
  };
}

export function historyForRule(
  snapshot: AlertHistorySnapshot | null,
  rule: AlertRule,
): AlertRuleHistory | null {
  if (!snapshot || snapshot.buckets.length === 0) return null;
  const successfulDatasources = new Set(snapshot.datasources.map((item) => item.id));
  const replicaHistories = rule.replicas.map((replica) => {
    const series = snapshot.series.find(
      (item) =>
        item.datasourceId === replica.datasourceId &&
        item.name === rule.name &&
        item.category === rule.category,
    );
    if (series)
      return { datasourceId: replica.datasourceId, states: series.states, muted: series.muted };
    const fallback: AlertHistoryState = successfulDatasources.has(replica.datasourceId)
      ? "inactive"
      : "unknown";
    return {
      datasourceId: replica.datasourceId,
      states: snapshot.buckets.map(() => fallback),
      muted: snapshot.buckets.map(() => null),
    };
  });
  const representedDatasources = new Set(replicaHistories.map((item) => item.datasourceId));
  for (const series of snapshot.series) {
    if (
      series.name !== rule.name ||
      series.category !== rule.category ||
      representedDatasources.has(series.datasourceId)
    )
      continue;
    replicaHistories.push({
      datasourceId: series.datasourceId,
      states: series.states,
      muted: series.muted,
    });
    representedDatasources.add(series.datasourceId);
  }
  for (const failure of snapshot.errors) {
    if (representedDatasources.has(failure.datasourceId)) continue;
    replicaHistories.push({
      datasourceId: failure.datasourceId,
      states: snapshot.buckets.map(() => "unknown" as const),
      muted: snapshot.buckets.map(() => null),
    });
    representedDatasources.add(failure.datasourceId);
  }
  if (!replicaHistories.length) return null;

  const states: AlertHistoryState[] = [];
  const muted: Array<boolean | null> = [];
  for (let index = 0; index < snapshot.buckets.length; index += 1) {
    const replicaStates = replicaHistories.map((item) => item.states[index] ?? "unknown");
    const state: AlertHistoryState = replicaStates.includes("firing")
      ? "firing"
      : replicaStates.includes("pending")
        ? "pending"
        : replicaStates.includes("unknown")
          ? "unknown"
          : "inactive";
    states.push(state);
    const activeMuteValues = replicaHistories.flatMap((item, replicaIndex) =>
      ["firing", "pending"].includes(replicaStates[replicaIndex] ?? "unknown")
        ? [item.muted[index] ?? null]
        : [],
    );
    muted.push(
      activeMuteValues.length > 0 && activeMuteValues.every((value) => value === true)
        ? true
        : activeMuteValues.some((value) => value === false)
          ? false
          : null,
    );
  }
  const observed = states.filter((state) => state !== "unknown").length;
  const quiet = states.filter((state) => state === "inactive").length;
  return {
    states,
    muted,
    quietPercent: observed > 0 ? (quiet / observed) * 100 : null,
    coveragePercent: (observed / states.length) * 100,
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

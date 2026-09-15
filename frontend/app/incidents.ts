type IncidentSnapshot = {
  id: string;
  events: unknown[];
  summaryOnly?: boolean;
  description?: unknown;
  labels?: unknown;
  annotations?: unknown;
  checkIds?: string[];
  checksRelationState?: string;
};

export type IncidentTimelineSort = "newest_first" | "oldest_first";

type IncidentTimelineEvent = {
  id: string;
  at: string;
};

export function sortIncidentEventsByTime<T extends IncidentTimelineEvent>(
  events: readonly T[],
  order: IncidentTimelineSort,
): T[] {
  const direction = order === "newest_first" ? -1 : 1;
  return [...events].sort((left, right) => {
    const leftTimestamp = Date.parse(left.at);
    const rightTimestamp = Date.parse(right.at);
    const leftIsValid = Number.isFinite(leftTimestamp);
    const rightIsValid = Number.isFinite(rightTimestamp);

    if (leftIsValid && rightIsValid) {
      return (
        direction * (leftTimestamp - rightTimestamp) || direction * left.id.localeCompare(right.id)
      );
    }
    if (leftIsValid !== rightIsValid) return leftIsValid ? -1 : 1;
    return (
      direction * left.at.localeCompare(right.at) || direction * left.id.localeCompare(right.id)
    );
  });
}

export function mergeIncidentSummariesWithHistory<T extends IncidentSnapshot>(
  summaries: T[],
  current: T[],
): T[] {
  const currentById = new Map(current.map((incident) => [incident.id, incident]));
  return summaries.map((summary) => {
    const detailed = currentById.get(summary.id);
    let merged =
      summary.summaryOnly && detailed && !detailed.summaryOnly
        ? ({
            ...summary,
            summaryOnly: false,
            description: detailed.description,
            labels: detailed.labels,
            annotations: detailed.annotations,
            events: detailed.events,
          } as T)
        : summary;
    if (!summary.events.length && detailed?.events.length) {
      merged = { ...merged, events: detailed.events };
    }
    if (
      summary.checksRelationState === "available" &&
      detailed?.checksRelationState === "available"
    ) {
      merged = {
        ...merged,
        checkIds: [...new Set([...(summary.checkIds ?? []), ...(detailed.checkIds ?? [])])],
      };
    }
    return merged;
  });
}

export type IncidentListFilters = {
  status: "active" | "all" | "open" | "acknowledged" | "resolved" | "silenced";
  severity: "all" | "critical" | "warning" | "info" | "unknown";
  query: string;
  alertname?: string;
  datasourceId?: string;
  limit: number;
  offset: number;
};

export function normalizeIncidentSearch(value: string): string {
  return value.trim();
}

export function incidentListPath(filters: IncidentListFilters): string {
  const params = new URLSearchParams({
    limit: String(filters.limit),
    offset: String(filters.offset),
    view: "compact",
  });
  if (filters.status !== "all") params.set("status", filters.status);
  if (filters.severity !== "all") params.set("severity", filters.severity);
  const query = normalizeIncidentSearch(filters.query);
  if (query) params.set("q", query);
  if (filters.alertname) params.set("alertname", filters.alertname);
  if (filters.datasourceId) params.set("datasource_id", filters.datasourceId);
  return `/incidents?${params.toString()}`;
}

export type RefreshBurstCoalescer = {
  request: () => void;
  cancel: () => void;
};

export function sseReconnectDelay(attempt: number, random: () => number = Math.random): number {
  const boundedAttempt = Math.max(0, Math.min(5, Math.floor(attempt)));
  const base = Math.min(30_000, 1_000 * 2 ** boundedAttempt);
  const jitter = 0.8 + Math.max(0, Math.min(1, random())) * 0.4;
  return Math.min(30_000, Math.round(base * jitter));
}

export function createRefreshBurstCoalescer(
  run: () => Promise<unknown>,
  delayMs = 250,
): RefreshBurstCoalescer {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let running = false;
  let pending = false;
  let cancelled = false;

  const arm = () => {
    if (timer !== null || running || cancelled) return;
    timer = setTimeout(() => {
      timer = null;
      void flush().catch(() => undefined);
    }, delayMs);
  };

  const flush = async () => {
    if (cancelled || running) return;
    running = true;
    pending = false;
    try {
      await run();
    } finally {
      running = false;
      if (pending) arm();
    }
  };

  return {
    request() {
      if (cancelled) return;
      pending = true;
      arm();
    },
    cancel() {
      cancelled = true;
      pending = false;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
  };
}

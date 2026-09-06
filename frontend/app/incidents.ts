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
  return `/incidents?${params.toString()}`;
}

export type RefreshBurstCoalescer = {
  request: () => void;
  cancel: () => void;
};

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

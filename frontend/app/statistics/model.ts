export const STATISTICS_WINDOWS = ["24h", "7d", "30d"] as const;

export type StatisticsWindow = (typeof STATISTICS_WINDOWS)[number];

export type StatisticsTotals = {
  incidentsStarted: number;
  incidentsResolved: number;
  activeIncidents: number;
  activeCritical: number;
  acknowledgementRate: number | null;
  resolutionRate: number | null;
  meanTimeToAcknowledgeSeconds: number | null;
  meanTimeToResolveSeconds: number | null;
  deliveries: number;
  deliveriesSucceeded: number;
  deliveriesFailed: number;
  deliverySuccessRate: number | null;
};

export type StatisticsTimelinePoint = {
  startsAt: string;
  incidentsStarted: number;
  incidentsResolved: number;
  deliveriesSucceeded: number;
  deliveriesFailed: number;
};

export type StatisticsSeverity = {
  severity: string;
  count: number;
};

export type StatisticsSource = {
  sourceId: string;
  name: string;
  region: string | null;
  count: number;
};

export type StatisticsChannel = {
  channelId: string;
  name: string;
  kind: string;
  total: number;
  succeeded: number;
  failed: number;
  successRate: number | null;
};

export type StatisticsSnapshot = {
  window: StatisticsWindow;
  generatedAt: string | null;
  startsAt: string | null;
  endsAt: string | null;
  bucketSeconds: number | null;
  totals: StatisticsTotals;
  timeline: StatisticsTimelinePoint[];
  severities: StatisticsSeverity[];
  sources: StatisticsSource[];
  channels: StatisticsChannel[];
};

const ZERO_TOTALS: StatisticsTotals = {
  incidentsStarted: 0,
  incidentsResolved: 0,
  activeIncidents: 0,
  activeCritical: 0,
  acknowledgementRate: null,
  resolutionRate: null,
  meanTimeToAcknowledgeSeconds: null,
  meanTimeToResolveSeconds: null,
  deliveries: 0,
  deliveriesSucceeded: 0,
  deliveriesFailed: 0,
  deliverySuccessRate: null,
};

const DEFAULT_BUCKET_SECONDS: Record<StatisticsWindow, number> = {
  "24h": 60 * 60,
  "7d": 6 * 60 * 60,
  "30d": 24 * 60 * 60,
};

const MAX_TIMELINE_POINTS = 30;
const MAX_SEVERITY_ROWS = 4;
const MAX_RANKING_ROWS = 5;

export function emptyStatisticsSnapshot(window: StatisticsWindow = "7d"): StatisticsSnapshot {
  return {
    window,
    generatedAt: null,
    startsAt: null,
    endsAt: null,
    bucketSeconds: DEFAULT_BUCKET_SECONDS[window],
    totals: { ...ZERO_TOTALS },
    timeline: [],
    severities: [],
    sources: [],
    channels: [],
  };
}

/**
 * Use this only for a confirmed empty response. A request that has not completed or failed should
 * remain `null`, so the UI cannot accidentally present unavailable statistics as zero activity.
 */
export const EMPTY_STATISTICS: StatisticsSnapshot = emptyStatisticsSnapshot();

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function nonNegativeInteger(value: unknown): number | null {
  const parsed = finiteNumber(value);
  if (parsed === null || parsed < 0 || !Number.isInteger(parsed)) return null;
  return parsed;
}

function nonNegativeNumber(value: unknown): number | null {
  const parsed = finiteNumber(value);
  return parsed !== null && parsed >= 0 ? parsed : null;
}

function percentage(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const parsed = finiteNumber(value);
  return parsed !== null && parsed >= 0 && parsed <= 100 ? parsed : null;
}

function requiredPercentage(value: unknown): { valid: boolean; value: number | null } {
  if (value === null) return { valid: true, value: null };
  const parsed = percentage(value);
  return { valid: parsed !== null, value: parsed };
}

function requiredDuration(value: unknown): { valid: boolean; value: number | null } {
  if (value === null) return { valid: true, value: null };
  const parsed = nonNegativeNumber(value);
  return { valid: parsed !== null, value: parsed };
}

function text(value: unknown, maximumLength = 200): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/\s+/g, " ").trim();
  if (!normalized) return null;
  return normalized.slice(0, maximumLength);
}

function timestamp(value: unknown): string | null {
  const candidate = text(value, 80);
  if (!candidate) return null;
  const milliseconds = Date.parse(candidate);
  if (!Number.isFinite(milliseconds)) return null;
  return new Date(milliseconds).toISOString();
}

function statisticsWindow(value: unknown): StatisticsWindow | null {
  return STATISTICS_WINDOWS.includes(value as StatisticsWindow)
    ? (value as StatisticsWindow)
    : null;
}

function normalizeTotals(value: unknown): StatisticsTotals | null {
  const item = record(value);
  if (!item) return null;
  const counts = {
    incidentsStarted: nonNegativeInteger(item.incidents_started),
    incidentsResolved: nonNegativeInteger(item.incidents_resolved),
    activeIncidents: nonNegativeInteger(item.active_incidents),
    activeCritical: nonNegativeInteger(item.active_critical),
    deliveries: nonNegativeInteger(item.deliveries),
    deliveriesSucceeded: nonNegativeInteger(item.deliveries_succeeded),
    deliveriesFailed: nonNegativeInteger(item.deliveries_failed),
  };
  if (Object.values(counts).some((count) => count === null)) return null;
  if ((counts.activeCritical ?? 0) > (counts.activeIncidents ?? 0)) return null;
  if (
    (counts.deliveriesSucceeded ?? 0) > (counts.deliveries ?? 0) ||
    (counts.deliveriesFailed ?? 0) > (counts.deliveries ?? 0) ||
    (counts.deliveriesSucceeded ?? 0) + (counts.deliveriesFailed ?? 0) > (counts.deliveries ?? 0)
  ) {
    return null;
  }
  const acknowledgementRate = requiredPercentage(item.acknowledgement_rate);
  const resolutionRate = requiredPercentage(item.resolution_rate);
  const deliverySuccessRate = requiredPercentage(item.delivery_success_rate);
  const acknowledgeDuration = requiredDuration(item.mean_time_to_acknowledge_seconds);
  const resolveDuration = requiredDuration(item.mean_time_to_resolve_seconds);
  if (
    !acknowledgementRate.valid ||
    !resolutionRate.valid ||
    !deliverySuccessRate.valid ||
    !acknowledgeDuration.valid ||
    !resolveDuration.valid
  ) {
    return null;
  }
  return {
    incidentsStarted: counts.incidentsStarted as number,
    incidentsResolved: counts.incidentsResolved as number,
    activeIncidents: counts.activeIncidents as number,
    activeCritical: counts.activeCritical as number,
    acknowledgementRate: acknowledgementRate.value,
    resolutionRate: resolutionRate.value,
    meanTimeToAcknowledgeSeconds: acknowledgeDuration.value,
    meanTimeToResolveSeconds: resolveDuration.value,
    deliveries: counts.deliveries as number,
    deliveriesSucceeded: counts.deliveriesSucceeded as number,
    deliveriesFailed: counts.deliveriesFailed as number,
    deliverySuccessRate: deliverySuccessRate.value,
  };
}

function normalizeTimelinePoint(value: unknown): StatisticsTimelinePoint | null {
  const item = record(value);
  if (!item) return null;
  const startsAt = timestamp(item.starts_at);
  const incidentsStarted = nonNegativeInteger(item.incidents_started);
  const incidentsResolved = nonNegativeInteger(item.incidents_resolved);
  const deliveriesSucceeded = nonNegativeInteger(item.deliveries_succeeded);
  const deliveriesFailed = nonNegativeInteger(item.deliveries_failed);
  if (
    !startsAt ||
    incidentsStarted === null ||
    incidentsResolved === null ||
    deliveriesSucceeded === null ||
    deliveriesFailed === null
  ) {
    return null;
  }
  return {
    startsAt,
    incidentsStarted,
    incidentsResolved,
    deliveriesSucceeded,
    deliveriesFailed,
  };
}

function normalizeTimeline(value: unknown, startsAt: string, endsAt: string) {
  const start = Date.parse(startsAt);
  const end = Date.parse(endsAt);
  const unique = new Map<string, StatisticsTimelinePoint>();
  for (const candidate of array(value)) {
    const point = normalizeTimelinePoint(candidate);
    if (!point) continue;
    const pointTime = Date.parse(point.startsAt);
    if (pointTime < start || pointTime >= end) continue;
    unique.set(point.startsAt, point);
  }
  return [...unique.values()].sort(
    (left, right) => Date.parse(left.startsAt) - Date.parse(right.startsAt),
  );
}

function normalizeSeverities(value: unknown): StatisticsSeverity[] {
  const totals = new Map<string, number>();
  for (const candidate of array(value)) {
    const item = record(candidate);
    const severity = text(item?.severity, 40)?.toLowerCase() ?? null;
    const count = nonNegativeInteger(item?.count);
    if (!severity || count === null) continue;
    totals.set(severity, (totals.get(severity) ?? 0) + count);
  }
  const priority = new Map([
    ["critical", 0],
    ["warning", 1],
    ["info", 2],
    ["unknown", 3],
  ]);
  return [...totals.entries()]
    .map(([severity, count]) => ({ severity, count }))
    .sort(
      (left, right) =>
        (priority.get(left.severity) ?? 10) - (priority.get(right.severity) ?? 10) ||
        right.count - left.count ||
        left.severity.localeCompare(right.severity),
    );
}

function normalizeSources(value: unknown): StatisticsSource[] {
  const unique = new Map<string, StatisticsSource>();
  for (const candidate of array(value)) {
    const item = record(candidate);
    const sourceId = text(item?.source_id, 128);
    const name = text(item?.name, 200);
    const count = nonNegativeInteger(item?.count);
    if (!sourceId || !name || count === null) continue;
    unique.set(sourceId, {
      sourceId,
      name,
      region: text(item?.region, 80),
      count,
    });
  }
  return [...unique.values()].sort(
    (left, right) => right.count - left.count || left.name.localeCompare(right.name),
  );
}

function normalizeChannels(value: unknown): StatisticsChannel[] {
  const unique = new Map<string, StatisticsChannel>();
  for (const candidate of array(value)) {
    const item = record(candidate);
    const channelId = text(item?.channel_id, 128);
    const name = text(item?.name, 200);
    const kind = text(item?.kind, 80);
    const total = nonNegativeInteger(item?.total);
    const succeeded = nonNegativeInteger(item?.succeeded);
    const failed = nonNegativeInteger(item?.failed);
    const successRateResult = requiredPercentage(item?.success_rate);
    if (
      !channelId ||
      !name ||
      !kind ||
      total === null ||
      succeeded === null ||
      failed === null ||
      !successRateResult.valid ||
      succeeded > total ||
      failed > total ||
      succeeded + failed > total
    ) {
      continue;
    }
    unique.set(channelId, {
      channelId,
      name,
      kind,
      total,
      succeeded,
      failed,
      successRate: successRateResult.value,
    });
  }
  return [...unique.values()].sort(
    (left, right) => right.total - left.total || left.name.localeCompare(right.name),
  );
}

export function normalizeStatisticsSnapshot(payload: unknown): StatisticsSnapshot | null {
  const envelope = record(payload);
  if (!envelope) return null;
  const body = record(envelope.statistics) ?? envelope;
  const window = statisticsWindow(body.window);
  const generatedAt = timestamp(body.generated_at);
  const startsAt = timestamp(body.starts_at);
  const endsAt = timestamp(body.ends_at);
  const bucketSeconds = nonNegativeInteger(body.bucket_seconds);
  const totals = normalizeTotals(body.totals);
  if (
    !window ||
    !generatedAt ||
    !startsAt ||
    !endsAt ||
    bucketSeconds === null ||
    bucketSeconds === 0 ||
    !totals
  ) {
    return null;
  }
  const rangeSeconds = (Date.parse(endsAt) - Date.parse(startsAt)) / 1000;
  if (rangeSeconds <= 0 || bucketSeconds > rangeSeconds) return null;
  if (
    array(body.timeline).length > MAX_TIMELINE_POINTS ||
    array(body.severities).length > MAX_SEVERITY_ROWS ||
    array(body.sources).length > MAX_RANKING_ROWS ||
    array(body.channels).length > MAX_RANKING_ROWS
  ) {
    return null;
  }
  return {
    window,
    generatedAt,
    startsAt,
    endsAt,
    bucketSeconds,
    totals,
    timeline: normalizeTimeline(body.timeline, startsAt, endsAt),
    severities: normalizeSeverities(body.severities),
    sources: normalizeSources(body.sources),
    channels: normalizeChannels(body.channels),
  };
}

export function isStatisticsSnapshotEmpty(snapshot: StatisticsSnapshot): boolean {
  const { totals } = snapshot;
  return (
    totals.incidentsStarted === 0 &&
    totals.incidentsResolved === 0 &&
    totals.activeIncidents === 0 &&
    totals.activeCritical === 0 &&
    totals.deliveries === 0 &&
    snapshot.timeline.every(
      (point) =>
        point.incidentsStarted === 0 &&
        point.incidentsResolved === 0 &&
        point.deliveriesSucceeded === 0 &&
        point.deliveriesFailed === 0,
    ) &&
    snapshot.severities.every((item) => item.count === 0) &&
    snapshot.sources.every((item) => item.count === 0) &&
    snapshot.channels.every((item) => item.total === 0)
  );
}

export function createDemoStatisticsSnapshot(): StatisticsSnapshot {
  const startsAt = "2026-08-30T00:00:00.000Z";
  const incidentStarts = [
    1, 1, 0, 2, 2, 1, 1, 2, 0, 1, 1, 1, 2, 3, 1, 2, 1, 1, 1, 2, 2, 1, 2, 2, 1, 0, 1, 2,
  ];
  const incidentResolutions = [
    0, 1, 1, 1, 1, 1, 0, 2, 1, 1, 1, 2, 2, 1, 1, 2, 1, 1, 1, 1, 2, 2, 1, 3, 1, 1, 1, 2,
  ];
  const deliverySuccesses = [
    8, 10, 9, 11, 11, 12, 10, 11, 9, 10, 10, 10, 12, 13, 13, 13, 11, 12, 12, 12, 13, 14, 14, 14, 10,
    11, 10, 11,
  ];
  const deliveryFailures = [
    0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1,
  ];
  return {
    window: "7d",
    generatedAt: "2026-09-06T00:00:00.000Z",
    startsAt,
    endsAt: "2026-09-06T00:00:00.000Z",
    bucketSeconds: DEFAULT_BUCKET_SECONDS["7d"],
    totals: {
      incidentsStarted: 37,
      incidentsResolved: 35,
      activeIncidents: 5,
      activeCritical: 1,
      acknowledgementRate: 91.9,
      resolutionRate: 94.6,
      meanTimeToAcknowledgeSeconds: 420,
      meanTimeToResolveSeconds: 3_780,
      deliveries: 326,
      deliveriesSucceeded: 316,
      deliveriesFailed: 10,
      deliverySuccessRate: 96.9,
    },
    timeline: incidentStarts.map((incidentsStarted, index) => ({
      startsAt: new Date(
        Date.parse(startsAt) + index * DEFAULT_BUCKET_SECONDS["7d"] * 1_000,
      ).toISOString(),
      incidentsStarted,
      incidentsResolved: incidentResolutions[index] ?? 0,
      deliveriesSucceeded: deliverySuccesses[index] ?? 0,
      deliveriesFailed: deliveryFailures[index] ?? 0,
    })),
    severities: [
      { severity: "critical", count: 6 },
      { severity: "warning", count: 18 },
      { severity: "info", count: 11 },
      { severity: "unknown", count: 2 },
    ],
    sources: [
      { sourceId: "edge-alertmanager", name: "Edge Alertmanager", region: "EU", count: 13 },
      { sourceId: "synthetic-checks", name: "Synthetic checks", region: "Global", count: 10 },
      { sourceId: "checkout-alerts", name: "Checkout alerts", region: "EU", count: 8 },
      { sourceId: "database-alerts", name: "Database alerts", region: "EU", count: 6 },
    ],
    channels: [
      {
        channelId: "web-push",
        name: "Web Push",
        kind: "web_push",
        total: 140,
        succeeded: 136,
        failed: 4,
        successRate: 97.1,
      },
      {
        channelId: "telegram-ops",
        name: "Telegram Operations",
        kind: "telegram",
        total: 102,
        succeeded: 100,
        failed: 2,
        successRate: 98,
      },
      {
        channelId: "smtp-on-call",
        name: "On-call email",
        kind: "smtp",
        total: 84,
        succeeded: 80,
        failed: 4,
        successRate: 95.2,
      },
    ],
  };
}

export const DEMO_STATISTICS_SNAPSHOT: StatisticsSnapshot = createDemoStatisticsSnapshot();

export const CHECK_STATUSES = ["up", "degraded", "down", "stale", "unknown"] as const;

export type CheckStatus = (typeof CHECK_STATUSES)[number];
export type ChecksDataState = "ready" | "empty" | "stale" | "unavailable" | "disabled";

export type ChecksMeta = {
  enabled: boolean;
  dataState: ChecksDataState;
  snapshotId: string | null;
  fetchedAt: string | null;
  evaluatedAt: string | null;
  cacheExpiresAt: string | null;
  code: string | null;
  warningCodes: string[];
};

export type CheckSummary = Record<CheckStatus, number> & {
  total: number;
};

export type CheckListItem = {
  checkId: string;
  name: string;
  group: string | null;
  target: string | null;
  status: CheckStatus;
  statusReason: string | null;
  lastCheckedAt: string | null;
  oldestCheckedAt: string | null;
  sourcesTotal: number;
  sourcesUp: number;
  staleResults: number;
  dataIncomplete: boolean;
  latencySeconds: number | null;
  scenarios: string[];
  sources: string[];
  activeAlerts: number | null;
  diagnosticCodes: string[];
};

export type CheckCanary = {
  id: string | null;
  success: boolean | null;
  statusReason: string | null;
};

export type CheckAssertion = {
  key: string;
  success: boolean | null;
  statusReason: string | null;
};

export type CheckResult = {
  source: string | null;
  scenario: string | null;
  variant: string | null;
  target: string | null;
  status: CheckStatus;
  statusReason: string | null;
  success: boolean | null;
  durationSeconds: number | null;
  ttfbSeconds: number | null;
  checkedAt: string | null;
  stale: boolean;
  dataIncomplete: boolean;
  canaries: CheckCanary[];
  assertions: CheckAssertion[];
  diagnosticCodes: string[];
};

export type CheckAlertLink = {
  id: string | null;
  name: string;
  severity: string | null;
  status: string | null;
  startsAt: string | null;
  lastEventAt: string | null;
  resolvedAt: string | null;
  incidentId: string | null;
  href: string | null;
};

export type CheckIncidentLink = {
  id: string;
  title: string;
  status: string | null;
  href: string | null;
};

export type CheckPart = {
  scenario: string | null;
  variant: string | null;
  status: CheckStatus;
  statusReason: string | null;
  sourcesTotal: number;
  sourcesUp: number;
  staleResults: number;
  dataIncomplete: boolean;
};

export type CheckDetail = CheckListItem & {
  results: CheckResult[];
  parts: CheckPart[];
  alerts: CheckAlertLink[];
  incidents: CheckIncidentLink[];
  alertLinksAvailable: boolean;
  relatedAlertsTotal: number | null;
  incidentsTotal: number | null;
  relationsIncomplete: boolean;
  relationWarningCodes: string[];
  grafanaUrl: string | null;
};

export type ChecksList = {
  meta: ChecksMeta;
  items: CheckListItem[];
  total: number;
  limit: number;
  offset: number;
};

export type ChecksSummaryResponse = {
  meta: ChecksMeta;
  summary: CheckSummary | null;
  problemChecks: CheckListItem[];
};

export type CheckDetailResponse = {
  meta: ChecksMeta;
  check: CheckDetail | null;
};

export type CheckFilters = {
  status: "all" | CheckStatus;
  group: string;
  source: string;
  target: string;
  scenario: string;
  search: string;
  limit: number;
  offset: number;
};

const DATA_STATES = new Set<ChecksDataState>([
  "ready",
  "empty",
  "stale",
  "unavailable",
  "disabled",
]);
const STATUS_SET = new Set<CheckStatus>(CHECK_STATUSES);
const PROBLEM_PRIORITY: Record<CheckStatus, number> = {
  down: 0,
  degraded: 1,
  unknown: 2,
  stale: 3,
  up: 4,
};

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringOrNull(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return normalized || null;
}

function stringList(value: unknown): string[] {
  return [
    ...new Set(
      array(value)
        .map(stringOrNull)
        .filter((item): item is string => item !== null),
    ),
  ].sort((left, right) => left.localeCompare(right));
}

function finiteNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const normalized = Number(value);
  return Number.isFinite(normalized) ? normalized : null;
}

function count(value: unknown, fallback = 0): number {
  const normalized = finiteNumber(value);
  return normalized === null ? fallback : Math.max(0, Math.trunc(normalized));
}

function nullableCount(value: unknown): number | null {
  const normalized = finiteNumber(value);
  return normalized === null ? null : Math.max(0, Math.trunc(normalized));
}

function optionalDuration(value: unknown): number | null {
  const normalized = finiteNumber(value);
  return normalized !== null && normalized >= 0 ? normalized : null;
}

function booleanOrNull(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (value === 0 || value === "0") return false;
  if (value === 1 || value === "1") return true;
  return null;
}

function status(value: unknown): CheckStatus {
  const normalized = String(value ?? "unknown").toLowerCase();
  return STATUS_SET.has(normalized as CheckStatus) ? (normalized as CheckStatus) : "unknown";
}

function dataState(value: unknown, enabled: boolean, itemCount = 0): ChecksDataState {
  if (!enabled) return "disabled";
  const normalized = String(value ?? "").toLowerCase();
  if (DATA_STATES.has(normalized as ChecksDataState)) return normalized as ChecksDataState;
  return itemCount > 0 ? "ready" : "empty";
}

function errorCode(body: Record<string, unknown>): string | null {
  const error = record(body.error);
  const detail = record(body.detail);
  return stringOrNull(
    body.error_code ?? body.code ?? error.code ?? detail.code ?? body.warning_code,
  );
}

export function normalizeChecksMeta(payload: unknown, itemCount = 0): ChecksMeta {
  const body = record(payload);
  const enabled = body.enabled === undefined ? true : Boolean(body.enabled);
  return {
    enabled,
    dataState: dataState(body.data_state, enabled, itemCount),
    snapshotId: stringOrNull(body.snapshot_id),
    fetchedAt: stringOrNull(body.fetched_at),
    evaluatedAt: stringOrNull(body.evaluated_at),
    cacheExpiresAt: stringOrNull(body.cache_expires_at),
    code: errorCode(body),
    warningCodes: stringList(body.warning_codes),
  };
}

export function normalizeCheckListItem(value: unknown): CheckListItem | null {
  const body = record(value);
  const checkId = stringOrNull(body.check_id ?? body.id);
  if (!checkId) return null;
  const sourceValues = body.sources ?? body.source_names;
  return {
    checkId,
    name: stringOrNull(body.name ?? body.check_name) ?? checkId,
    group: stringOrNull(body.group),
    target: stringOrNull(body.target),
    status: status(body.status),
    statusReason: stringOrNull(body.status_reason),
    lastCheckedAt: stringOrNull(body.last_checked_at),
    oldestCheckedAt: stringOrNull(body.oldest_checked_at),
    sourcesTotal: count(body.sources_total),
    sourcesUp: count(body.sources_up),
    staleResults: count(body.stale_results),
    dataIncomplete: Boolean(body.data_incomplete),
    latencySeconds: optionalDuration(body.latency_seconds),
    scenarios: stringList(body.scenarios),
    sources: stringList(sourceValues),
    activeAlerts:
      body.active_alerts === null
        ? null
        : Array.isArray(body.active_alerts)
          ? body.active_alerts.length
          : finiteNumber(body.active_alerts) === null
            ? null
            : count(body.active_alerts),
    diagnosticCodes: stringList(body.diagnostic_codes),
  };
}

function candidateItems(body: Record<string, unknown>): unknown[] {
  if (Array.isArray(body.checks)) return body.checks;
  if (Array.isArray(body.items)) return body.items;
  if (Array.isArray(body.data)) return body.data;
  return [];
}

export function normalizeChecksList(payload: unknown): ChecksList {
  const body = record(payload);
  const items = candidateItems(body)
    .map(normalizeCheckListItem)
    .filter((item): item is CheckListItem => item !== null);
  return {
    meta: normalizeChecksMeta(body, items.length),
    items,
    total: count(body.total, items.length),
    limit: count(body.limit, 50) || 50,
    offset: count(body.offset),
  };
}

const EMPTY_SUMMARY: CheckSummary = {
  total: 0,
  up: 0,
  degraded: 0,
  down: 0,
  stale: 0,
  unknown: 0,
};

export function emptyCheckSummary(): CheckSummary {
  return { ...EMPTY_SUMMARY };
}

export function normalizeChecksSummary(payload: unknown): ChecksSummaryResponse {
  const body = record(payload);
  const summaryBody = Object.keys(record(body.summary)).length ? record(body.summary) : body;
  const meta = normalizeChecksMeta(body, count(summaryBody.total));
  if (meta.dataState === "unavailable" || meta.dataState === "disabled") {
    return {
      meta,
      summary: meta.dataState === "disabled" ? emptyCheckSummary() : null,
      problemChecks: [],
    };
  }
  const summary = {
    total: count(summaryBody.total),
    up: count(summaryBody.up),
    degraded: count(summaryBody.degraded),
    down: count(summaryBody.down),
    stale: count(summaryBody.stale),
    unknown: count(summaryBody.unknown),
  };
  return {
    meta,
    summary,
    problemChecks: array(body.problem_checks)
      .map(normalizeCheckListItem)
      .filter((item): item is CheckListItem => item !== null),
  };
}

function normalizeCanary(value: unknown): CheckCanary {
  const body = record(value);
  return {
    id: stringOrNull(body.canary ?? body.id ?? body.name),
    success: booleanOrNull(body.success ?? body.result ?? body.passed),
    statusReason: stringOrNull(body.status_reason),
  };
}

function normalizeAssertion(value: unknown): CheckAssertion | null {
  const body = record(value);
  const key = stringOrNull(body.key ?? body.assertion ?? body.name);
  if (!key) return null;
  return {
    key,
    success: booleanOrNull(body.success ?? body.result ?? body.passed),
    statusReason: stringOrNull(body.status_reason),
  };
}

export function normalizeCheckResult(value: unknown): CheckResult {
  const body = record(value);
  const success = booleanOrNull(body.success ?? body.result);
  const normalizedStatus =
    body.status === undefined && success !== null ? (success ? "up" : "down") : status(body.status);
  return {
    source: stringOrNull(body.source),
    scenario: stringOrNull(body.scenario),
    variant: stringOrNull(body.variant),
    target: stringOrNull(body.target),
    status: normalizedStatus,
    statusReason: stringOrNull(body.status_reason),
    success,
    durationSeconds: optionalDuration(body.duration_seconds ?? body.duration),
    ttfbSeconds: optionalDuration(body.ttfb_seconds ?? body.ttfb),
    checkedAt: stringOrNull(
      body.checked_at ?? body.last_checked_at ?? body.last_run_at ?? body.timestamp,
    ),
    stale: Boolean(body.stale) || normalizedStatus === "stale",
    dataIncomplete: Boolean(body.data_incomplete),
    canaries: array(body.canaries ?? body.canary).map(normalizeCanary),
    assertions: array(body.assertions)
      .map(normalizeAssertion)
      .filter((item): item is CheckAssertion => item !== null),
    diagnosticCodes: stringList(body.diagnostic_codes),
  };
}

function normalizeAlert(value: unknown): CheckAlertLink | null {
  const body = record(value);
  const name = stringOrNull(body.name ?? body.alertname ?? body.title);
  if (!name) return null;
  return {
    id: stringOrNull(body.id ?? body.alert_id ?? body.fingerprint),
    name,
    severity: stringOrNull(body.severity),
    status: stringOrNull(body.status),
    startsAt: stringOrNull(body.starts_at ?? body.started_at),
    lastEventAt: stringOrNull(body.last_event_at),
    resolvedAt: stringOrNull(body.resolved_at),
    incidentId: stringOrNull(body.incident_id),
    href: safeInternalHref(body.href),
  };
}

function normalizeIncident(value: unknown): CheckIncidentLink | null {
  const body = record(value);
  const id = stringOrNull(body.id ?? body.incident_id);
  if (!id) return null;
  return {
    id,
    title: stringOrNull(body.title ?? body.name) ?? id,
    status: stringOrNull(body.status),
    href: safeInternalHref(body.href),
  };
}

export function safeInternalHref(value: unknown): string | null {
  const raw = stringOrNull(value);
  if (!raw) return null;
  const hasBrowserOrigin = typeof window !== "undefined";
  if (!hasBrowserOrigin && (!raw.startsWith("/") || raw.startsWith("//"))) return null;
  try {
    const origin = hasBrowserOrigin ? window.location.origin : "https://alert-hub.invalid";
    const url = new URL(raw, origin);
    if (url.origin !== origin || !url.pathname.startsWith("/incidents/")) return null;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return null;
  }
}

export function safeExternalUrl(value: unknown): string | null {
  const raw = stringOrNull(value);
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

export function normalizeCheckDetail(payload: unknown): CheckDetailResponse {
  const envelope = record(payload);
  const source = Object.keys(record(envelope.check)).length ? record(envelope.check) : envelope;
  const listItem = normalizeCheckListItem(source);
  const meta = normalizeChecksMeta(envelope, listItem ? 1 : 0);
  if (!listItem || meta.dataState === "disabled" || meta.dataState === "unavailable") {
    return { meta, check: null };
  }
  const activeAlertValue = source.active_alerts;
  const alertItems = Array.isArray(activeAlertValue)
    ? activeAlertValue
    : array(
        source.related_alerts ?? source.alerts ?? source.active_alert_items ?? source.linked_alerts,
      );
  const check: CheckDetail = {
    ...listItem,
    results: array(source.results ?? source.measurements).map(normalizeCheckResult),
    parts: array(source.parts).map((value) => {
      const body = record(value);
      return {
        scenario: stringOrNull(body.scenario),
        variant: stringOrNull(body.variant),
        status: status(body.status),
        statusReason: stringOrNull(body.status_reason),
        sourcesTotal: count(body.sources_total),
        sourcesUp: count(body.sources_up),
        staleResults: count(body.stale_results),
        dataIncomplete: Boolean(body.data_incomplete),
      };
    }),
    alerts: alertItems.map(normalizeAlert).filter((item): item is CheckAlertLink => item !== null),
    incidents: array(source.incidents ?? source.linked_incidents)
      .map(normalizeIncident)
      .filter((item): item is CheckIncidentLink => item !== null),
    alertLinksAvailable:
      source.alerts_available === undefined
        ? source.active_alerts !== null && source.related_alerts !== null
        : Boolean(source.alerts_available),
    relatedAlertsTotal: nullableCount(source.related_alerts_total),
    incidentsTotal: nullableCount(source.incidents_total),
    relationsIncomplete: Boolean(source.relations_incomplete),
    relationWarningCodes: stringList(source.relation_warning_codes),
    grafanaUrl: safeExternalUrl(source.grafana_url),
  };
  if (Array.isArray(activeAlertValue)) check.activeAlerts = activeAlertValue.length;
  return { meta, check };
}

export function problemChecks(items: CheckListItem[], limit = 5): CheckListItem[] {
  return [...items]
    .filter((item) => item.status !== "up")
    .sort(
      (left, right) =>
        PROBLEM_PRIORITY[left.status] - PROBLEM_PRIORITY[right.status] ||
        left.checkId.localeCompare(right.checkId),
    )
    .slice(0, Math.max(0, limit));
}

export function groupChecks(items: CheckListItem[]): Array<{
  key: string;
  label: string | null;
  items: CheckListItem[];
}> {
  const groups = new Map<string, { label: string | null; items: CheckListItem[] }>();
  for (const item of items) {
    const key = item.group ?? "";
    const group = groups.get(key) ?? { label: item.group, items: [] };
    group.items.push(item);
    groups.set(key, group);
  }
  return [...groups.entries()]
    .sort(([left], [right]) => {
      if (!left) return 1;
      if (!right) return -1;
      return left.localeCompare(right);
    })
    .map(([key, group]) => ({ key, ...group }));
}

export function buildChecksQuery(filters: CheckFilters, includePagination = true): string {
  const query = new URLSearchParams();
  if (filters.status !== "all") query.set("status", filters.status);
  for (const key of ["group", "source", "target", "scenario", "search"] as const) {
    const value = filters[key].trim();
    if (value) query.set(key, value);
  }
  if (includePagination) {
    query.set("limit", String(filters.limit));
    query.set("offset", String(filters.offset));
  }
  const serialized = query.toString();
  return serialized ? `?${serialized}` : "";
}

export function hasActiveCheckFilters(filters: CheckFilters): boolean {
  return (
    filters.status !== "all" ||
    [filters.group, filters.source, filters.target, filters.scenario, filters.search].some(
      (value) => value.trim().length > 0,
    )
  );
}

export function resultMatrix(check: CheckDetail): {
  sources: Array<string | null>;
  scenarios: Array<string | null>;
  cells: Map<string, CheckResult[]>;
} {
  const sources = [...new Set(check.results.map((item) => item.source))].sort((left, right) =>
    (left ?? "").localeCompare(right ?? ""),
  );
  const scenarios = [...new Set(check.results.map((item) => item.scenario))].sort((left, right) =>
    (left ?? "").localeCompare(right ?? ""),
  );
  const cells = new Map<string, CheckResult[]>();
  check.results.forEach((item) => {
    const key = `${item.source ?? ""}\u0000${item.scenario ?? ""}`;
    cells.set(key, [...(cells.get(key) ?? []), item]);
  });
  return { sources, scenarios, cells };
}

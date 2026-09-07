import { useEffect, useMemo, useState } from "react";

import {
  type AlertRule,
  type AlertRuleFilter,
  type AlertRulesSnapshot,
  type AvailabilityRow,
  type AvailabilitySnapshot,
  type AvailabilityTarget,
  type AvailabilityWindow,
  buildAlertRulesPath,
  mergeAvailability,
  normalizeAlertRules,
  normalizeAvailability,
} from "./model";

type Language = "ru" | "en";
type RuntimeMode = "active" | "demo" | "unavailable";
type Request = (path: string, signal: AbortSignal) => Promise<{ payload: unknown }>;

const PAGE_SIZE = 25;
const WINDOWS: AvailabilityWindow[] = ["24h", "7d", "30d"];

function tx(language: Language, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

function demoRules(): AlertRulesSnapshot {
  return normalizeAlertRules({
    data_state: "ok",
    generated_at: "2026-09-07T00:00:00Z",
    totals: {
      rules: 3,
      firing_instances: 2,
      pending_instances: 1,
      unhealthy_rules: 1,
      related_incidents: 2,
    },
    rules: [
      {
        id: "demo-api-down",
        datasource_id: "prom-demo",
        datasource_name: "Demo Prometheus",
        group: "platform",
        file: "platform.yml",
        name: "ApiDown",
        state: "firing",
        health: "ok",
        firing_instances: 2,
        pending_instances: 0,
        last_evaluation: "2026-09-07T00:00:00Z",
        evaluation_time_seconds: 0.012,
        last_error: null,
        related_incidents: 2,
        incidents_href: "/incidents?q=ApiDown",
      },
      {
        id: "demo-latency",
        datasource_id: "prom-demo",
        datasource_name: "Demo Prometheus",
        group: "platform",
        file: "platform.yml",
        name: "LatencyHigh",
        state: "pending",
        health: "ok",
        firing_instances: 0,
        pending_instances: 1,
        last_evaluation: "2026-09-07T00:00:00Z",
        evaluation_time_seconds: 0.008,
        last_error: null,
        related_incidents: 0,
      },
      {
        id: "demo-broken",
        datasource_id: "prom-demo",
        datasource_name: "Demo Prometheus",
        group: "storage",
        file: "storage.yml",
        name: "DiskForecast",
        state: "inactive",
        health: "error",
        firing_instances: 0,
        pending_instances: 0,
        last_evaluation: "2026-09-07T00:00:00Z",
        evaluation_time_seconds: 0.004,
        last_error: "query evaluation failed",
        related_incidents: 0,
      },
    ],
    pagination: { page: 1, page_size: PAGE_SIZE, total_items: 3, total_pages: 1 },
    errors: [],
  });
}

function demoAvailability(): AvailabilitySnapshot[] {
  return WINDOWS.map((window, index) =>
    normalizeAvailability(
      {
        data_state: "ok",
        targets: [
          {
            datasource_id: "prom-demo",
            datasource_name: "Demo Prometheus",
            source: "ru",
            target: "api-core",
            observed_availability_percent: [99.96, 99.91, 99.88][index],
            samples_count: [1440, 10080, 43200][index],
            last_sample_at: "2026-09-07T00:00:00Z",
            data_state: "ok",
          },
        ],
      },
      window,
    ),
  );
}

function formatDate(language: Language, value: string | null) {
  if (!value) return tx(language, "Нет данных", "No data");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return tx(language, "Нет данных", "No data");
  return new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

function ruleStateLabel(language: Language, rule: AlertRule) {
  if (rule.health !== "ok") return tx(language, "Ошибка", "Error");
  if (rule.state === "firing") return "Firing";
  if (rule.state === "pending") return "Pending";
  return tx(language, "Неактивно", "Inactive");
}

function RuleBadge({ rule, language }: { rule: AlertRule; language: Language }) {
  const state = rule.health !== "ok" ? "error" : rule.state;
  return (
    <span className={`alert-state alert-state--${state}`}>{ruleStateLabel(language, rule)}</span>
  );
}

function AvailabilityValue({
  target,
  language,
}: {
  target?: AvailabilityTarget;
  language: Language;
}) {
  if (!target || target.dataState === "unknown" || target.observedAvailabilityPercent === null) {
    return <span className="availability-value availability-value--unknown">—</span>;
  }
  return (
    <span className={`availability-value availability-value--${target.dataState}`}>
      <b>{target.observedAvailabilityPercent.toFixed(3)}%</b>
      {target.dataState === "stale" && <small>{tx(language, "Устарело", "Stale")}</small>}
    </span>
  );
}

function StateNotice({
  state,
  language,
  onConfigure,
}: {
  state: AlertRulesSnapshot["dataState"];
  language: Language;
  onConfigure: () => void;
}) {
  if (state === "ok") return null;
  if (state === "not_configured") {
    return (
      <div className="alerts-notice" role="status">
        <span>
          <b>{tx(language, "Prometheus не настроен", "Prometheus is not configured")}</b>
          <small>
            {tx(
              language,
              "Добавьте активный datasource, чтобы загрузить правила и доступность.",
              "Add an enabled datasource to load rules and availability.",
            )}
          </small>
        </span>
        <button className="button button--quiet" type="button" onClick={onConfigure}>
          {tx(language, "Настроить Prometheus", "Configure Prometheus")}
        </button>
      </div>
    );
  }
  return (
    <div className={`alerts-notice alerts-notice--${state}`} role="status">
      <span>
        <b>
          {state === "partial"
            ? tx(language, "Данные получены частично", "Partial datasource result")
            : tx(language, "Данные Prometheus недоступны", "Prometheus data is unavailable")}
        </b>
        <small>
          {state === "partial"
            ? tx(
                language,
                "Доступные источники показаны; ошибки перечислены ниже.",
                "Available datasources are shown; failures are listed below.",
              )
            : tx(language, "Повторите запрос позже.", "Retry the request later.")}
        </small>
      </span>
    </div>
  );
}

export function AlertsPage({
  request,
  runtimeMode,
  language,
  datasources,
  grafanaUrl,
  navigate,
  externalRefreshVersion,
}: {
  request: Request;
  runtimeMode: RuntimeMode;
  language: Language;
  datasources: Array<{ id: string; name: string; enabled: boolean }>;
  grafanaUrl: string | null;
  navigate: (path: string) => void;
  externalRefreshVersion: number;
}) {
  const [datasourceId, setDatasourceId] = useState("");
  const [stateFilter, setStateFilter] = useState<AlertRuleFilter>("all");
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [page, setPage] = useState(1);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [rules, setRules] = useState<AlertRulesSnapshot | null>(() =>
    runtimeMode === "demo" ? demoRules() : null,
  );
  const [rulesLoading, setRulesLoading] = useState(runtimeMode === "active");
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [availability, setAvailability] = useState<AvailabilitySnapshot[]>(() =>
    runtimeMode === "demo" ? demoAvailability() : [],
  );
  const [availabilityLoading, setAvailabilityLoading] = useState(runtimeMode === "active");
  const [availabilityError, setAvailabilityError] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query.trim()), 250);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    if (runtimeMode !== "active") return undefined;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) setRulesLoading(true);
    });
    const path = buildAlertRulesPath({
      datasourceId,
      state: stateFilter,
      query: debouncedQuery,
      page,
      pageSize: PAGE_SIZE,
    });
    void request(path, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        const snapshot = normalizeAlertRules(result.payload);
        if (snapshot.pagination.totalPages > 0 && page > snapshot.pagination.totalPages) {
          setPage(snapshot.pagination.totalPages);
          return;
        }
        setRules(snapshot);
        setRulesError(null);
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        setRulesError(
          reason instanceof Error
            ? reason.message
            : tx(language, "Не удалось загрузить правила.", "Could not load alert rules."),
        );
      })
      .finally(() => {
        if (!controller.signal.aborted) setRulesLoading(false);
      });
    return () => controller.abort();
  }, [
    datasourceId,
    debouncedQuery,
    externalRefreshVersion,
    language,
    page,
    refreshVersion,
    request,
    runtimeMode,
    stateFilter,
  ]);

  useEffect(() => {
    if (runtimeMode !== "active") return undefined;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) setAvailabilityLoading(true);
    });
    void Promise.allSettled(
      WINDOWS.map(async (window) => {
        const result = await request(`/availability?window=${window}`, controller.signal);
        return normalizeAvailability(result.payload, window);
      }),
    ).then((results) => {
      if (controller.signal.aborted) return;
      const successful = results.flatMap((result) =>
        result.status === "fulfilled" ? [result.value] : [],
      );
      setAvailability(successful);
      setAvailabilityError(
        successful.length === WINDOWS.length
          ? null
          : tx(
              language,
              "Часть окон доступности не загрузилась.",
              "Some availability windows could not be loaded.",
            ),
      );
      setAvailabilityLoading(false);
    });
    return () => controller.abort();
  }, [externalRefreshVersion, language, refreshVersion, request, runtimeMode]);

  const rows = useMemo<AvailabilityRow[]>(() => mergeAvailability(availability), [availability]);
  const allErrors = useMemo(
    () =>
      [...(rules?.errors ?? []), ...availability.flatMap((snapshot) => snapshot.errors)].filter(
        (error, index, items) =>
          items.findIndex(
            (candidate) =>
              candidate.datasourceId === error.datasourceId && candidate.code === error.code,
          ) === index,
      ),
    [availability, rules],
  );
  const unavailable = runtimeMode === "unavailable";
  const showTotals = rules !== null && rules.dataState !== "unavailable" && !unavailable;
  const resetFilters = () => {
    setDatasourceId("");
    setStateFilter("all");
    setQuery("");
    setDebouncedQuery("");
    setPage(1);
  };
  const refresh = () => setRefreshVersion((value) => value + 1);

  return (
    <div className="page-stack alerts-page">
      <header className="alerts-heading">
        <span>
          <small>{tx(language, "Данные Prometheus", "Prometheus evidence")}</small>
          <h1>{tx(language, "Алерты", "Alerts")}</h1>
          <p>
            {tx(
              language,
              "Правила, активные срабатывания и фактическая доступность целей.",
              "Rules, active alert instances, and observed target availability.",
            )}
          </p>
        </span>
        <span className="alerts-heading__actions">
          {grafanaUrl ? (
            <a className="button button--quiet" href={grafanaUrl} target="_blank" rel="noreferrer">
              {tx(language, "Открыть Grafana", "Open Grafana")}
            </a>
          ) : null}
          <button
            className="button button--quiet"
            type="button"
            onClick={refresh}
            disabled={unavailable}
          >
            {tx(language, "Обновить", "Refresh")}
          </button>
        </span>
      </header>

      {runtimeMode === "demo" && (
        <div className="alerts-notice" role="status">
          <b>{tx(language, "Демонстрационные данные", "Demo data")}</b>
        </div>
      )}
      {unavailable && (
        <div className="alerts-notice alerts-notice--unavailable" role="status">
          <span>
            <b>{tx(language, "Нет подключения к API", "API connection unavailable")}</b>
            <small>
              {tx(
                language,
                "Актуальные правила и временные ряды не могут быть подтверждены.",
                "Current rules and time-series evidence cannot be verified.",
              )}
            </small>
          </span>
        </div>
      )}
      {rules && !unavailable && (
        <StateNotice
          state={rules.dataState}
          language={language}
          onConfigure={() => navigate("/reachability")}
        />
      )}

      <section className="alerts-kpis" aria-label={tx(language, "Сводка правил", "Rule summary")}>
        {[
          [
            tx(language, "Всего правил", "Total rules"),
            showTotals ? rules?.totals.rules : "—",
            "neutral",
          ],
          ["Firing", showTotals ? rules?.totals.firingInstances : "—", "danger"],
          ["Pending", showTotals ? rules?.totals.pendingInstances : "—", "warning"],
          [
            tx(language, "Ошибки правил", "Rule errors"),
            showTotals ? rules?.totals.unhealthyRules : "—",
            "danger",
          ],
        ].map(([label, value, tone]) => (
          <article className={`alerts-kpi alerts-kpi--${tone}`} key={label}>
            <small>{label}</small>
            <b>{rulesLoading && !rules ? "…" : value}</b>
          </article>
        ))}
      </section>

      <section className="alerts-panel" aria-labelledby="alert-rules-title">
        <header className="alerts-panel__head">
          <span>
            <small>{tx(language, "Alert rules", "Alert rules")}</small>
            <h2 id="alert-rules-title">{tx(language, "Правила Prometheus", "Prometheus rules")}</h2>
          </span>
          {rules?.generatedAt && <time>{formatDate(language, rules.generatedAt)}</time>}
        </header>
        <div className="alerts-filters" role="search">
          <label className="alerts-search">
            <span className="sr-only">{tx(language, "Поиск по имени", "Search by name")}</span>
            <input
              type="search"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              placeholder={tx(language, "Поиск по имени правила", "Search rule name")}
              disabled={unavailable}
            />
          </label>
          <label>
            <span className="sr-only">Datasource</span>
            <select
              value={datasourceId}
              onChange={(event) => {
                setDatasourceId(event.target.value);
                setPage(1);
              }}
              disabled={unavailable}
            >
              <option value="">{tx(language, "Все datasources", "All datasources")}</option>
              {datasources
                .filter((item) => item.enabled)
                .map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.name}
                  </option>
                ))}
            </select>
          </label>
          <label>
            <span className="sr-only">{tx(language, "Состояние", "State")}</span>
            <select
              value={stateFilter}
              onChange={(event) => {
                setStateFilter(event.target.value as AlertRuleFilter);
                setPage(1);
              }}
              disabled={unavailable}
            >
              <option value="all">{tx(language, "Все состояния", "All states")}</option>
              <option value="firing">Firing</option>
              <option value="pending">Pending</option>
              <option value="inactive">{tx(language, "Неактивные", "Inactive")}</option>
              <option value="error">{tx(language, "С ошибкой", "Error")}</option>
            </select>
          </label>
          <button
            className="button button--quiet"
            type="button"
            onClick={resetFilters}
            disabled={unavailable}
          >
            {tx(language, "Сбросить", "Reset")}
          </button>
        </div>

        {rulesLoading && !rules ? (
          <div className="alerts-loading" role="status">
            {tx(language, "Загружаем правила…", "Loading alert rules…")}
          </div>
        ) : rulesError ? (
          <div className="alerts-empty" role="alert">
            <b>{tx(language, "Правила недоступны", "Alert rules unavailable")}</b>
            <span>{rulesError}</span>
            <button className="button button--quiet" type="button" onClick={refresh}>
              {tx(language, "Повторить", "Retry")}
            </button>
          </div>
        ) : rules?.rules.length ? (
          <div className={`alerts-table-wrap ${rulesLoading ? "is-refreshing" : ""}`}>
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>{tx(language, "Правило", "Rule")}</th>
                  <th>Datasource</th>
                  <th>{tx(language, "Группа", "Group")}</th>
                  <th>{tx(language, "Состояние", "State")}</th>
                  <th>Firing</th>
                  <th>Pending</th>
                  <th>Health</th>
                  <th>{tx(language, "Последнее вычисление", "Last evaluation")}</th>
                  <th>{tx(language, "Ошибка", "Error")}</th>
                </tr>
              </thead>
              <tbody>
                {rules.rules.map((rule) => (
                  <tr key={rule.id}>
                    <td data-label={tx(language, "Правило", "Rule")}>
                      <span className="alert-rule-name">
                        <b>{rule.name}</b>
                        {rule.incidentsHref && (
                          <button
                            type="button"
                            onClick={() => navigate(rule.incidentsHref ?? "/incidents")}
                          >
                            {tx(
                              language,
                              `Инциденты: ${rule.relatedIncidents}`,
                              `Incidents: ${rule.relatedIncidents}`,
                            )}
                          </button>
                        )}
                      </span>
                    </td>
                    <td data-label="Datasource">{rule.datasourceName}</td>
                    <td data-label={tx(language, "Группа", "Group")}>
                      <span className="alert-rule-group">
                        <b>{rule.group || "—"}</b>
                        <small>{rule.file}</small>
                      </span>
                    </td>
                    <td data-label={tx(language, "Состояние", "State")}>
                      <RuleBadge rule={rule} language={language} />
                    </td>
                    <td data-label="Firing">{rule.firingInstances}</td>
                    <td data-label="Pending">{rule.pendingInstances}</td>
                    <td data-label="Health">
                      <code>{rule.health}</code>
                    </td>
                    <td data-label={tx(language, "Последнее вычисление", "Last evaluation")}>
                      <span className="alert-rule-evaluation">
                        <time>{formatDate(language, rule.lastEvaluation)}</time>
                        {rule.evaluationTimeSeconds !== null && (
                          <small>{(rule.evaluationTimeSeconds * 1000).toFixed(1)} ms</small>
                        )}
                      </span>
                    </td>
                    <td data-label={tx(language, "Ошибка", "Error")} className="alert-rule-error">
                      {rule.lastError ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="alerts-empty" role="status">
            <b>{tx(language, "Правила не найдены", "No alert rules found")}</b>
            <span>
              {rules?.dataState === "not_configured"
                ? tx(
                    language,
                    "Подключите Prometheus datasource.",
                    "Connect a Prometheus datasource.",
                  )
                : tx(
                    language,
                    "Измените фильтры или добавьте правила в Prometheus.",
                    "Change filters or add rules in Prometheus.",
                  )}
            </span>
          </div>
        )}
        {rules && rules.pagination.totalPages > 1 && (
          <nav
            className="alerts-pagination"
            aria-label={tx(language, "Страницы правил", "Rule pages")}
          >
            <button
              className="button button--quiet"
              type="button"
              disabled={page <= 1 || rulesLoading}
              onClick={() => setPage((value) => value - 1)}
            >
              {tx(language, "Назад", "Previous")}
            </button>
            <span>
              {tx(
                language,
                `Страница ${page} из ${rules.pagination.totalPages}`,
                `Page ${page} of ${rules.pagination.totalPages}`,
              )}
            </span>
            <button
              className="button button--quiet"
              type="button"
              disabled={page >= rules.pagination.totalPages || rulesLoading}
              onClick={() => setPage((value) => value + 1)}
            >
              {tx(language, "Далее", "Next")}
            </button>
          </nav>
        )}
      </section>

      <section className="alerts-panel" aria-labelledby="observed-availability-title">
        <header className="alerts-panel__head">
          <span>
            <small>probe_success</small>
            <h2 id="observed-availability-title">
              {tx(language, "Наблюдаемая доступность", "Observed availability")}
            </h2>
          </span>
        </header>
        {availabilityLoading && !availability.length ? (
          <div className="alerts-loading" role="status">
            {tx(language, "Рассчитываем доступность…", "Calculating availability…")}
          </div>
        ) : availabilityError && !rows.length ? (
          <div className="alerts-empty" role="alert">
            <b>{tx(language, "Доступность не рассчитана", "Availability unavailable")}</b>
            <span>{availabilityError}</span>
          </div>
        ) : rows.length ? (
          <div className={`alerts-table-wrap ${availabilityLoading ? "is-refreshing" : ""}`}>
            <table className="alerts-table alerts-availability-table">
              <thead>
                <tr>
                  <th>{tx(language, "Цель", "Target")}</th>
                  <th>{tx(language, "Источник / регион", "Source / region")}</th>
                  <th>24h</th>
                  <th>7d</th>
                  <th>30d</th>
                  <th>{tx(language, "Актуальность", "Freshness")}</th>
                  <th>{tx(language, "Последний sample", "Last sample")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const evidence = row.windows["24h"] ?? row.windows["7d"] ?? row.windows["30d"];
                  const states = Object.values(row.windows).map((item) => item?.dataState);
                  const freshness = states.includes("unknown")
                    ? "unknown"
                    : states.includes("stale")
                      ? "stale"
                      : "ok";
                  return (
                    <tr key={row.key}>
                      <td data-label={tx(language, "Цель", "Target")}>
                        <b>{row.target}</b>
                        <small className="alerts-cell-note">{row.datasourceName}</small>
                      </td>
                      <td data-label={tx(language, "Источник / регион", "Source / region")}>
                        {row.source}
                      </td>
                      {WINDOWS.map((window) => (
                        <td data-label={window} key={window}>
                          <AvailabilityValue target={row.windows[window]} language={language} />
                        </td>
                      ))}
                      <td data-label={tx(language, "Актуальность", "Freshness")}>
                        <span className={`alert-state alert-state--${freshness}`}>
                          {freshness === "ok"
                            ? tx(language, "Актуально", "Current")
                            : freshness === "stale"
                              ? tx(language, "Устарело", "Stale")
                              : tx(language, "Нет данных", "Unknown")}
                        </span>
                      </td>
                      <td data-label={tx(language, "Последний sample", "Last sample")}>
                        <time>{formatDate(language, evidence?.lastSampleAt ?? null)}</time>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="alerts-empty" role="status">
            <b>{tx(language, "Нет данных о доступности", "No availability data")}</b>
            <span>
              {tx(
                language,
                "Отсутствующие samples не считаются нулевой или полной доступностью.",
                "Missing samples are not treated as zero or full availability.",
              )}
            </span>
          </div>
        )}
        {availabilityError && rows.length > 0 && (
          <p className="alerts-inline-warning" role="status">
            {availabilityError}
          </p>
        )}
      </section>

      {allErrors.length > 0 && (
        <section className="alerts-panel" aria-labelledby="alerts-errors-title">
          <header className="alerts-panel__head">
            <span>
              <small>{tx(language, "Частичные результаты", "Partial results")}</small>
              <h2 id="alerts-errors-title">
                {tx(language, "Ошибки datasources", "Datasource errors")}
              </h2>
            </span>
          </header>
          <ul className="alerts-errors">
            {allErrors.map((error) => (
              <li key={`${error.datasourceId}-${error.code}`}>
                <b>{error.datasourceName}</b>
                <code>{error.code}</code>
                <span>{error.detail}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

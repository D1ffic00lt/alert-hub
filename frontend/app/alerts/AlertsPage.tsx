import { useEffect, useMemo, useState } from "react";

import {
  type AlertRule,
  type AlertRuleFilter,
  type AlertRuleReplica,
  type AlertRulesSnapshot,
  UNCATEGORIZED_FILTER,
  buildAlertRulesPath,
  normalizeAlertRules,
} from "./model";

type Language = "ru" | "en";
type RuntimeMode = "active" | "demo" | "unavailable";
type Request = (path: string, signal: AbortSignal) => Promise<{ payload: unknown }>;

const PAGE_SIZE = 25;

function tx(language: Language, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

function demoRules(): AlertRulesSnapshot {
  return normalizeAlertRules({
    data_state: "ok",
    generated_at: "2026-09-07T00:00:00Z",
    last_successful_refresh: "2026-09-07T00:00:00Z",
    totals: {
      rules: 4,
      firing_rules: 1,
      pending_rules: 1,
      error_rules: 1,
      datasources: 3,
      related_incidents: 2,
    },
    filtered_rules: 4,
    categories: ["infrastructure", "tls", "xray"],
    has_uncategorized: true,
    rules: [
      {
        id: "demo-api-down",
        name: "ApiDown",
        category: "infrastructure",
        state: "firing",
        firing_instances: 2,
        pending_instances: 0,
        has_error: false,
        datasource_count: 2,
        related_incidents: 2,
        replicas: [
          {
            id: "demo-api-down-ru",
            datasource_id: "prom-ru",
            datasource_name: "RU Prometheus",
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
            labels: { alert_category: "infrastructure", severity: "critical" },
            annotations: { summary: "API is unavailable" },
            related_incidents: 2,
            incidents_href: "/incidents?alertname=ApiDown&datasource_id=prom-ru",
          },
          {
            id: "demo-api-down-de",
            datasource_id: "prom-de",
            datasource_name: "DE Prometheus",
            group: "platform",
            file: "platform.yml",
            name: "ApiDown",
            state: "inactive",
            health: "ok",
            firing_instances: 0,
            pending_instances: 0,
            last_evaluation: "2026-09-07T00:00:00Z",
            evaluation_time_seconds: 0.009,
            last_error: null,
            labels: { alert_category: "infrastructure", severity: "critical" },
            annotations: { summary: "API is unavailable" },
            related_incidents: 0,
            incidents_href: null,
          },
        ],
      },
      {
        id: "demo-latency",
        name: "XrayLatencyHigh",
        category: "xray",
        state: "pending",
        firing_instances: 0,
        pending_instances: 1,
        has_error: false,
        datasource_count: 1,
        related_incidents: 0,
        replicas: [
          {
            id: "demo-latency-nl",
            datasource_id: "prom-nl",
            datasource_name: "NL Prometheus",
            group: "xray",
            file: "xray.yml",
            name: "XrayLatencyHigh",
            state: "pending",
            health: "ok",
            firing_instances: 0,
            pending_instances: 1,
            last_evaluation: "2026-09-07T00:00:00Z",
            evaluation_time_seconds: 0.008,
            last_error: null,
            labels: { alert_category: "xray", severity: "warning" },
            annotations: {},
            related_incidents: 0,
            incidents_href: "/incidents?alertname=XrayLatencyHigh&datasource_id=prom-nl",
          },
        ],
      },
      {
        id: "demo-broken",
        name: "DiskForecast",
        category: null,
        state: "error",
        firing_instances: 0,
        pending_instances: 0,
        has_error: true,
        datasource_count: 1,
        related_incidents: 0,
        replicas: [
          {
            id: "demo-broken-ru",
            datasource_id: "prom-ru",
            datasource_name: "RU Prometheus",
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
            labels: { severity: "warning" },
            annotations: {},
            related_incidents: 0,
            incidents_href: null,
          },
        ],
      },
      {
        id: "demo-tls",
        name: "TlsCertificateExpiringSoon",
        category: "tls",
        state: "inactive",
        firing_instances: 0,
        pending_instances: 0,
        has_error: false,
        datasource_count: 1,
        related_incidents: 0,
        replicas: [
          {
            id: "demo-tls-ru",
            datasource_id: "prom-ru",
            datasource_name: "RU Prometheus",
            group: "tls",
            file: "tls.yml",
            name: "TlsCertificateExpiringSoon",
            state: "inactive",
            health: "ok",
            firing_instances: 0,
            pending_instances: 0,
            last_evaluation: "2026-09-07T00:00:00Z",
            evaluation_time_seconds: 0.006,
            last_error: null,
            labels: { alert_category: "tls", severity: "warning" },
            annotations: {},
            related_incidents: 0,
            incidents_href: null,
          },
        ],
      },
    ],
    pagination: { page: 1, page_size: PAGE_SIZE, total_items: 4, total_pages: 1 },
    errors: [],
  });
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

function stateLabel(language: Language, state: AlertRule["state"]) {
  if (state === "firing") return "Firing";
  if (state === "pending") return "Pending";
  if (state === "error") return tx(language, "Ошибка", "Error");
  return tx(language, "Неактивно", "Inactive");
}

function RuleBadge({ state, language }: { state: AlertRule["state"]; language: Language }) {
  return <span className={`alert-state alert-state--${state}`}>{stateLabel(language, state)}</span>;
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
  if (state === "ok" || state === "empty") return null;
  if (state === "not_configured") {
    return (
      <div className="alerts-notice" role="status">
        <span>
          <b>{tx(language, "Prometheus не настроен", "Prometheus is not configured")}</b>
          <small>
            {tx(
              language,
              "Добавьте активный datasource, чтобы загрузить правила.",
              "Add an enabled datasource to load alert rules.",
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
                "Успешно полученные правила сохранены; ошибки источников перечислены ниже.",
                "Successfully fetched rules remain visible; datasource failures are listed below.",
              )
            : tx(language, "Повторите запрос позже.", "Retry the request later.")}
        </small>
      </span>
    </div>
  );
}

function Labels({ labels, language }: { labels: Record<string, string>; language: Language }) {
  const entries = Object.entries(labels).sort(([left], [right]) => left.localeCompare(right));
  return (
    <details className="alert-labels">
      <summary>
        {tx(language, "Labels", "Labels")} <span>{entries.length}</span>
      </summary>
      {entries.length ? (
        <dl>
          {entries.map(([key, value]) => (
            <div key={key}>
              <dt>{key}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p>{tx(language, "Labels отсутствуют", "No labels")}</p>
      )}
    </details>
  );
}

function ReplicaCard({
  replica,
  language,
  navigate,
}: {
  replica: AlertRuleReplica;
  language: Language;
  navigate: (path: string) => void;
}) {
  const displayState = replica.health !== "ok" || replica.lastError ? "error" : replica.state;
  return (
    <article className={`alert-replica alert-replica--${displayState}`}>
      <header>
        <span>
          <b>{replica.datasourceName}</b>
          <code>{replica.datasourceId}</code>
        </span>
        <RuleBadge state={displayState} language={language} />
      </header>
      <div className="alert-replica__counts">
        <span>
          <small>Firing</small>
          <b>{replica.firingInstances}</b>
        </span>
        <span>
          <small>Pending</small>
          <b>{replica.pendingInstances}</b>
        </span>
        <span>
          <small>Health</small>
          <code>{replica.health}</code>
        </span>
      </div>
      <dl className="alert-replica__meta">
        <div>
          <dt>{tx(language, "Группа", "Group")}</dt>
          <dd>{replica.group || "—"}</dd>
        </div>
        <div>
          <dt>{tx(language, "Файл", "File")}</dt>
          <dd title={replica.file}>{replica.file || "—"}</dd>
        </div>
        <div>
          <dt>{tx(language, "Последнее вычисление", "Last evaluation")}</dt>
          <dd>
            {formatDate(language, replica.lastEvaluation)}
            {replica.evaluationTimeSeconds !== null
              ? ` · ${(replica.evaluationTimeSeconds * 1000).toFixed(1)} ms`
              : ""}
          </dd>
        </div>
        <div>
          <dt>{tx(language, "Последняя ошибка", "Last error")}</dt>
          <dd className={replica.lastError ? "alert-rule-error" : ""}>
            {replica.lastError || "—"}
          </dd>
        </div>
      </dl>
      <footer>
        <Labels labels={replica.labels} language={language} />
        {replica.incidentsHref ? (
          <button
            className="button button--quiet alert-incidents-link"
            type="button"
            onClick={() => navigate(replica.incidentsHref ?? "/incidents")}
          >
            {tx(language, "Открыть инциденты", "Open incidents")}
            {replica.relatedIncidents > 0 ? ` · ${replica.relatedIncidents}` : ""}
          </button>
        ) : null}
      </footer>
    </article>
  );
}

function RuleDisclosure({
  rule,
  language,
  navigate,
}: {
  rule: AlertRule;
  language: Language;
  navigate: (path: string) => void;
}) {
  const problematic = rule.state !== "inactive" || rule.hasError;
  const [open, setOpen] = useState(problematic);

  return (
    <details
      className={`alert-rule alert-rule--${rule.state}`}
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <span className="alert-rule__identity">
          <b>{rule.name}</b>
          <small>
            {tx(
              language,
              `${rule.datasourceCount} datasource`,
              `${rule.datasourceCount} datasource${rule.datasourceCount === 1 ? "" : "s"}`,
            )}
          </small>
        </span>
        <span className="alert-rule__summary">
          <RuleBadge state={rule.state} language={language} />
          <span>Firing&nbsp;{rule.firingInstances}</span>
          <span>Pending&nbsp;{rule.pendingInstances}</span>
        </span>
      </summary>
      <div className="alert-replicas">
        {rule.replicas.map((replica) => (
          <ReplicaCard replica={replica} language={language} navigate={navigate} key={replica.id} />
        ))}
      </div>
    </details>
  );
}

type CategoryGroup = {
  key: string;
  category: string | null;
  rules: AlertRule[];
  problematic: boolean;
};

function CategoryDisclosure({
  group,
  language,
  navigate,
}: {
  group: CategoryGroup;
  language: Language;
  navigate: (path: string) => void;
}) {
  const [open, setOpen] = useState(group.problematic);
  const firing = group.rules.filter((rule) => rule.state === "firing").length;
  const pending = group.rules.filter((rule) => rule.state === "pending").length;
  const errors = group.rules.filter((rule) => rule.hasError).length;

  return (
    <details
      className={`alert-category ${group.problematic ? "alert-category--problem" : ""}`}
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <span>
          <b>{group.category ?? tx(language, "Без категории", "Uncategorized")}</b>
          <small>
            {tx(language, `Правил: ${group.rules.length}`, `Rules: ${group.rules.length}`)}
          </small>
        </span>
        <span className="alert-category__counts">
          {firing > 0 && <span className="alert-state alert-state--firing">Firing {firing}</span>}
          {pending > 0 && (
            <span className="alert-state alert-state--pending">Pending {pending}</span>
          )}
          {errors > 0 && (
            <span className="alert-state alert-state--error">
              {tx(language, "Ошибки", "Errors")} {errors}
            </span>
          )}
        </span>
      </summary>
      <div className="alert-category__rules">
        {group.rules.map((rule) => (
          <RuleDisclosure
            rule={rule}
            language={language}
            navigate={navigate}
            key={`${rule.id}:${rule.state}:${String(rule.hasError)}`}
          />
        ))}
      </div>
    </details>
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
  const [category, setCategory] = useState("");
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
      category,
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
    category,
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

  const groups = useMemo<CategoryGroup[]>(() => {
    const byCategory = new Map<string, CategoryGroup>();
    for (const rule of rules?.rules ?? []) {
      const key = rule.category ?? UNCATEGORIZED_FILTER;
      const existing = byCategory.get(key) ?? {
        key,
        category: rule.category,
        rules: [],
        problematic: false,
      };
      existing.rules.push(rule);
      existing.problematic ||= rule.state !== "inactive" || rule.hasError;
      byCategory.set(key, existing);
    }
    return [...byCategory.values()].sort(
      (left, right) =>
        Number(right.problematic) - Number(left.problematic) ||
        Number(left.category === null) - Number(right.category === null) ||
        (left.category ?? "").localeCompare(right.category ?? ""),
    );
  }, [rules]);

  const unavailable = runtimeMode === "unavailable";
  const showTotals = rules !== null && rules.dataState !== "unavailable" && !unavailable;
  const resetFilters = () => {
    setDatasourceId("");
    setCategory("");
    setStateFilter("all");
    setQuery("");
    setDebouncedQuery("");
    setPage(1);
  };
  const refresh = () => setRefreshVersion((value) => value + 1);

  return (
    <div className="page-stack alerts-page" aria-busy={rulesLoading}>
      <header className="alerts-heading">
        <span>
          <small>{tx(language, "Каталог Prometheus", "Prometheus catalog")}</small>
          <h1>{tx(language, "Алерты", "Alerts")}</h1>
          <p>
            {tx(
              language,
              "Техническое состояние правил по категориям и datasources. Реакция на события — во вкладке «Инциденты».",
              "Technical rule state by category and datasource. Event response stays in Incidents.",
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
            disabled={unavailable || rulesLoading}
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
                "Актуальное состояние правил не может быть подтверждено.",
                "Current rule state cannot be verified.",
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
            tx(language, "Уникальные правила", "Unique rules"),
            showTotals ? rules?.totals.rules : "—",
            "neutral",
          ],
          ["Firing", showTotals ? rules?.totals.firingRules : "—", "danger"],
          ["Pending", showTotals ? rules?.totals.pendingRules : "—", "warning"],
          [
            tx(language, "Ошибки вычисления", "Evaluation errors"),
            showTotals ? rules?.totals.errorRules : "—",
            "danger",
          ],
          ["Datasources", showTotals ? rules?.totals.datasources : "—", "neutral"],
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
            <small>Alert rules</small>
            <h2 id="alert-rules-title">{tx(language, "Правила Prometheus", "Prometheus rules")}</h2>
          </span>
          <span className="alerts-panel__status">
            {rules && showTotals ? (
              <small>
                {tx(
                  language,
                  `Показано ${rules.filteredRules} из ${rules.totals.rules}`,
                  `Showing ${rules.filteredRules} of ${rules.totals.rules}`,
                )}
              </small>
            ) : null}
            {rules?.lastSuccessfulRefresh ? (
              <time>
                {tx(language, "Обновлено", "Updated")}{" "}
                {formatDate(language, rules.lastSuccessfulRefresh)}
              </time>
            ) : null}
          </span>
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
            <span className="sr-only">{tx(language, "Категория", "Category")}</span>
            <select
              value={category}
              onChange={(event) => {
                setCategory(event.target.value);
                setPage(1);
              }}
              disabled={unavailable}
            >
              <option value="">{tx(language, "Все категории", "All categories")}</option>
              {rules?.categories.map((value) => (
                <option value={value} key={value}>
                  {value}
                </option>
              ))}
              {rules?.hasUncategorized ? (
                <option value={UNCATEGORIZED_FILTER}>
                  {tx(language, "Без категории", "Uncategorized")}
                </option>
              ) : null}
            </select>
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
              <option value="error">{tx(language, "С ошибкой", "Error")}</option>
              <option value="inactive">{tx(language, "Неактивные", "Inactive")}</option>
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
        ) : rulesError && !rules ? (
          <div className="alerts-empty" role="alert">
            <b>{tx(language, "Правила недоступны", "Alert rules unavailable")}</b>
            <span>{rulesError}</span>
            <button className="button button--quiet" type="button" onClick={refresh}>
              {tx(language, "Повторить", "Retry")}
            </button>
          </div>
        ) : groups.length ? (
          <div className={`alert-categories ${rulesLoading ? "is-refreshing" : ""}`}>
            {groups.map((group) => (
              <CategoryDisclosure
                group={group}
                language={language}
                navigate={navigate}
                key={`${group.key}:${String(group.problematic)}`}
              />
            ))}
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
                : rules?.dataState === "empty"
                  ? tx(
                      language,
                      "Prometheus не вернул alert rules.",
                      "Prometheus returned no alert rules.",
                    )
                  : tx(
                      language,
                      "Измените фильтры или добавьте правила в Prometheus.",
                      "Change filters or add rules in Prometheus.",
                    )}
            </span>
          </div>
        )}
        {rulesError && rules ? (
          <p className="alerts-inline-warning" role="status">
            {rulesError}
          </p>
        ) : null}
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

      {(rules?.errors.length ?? 0) > 0 && (
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
            {rules?.errors.map((error) => (
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

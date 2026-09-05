import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";

import {
  CHECK_STATUSES,
  type CheckDetail,
  type CheckFilters,
  type CheckListItem,
  type CheckResult,
  type CheckStatus,
  groupChecks,
  hasActiveCheckFilters,
  problemChecks,
  resultMatrix,
} from "./model";
import {
  type CheckDetailState,
  type ChecksListState,
  type ChecksOverviewState,
  type ChecksRequest,
  type ChecksRuntimeMode,
  useCheckDetail,
  useChecksList,
} from "./hooks";

export type ChecksLanguage = "ru" | "en";

type Navigate = (path: string) => void;

function tx(language: ChecksLanguage, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

const STATUS_COPY: Record<CheckStatus, readonly [string, string, string]> = {
  up: ["Работает", "Up", "✓"],
  degraded: ["Частичный отказ", "Degraded", "◐"],
  down: ["Не работает", "Down", "!"],
  stale: ["Устарело", "Stale", "◷"],
  unknown: ["Неизвестно", "Unknown", "?"],
};

const REASON_COPY: Record<string, readonly [string, string]> = {
  result_up: ["Последний результат успешен", "The latest result passed"],
  result_failed: ["Последний результат неуспешен", "The latest result failed"],
  all_sources_up: ["Все известные Sources успешны", "All known Sources are up"],
  all_results_up: ["Все части Check успешны", "All Check parts are up"],
  confirmed_failures: [
    "Отказ подтверждён требуемым числом Sources",
    "The required number of Sources confirmed the failure",
  ],
  mixed_results: ["Источники сообщают разные результаты", "Sources report mixed results"],
  insufficient_sources: [
    "Недостаточно независимых источников для подтверждения отказа",
    "Not enough independent sources to confirm the failure",
  ],
  incomplete_data: ["Набор результатов неполон", "The result set is incomplete"],
  expired_measurements: ["Все измерения устарели", "All measurements have expired"],
  invalid_data: ["Получены недостоверные данные", "Invalid or conflicting data was returned"],
  prometheus_unavailable: ["Prometheus временно недоступен", "Prometheus is unavailable"],
};

function reasonLabel(language: ChecksLanguage, reason: string | null) {
  if (!reason) return null;
  const copy = REASON_COPY[reason];
  return copy ? tx(language, copy[0], copy[1]) : reason.replaceAll("_", " ");
}

function formatTimestamp(language: ChecksLanguage, value: string | null) {
  if (!value) return tx(language, "Нет данных", "No data");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return tx(language, "Некорректное время", "Invalid time");
  return new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date);
}

function formatDuration(language: ChecksLanguage, value: number | null) {
  if (value === null) return tx(language, "Нет данных", "No data");
  if (value < 1) return `${Math.round(value * 1000)} ms`;
  return `${value.toFixed(value < 10 ? 2 : 1)} s`;
}

function Glyph({ children }: { children: ReactNode }) {
  return (
    <span className="checks-glyph" aria-hidden="true">
      {children}
    </span>
  );
}

function WarningCodesNotice({
  codes,
  language,
  compact = false,
}: {
  codes: string[];
  language: ChecksLanguage;
  compact?: boolean;
}) {
  if (!codes.length) return null;
  return (
    <div
      className={`checks-notice checks-notice--warning ${compact ? "checks-notice--compact" : ""}`}
      role="status"
    >
      <Glyph>△</Glyph>
      <span>
        <b>
          {tx(
            language,
            "Часть необязательных метрик Checks недоступна.",
            "Some optional Checks metrics are unavailable.",
          )}
        </b>
        <span className="checks-warning-codes">
          {codes.map((code) => (
            <code key={code}>{code}</code>
          ))}
        </span>
      </span>
    </div>
  );
}

export function CheckStatusBadge({
  status,
  language,
  compact = false,
}: {
  status: CheckStatus;
  language: ChecksLanguage;
  compact?: boolean;
}) {
  const [russian, english, icon] = STATUS_COPY[status];
  const label = tx(language, russian, english);
  return (
    <span className={`check-status check-status--${status}`} aria-label={label}>
      <Glyph>{icon}</Glyph>
      {!compact && <span>{label}</span>}
    </span>
  );
}

function Panel({
  children,
  className = "",
  title,
  eyebrow,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
  eyebrow?: string;
  action?: ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || eyebrow || action) && (
        <div className="panel__header">
          <div>
            {eyebrow && <span className="eyebrow">{eyebrow}</span>}
            {title && <h2>{title}</h2>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

function StateMessage({
  language,
  phase,
  error,
  onRetry,
  compact = false,
}: {
  language: ChecksLanguage;
  phase: ChecksListState["phase"] | CheckDetailState["phase"];
  error?: string | null;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const content = (() => {
    switch (phase) {
      case "loading":
        return {
          icon: "…",
          title: tx(language, "Загружаем Checks", "Loading Checks"),
          message: tx(
            language,
            "Получаем свежий снимок напрямую из Prometheus.",
            "Fetching a fresh snapshot backed by Prometheus.",
          ),
        };
      case "disabled":
        return {
          icon: "○",
          title: tx(language, "Модуль Checks отключён", "Checks is disabled"),
          message: tx(
            language,
            "Администратор может включить его серверной настройкой CHECKS_ENABLED.",
            "An administrator can enable it with the server-side CHECKS_ENABLED setting.",
          ),
        };
      case "unavailable":
        return {
          icon: "!",
          title: tx(language, "Результаты Checks недоступны", "Checks data is unavailable"),
          message: tx(
            language,
            "Прежний успешный результат скрыт: источник данных сейчас не подтвердил его актуальность.",
            "Any previous success is hidden because the data source cannot confirm that it is current.",
          ),
        };
      case "empty":
        return {
          icon: "◇",
          title: tx(language, "Проверок пока нет", "No checks yet"),
          message: tx(
            language,
            "Подключите совместимого исполнителя, публикующего synthetic_check_status и synthetic_check_last_run_timestamp_seconds в Prometheus.",
            "Connect a compatible runner that publishes synthetic_check_status and synthetic_check_last_run_timestamp_seconds to Prometheus.",
          ),
        };
      case "not_found":
        return {
          icon: "?",
          title: tx(language, "Check не найден", "Check not found"),
          message: tx(
            language,
            "Достоверный текущий перечень не содержит эту проверку.",
            "The verified current inventory does not contain this check.",
          ),
        };
      default:
        return null;
    }
  })();
  if (!content) return null;
  return (
    <div className={`checks-state ${compact ? "checks-state--compact" : ""}`} role="status">
      <Glyph>{content.icon}</Glyph>
      <div>
        <h3>{content.title}</h3>
        <p>{content.message}</p>
        {error && !["loading", "disabled", "empty"].includes(phase) && (
          <code className="checks-state__code">{error}</code>
        )}
      </div>
      {onRetry && phase === "unavailable" && (
        <button className="button button--quiet button--small" onClick={onRetry}>
          {tx(language, "Повторить", "Retry")}
        </button>
      )}
    </div>
  );
}

function SummaryStrip({
  summary,
  language,
  activeStatus,
  onStatus,
}: {
  summary: NonNullable<ChecksListState["summary"]>;
  language: ChecksLanguage;
  activeStatus?: "all" | CheckStatus;
  onStatus?: (status: "all" | CheckStatus) => void;
}) {
  const entries: Array<{ status: "all" | CheckStatus; value: number; label: string }> = [
    { status: "all", value: summary.total, label: tx(language, "Всего", "Total") },
    ...CHECK_STATUSES.map((status) => ({
      status,
      value: summary[status],
      label: tx(language, STATUS_COPY[status][0], STATUS_COPY[status][1]),
    })),
  ];
  return (
    <div className="checks-summary" aria-label={tx(language, "Сводка Checks", "Checks summary")}>
      {entries.map((entry) => {
        const content = (
          <>
            {entry.status !== "all" && <Glyph>{STATUS_COPY[entry.status][2]}</Glyph>}
            <strong>{entry.value}</strong>
            <span>{entry.label}</span>
          </>
        );
        return onStatus ? (
          <button
            key={entry.status}
            className={`checks-summary__item checks-summary__item--${entry.status} ${activeStatus === entry.status ? "active" : ""}`}
            aria-pressed={activeStatus === entry.status}
            onClick={() => onStatus(entry.status)}
          >
            {content}
          </button>
        ) : (
          <div
            key={entry.status}
            className={`checks-summary__item checks-summary__item--${entry.status}`}
          >
            {content}
          </div>
        );
      })}
    </div>
  );
}

export function ChecksWidget({
  state,
  language,
  navigate,
  onRetry,
}: {
  state: ChecksOverviewState;
  language: ChecksLanguage;
  navigate: Navigate;
  onRetry: () => void;
}) {
  if (state.phase === "disabled") return null;
  const problems = problemChecks(state.problems);
  return (
    <Panel
      className="checks-widget"
      eyebrow="Prometheus · Checks"
      title={tx(language, "Автоматизированные проверки", "Automated checks")}
      action={
        <button className="text-button" onClick={() => navigate("/checks")}>
          {tx(language, "Открыть Checks", "Open Checks")} <span aria-hidden="true">→</span>
        </button>
      }
    >
      <WarningCodesNotice codes={state.meta?.warningCodes ?? []} language={language} compact />
      {state.phase === "loading" || state.phase === "unavailable" ? (
        <StateMessage
          language={language}
          phase={state.phase}
          error={state.error}
          onRetry={onRetry}
          compact
        />
      ) : state.summary ? (
        <>
          {state.phase === "stale" && (
            <div className="checks-notice checks-notice--stale" role="status">
              <Glyph>◷</Glyph>
              {tx(
                language,
                "Показан явно помеченный устаревший снимок.",
                "This snapshot is explicitly marked as stale.",
              )}
            </div>
          )}
          <SummaryStrip summary={state.summary} language={language} />
          {state.phase === "empty" ? (
            <StateMessage language={language} phase="empty" compact />
          ) : problems.length ? (
            <div className="checks-problem-list">
              <h3>{tx(language, "Требуют внимания", "Needs attention")}</h3>
              {problems.map((check) => (
                <button
                  key={check.checkId}
                  className="checks-problem-row"
                  onClick={() => navigate(`/checks/${encodeURIComponent(check.checkId)}`)}
                >
                  <CheckStatusBadge status={check.status} language={language} compact />
                  <span>
                    <b>{check.name}</b>
                    <small>
                      {check.group ?? tx(language, "Без группы", "Ungrouped")}
                      {check.statusReason ? ` · ${reasonLabel(language, check.statusReason)}` : ""}
                    </small>
                  </span>
                  <span aria-hidden="true">›</span>
                </button>
              ))}
            </div>
          ) : (
            <div className="checks-all-up">
              <Glyph>✓</Glyph>
              <span>
                <b>{tx(language, "Все проверки работают", "All checks are up")}</b>
                <small>
                  {tx(
                    language,
                    "Проблемных Check в текущем снимке нет.",
                    "The current snapshot has no problem checks.",
                  )}
                </small>
              </span>
            </div>
          )}
        </>
      ) : null}
    </Panel>
  );
}

function initialFilters(): CheckFilters {
  const params =
    typeof window === "undefined" ? new URLSearchParams() : new URLSearchParams(location.search);
  const rawStatus = params.get("status") ?? "all";
  const status = CHECK_STATUSES.includes(rawStatus as CheckStatus)
    ? (rawStatus as CheckStatus)
    : "all";
  const rawOffset = Number(params.get("offset") ?? 0);
  return {
    status,
    group: params.get("group") ?? "",
    source: params.get("source") ?? "",
    target: params.get("target") ?? "",
    scenario: params.get("scenario") ?? "",
    search: params.get("search") ?? "",
    limit: 50,
    offset: Number.isFinite(rawOffset) && rawOffset > 0 ? Math.trunc(rawOffset / 50) * 50 : 0,
  };
}

function filtersUrl(filters: CheckFilters) {
  const query = new URLSearchParams();
  if (filters.status !== "all") query.set("status", filters.status);
  for (const key of ["group", "source", "target", "scenario", "search"] as const) {
    if (filters[key]) query.set(key, filters[key]);
  }
  if (filters.offset) query.set("offset", String(filters.offset));
  const serialized = query.toString();
  return `/checks${serialized ? `?${serialized}` : ""}`;
}

export function ChecksPage({
  request,
  runtimeMode,
  language,
  navigate,
}: {
  request: ChecksRequest;
  runtimeMode: ChecksRuntimeMode;
  language: ChecksLanguage;
  navigate: Navigate;
}) {
  const [filters, setFilters] = useState<CheckFilters>(initialFilters);
  const [searchDraft, setSearchDraft] = useState(filters.search);
  const [grouped, setGrouped] = useState(true);
  const [state, refresh] = useChecksList(request, runtimeMode, filters);
  const groups = useMemo(
    () => (grouped ? groupChecks(state.items) : [{ key: "all", label: null, items: state.items }]),
    [grouped, state.items],
  );
  const filtersActive = hasActiveCheckFilters(filters);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.history.replaceState(window.history.state, "", filtersUrl(filters));
  }, [filters]);

  const setFilter = <Key extends keyof CheckFilters>(key: Key, value: CheckFilters[Key]) => {
    setFilters((current) => ({ ...current, [key]: value, offset: 0 }));
  };
  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    setFilter("search", searchDraft.trim());
  };
  const reset = () => {
    setSearchDraft("");
    setFilters({
      status: "all",
      group: "",
      source: "",
      target: "",
      scenario: "",
      search: "",
      limit: 50,
      offset: 0,
    });
  };
  const firstItem = state.total === 0 ? 0 : state.offset + 1;
  const lastItem = Math.min(state.offset + state.items.length, state.total);

  return (
    <div className="page-stack checks-page">
      <div className="page-heading">
        <div>
          <span className="eyebrow">Prometheus · Checks</span>
          <h1>Checks</h1>
          <p>
            {tx(
              language,
              "Результаты внешних автоматизированных проверок по источникам, сценариям и вариантам.",
              "External automated-check results across sources, scenarios, and variants.",
            )}
          </p>
        </div>
        <div className="page-heading__actions">
          <button
            className="button button--quiet"
            onClick={refresh}
            disabled={state.phase === "loading"}
          >
            <Glyph>↻</Glyph>
            {state.refreshing
              ? tx(language, "Обновляем…", "Refreshing…")
              : tx(language, "Обновить", "Refresh")}
          </button>
        </div>
      </div>

      {state.summary && (
        <SummaryStrip
          summary={state.summary}
          language={language}
          activeStatus={filters.status}
          onStatus={(status) => setFilter("status", status)}
        />
      )}
      <WarningCodesNotice codes={state.meta?.warningCodes ?? []} language={language} />

      <Panel className="checks-list-panel">
        <form className="checks-filter-bar" onSubmit={submitSearch} role="search">
          <label className="checks-search">
            <Glyph>⌕</Glyph>
            <span className="sr-only">{tx(language, "Поиск Checks", "Search Checks")}</span>
            <input
              value={searchDraft}
              maxLength={200}
              onChange={(event) => setSearchDraft(event.target.value)}
              placeholder={tx(language, "ID, название или Target…", "ID, name, or Target…")}
            />
          </label>
          <button className="button button--quiet button--small">
            {tx(language, "Найти", "Search")}
          </button>
          <label className="checks-status-filter">
            <span>{tx(language, "Статус", "Status")}</span>
            <select
              value={filters.status}
              onChange={(event) =>
                setFilter("status", event.target.value as CheckFilters["status"])
              }
            >
              <option value="all">{tx(language, "Любой", "Any")}</option>
              {CHECK_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {tx(language, STATUS_COPY[status][0], STATUS_COPY[status][1])}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className={`button button--quiet button--small ${grouped ? "active" : ""}`}
            aria-pressed={grouped}
            onClick={() => setGrouped((value) => !value)}
          >
            <Glyph>≡</Glyph>
            {tx(language, "По группам", "Group results")}
          </button>
        </form>
        <details className="checks-more-filters">
          <summary>{tx(language, "Дополнительные фильтры", "More filters")}</summary>
          <div>
            {(["group", "source", "target", "scenario"] as const).map((key) => (
              <label key={key}>
                <span>{key[0].toUpperCase() + key.slice(1)}</span>
                <input
                  value={filters[key]}
                  maxLength={128}
                  onChange={(event) => setFilter(key, event.target.value)}
                />
              </label>
            ))}
            <button type="button" className="text-button" onClick={reset}>
              {tx(language, "Сбросить фильтры", "Reset filters")}
            </button>
          </div>
        </details>

        {state.phase === "empty" && filtersActive ? (
          <div className="checks-state" role="status">
            <Glyph>⌕</Glyph>
            <div>
              <h3>{tx(language, "Ничего не найдено", "Nothing found")}</h3>
              <p>
                {tx(
                  language,
                  "Текущим фильтрам не соответствует ни один Check.",
                  "No Check matches the current filters.",
                )}
              </p>
            </div>
            <button className="button button--quiet button--small" onClick={reset}>
              {tx(language, "Сбросить фильтры", "Reset filters")}
            </button>
          </div>
        ) : state.phase === "loading" ||
          state.phase === "disabled" ||
          state.phase === "unavailable" ||
          state.phase === "empty" ? (
          <StateMessage
            language={language}
            phase={state.phase}
            error={state.error}
            onRetry={refresh}
          />
        ) : (
          <>
            {state.phase === "stale" && (
              <div className="checks-notice checks-notice--stale" role="status">
                <Glyph>◷</Glyph>
                <span>
                  <b>{tx(language, "Снимок устарел", "Snapshot is stale")}</b>
                  {tx(
                    language,
                    " Эти результаты не обозначаются как актуальные.",
                    " These results are not presented as current.",
                  )}
                </span>
              </div>
            )}
            <div className="checks-result-count" aria-live="polite">
              {tx(language, "Показано", "Showing")} {firstItem}–{lastItem} / {state.total}
            </div>
            {groups.map((group) => (
              <section className="checks-group" key={group.key || "ungrouped"}>
                {grouped && (
                  <h2>
                    {group.label ?? tx(language, "Без группы", "Ungrouped")}
                    <span>{group.items.length}</span>
                  </h2>
                )}
                <ChecksTable items={group.items} language={language} navigate={navigate} />
              </section>
            ))}
            <nav
              className="checks-pagination"
              aria-label={tx(language, "Страницы Checks", "Checks pages")}
            >
              <button
                className="button button--quiet button--small"
                disabled={filters.offset === 0}
                onClick={() =>
                  setFilters((current) => ({
                    ...current,
                    offset: Math.max(0, current.offset - current.limit),
                  }))
                }
              >
                ← {tx(language, "Назад", "Previous")}
              </button>
              <span>
                {tx(language, "Страница", "Page")} {Math.floor(filters.offset / filters.limit) + 1}
              </span>
              <button
                className="button button--quiet button--small"
                disabled={filters.offset + state.items.length >= state.total}
                onClick={() =>
                  setFilters((current) => ({ ...current, offset: current.offset + current.limit }))
                }
              >
                {tx(language, "Далее", "Next")} →
              </button>
            </nav>
          </>
        )}
      </Panel>
    </div>
  );
}

function ChecksTable({
  items,
  language,
  navigate,
}: {
  items: CheckListItem[];
  language: ChecksLanguage;
  navigate: Navigate;
}) {
  return (
    <div className="checks-table-wrap">
      <table className="checks-table">
        <thead>
          <tr>
            <th>{tx(language, "Check", "Check")}</th>
            <th>{tx(language, "Статус", "Status")}</th>
            <th>{tx(language, "Последний запуск", "Last run")}</th>
            <th>
              <span
                title={tx(
                  language,
                  "Максимальная duration свежих успешных результатов",
                  "Maximum duration among fresh successful results",
                )}
              >
                {tx(language, "Макс. latency", "Max latency")}
              </span>
            </th>
            <th>{tx(language, "Sources", "Sources")}</th>
            <th>{tx(language, "Алерты", "Alerts")}</th>
            <th>
              <span className="sr-only">{tx(language, "Открыть", "Open")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((check) => (
            <tr key={check.checkId}>
              <td data-label="Check">
                <b>{check.name}</b>
                <small>
                  <code>{check.checkId}</code>
                  {check.target && <> · Target: {check.target}</>}
                </small>
                {check.dataIncomplete && (
                  <span className="checks-inline-warning">
                    <Glyph>△</Glyph>
                    {tx(language, "Неполные данные", "Incomplete data")}
                  </span>
                )}
                {check.diagnosticCodes.length > 0 && (
                  <span className="checks-inline-warning">
                    <Glyph>△</Glyph>
                    <span>
                      {tx(language, "Диагностика", "Diagnostics")}:{" "}
                      <code>{check.diagnosticCodes.join(", ")}</code>
                    </span>
                  </span>
                )}
              </td>
              <td data-label={tx(language, "Статус", "Status")}>
                <CheckStatusBadge status={check.status} language={language} />
                {check.statusReason && <small>{reasonLabel(language, check.statusReason)}</small>}
                {check.staleResults > 0 && (
                  <small>
                    {tx(language, "Устаревших результатов", "Stale results")}: {check.staleResults}
                  </small>
                )}
              </td>
              <td data-label={tx(language, "Последний запуск", "Last run")}>
                <time dateTime={check.lastCheckedAt ?? undefined}>
                  {formatTimestamp(language, check.lastCheckedAt)}
                </time>
                {check.oldestCheckedAt && check.oldestCheckedAt !== check.lastCheckedAt && (
                  <small>
                    {tx(language, "Самый старый", "Oldest")}:{" "}
                    {formatTimestamp(language, check.oldestCheckedAt)}
                  </small>
                )}
              </td>
              <td data-label={tx(language, "Макс. latency", "Max latency")}>
                {check.latencySeconds === null
                  ? "—"
                  : formatDuration(language, check.latencySeconds)}
              </td>
              <td data-label="Sources">
                <b>
                  {check.sourcesUp}/{check.sourcesTotal}
                </b>
                <small>{tx(language, "полностью успешны", "fully successful")}</small>
              </td>
              <td data-label={tx(language, "Алерты", "Alerts")}>
                {check.activeAlerts === null
                  ? tx(language, "Недоступно", "Unavailable")
                  : check.activeAlerts}
              </td>
              <td>
                <button
                  className="row-open"
                  onClick={() => navigate(`/checks/${encodeURIComponent(check.checkId)}`)}
                  aria-label={`${tx(language, "Открыть Check", "Open Check")} ${check.name}`}
                >
                  <span aria-hidden="true">›</span>
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ResultMetrics({ result, language }: { result: CheckResult; language: ChecksLanguage }) {
  return (
    <dl className="check-result-metrics">
      {result.durationSeconds !== null && (
        <div>
          <dt>Duration</dt>
          <dd>{formatDuration(language, result.durationSeconds)}</dd>
        </div>
      )}
      {result.ttfbSeconds !== null && (
        <div>
          <dt>TTFB</dt>
          <dd>{formatDuration(language, result.ttfbSeconds)}</dd>
        </div>
      )}
      <div>
        <dt>{tx(language, "Завершён", "Completed")}</dt>
        <dd>{formatTimestamp(language, result.checkedAt)}</dd>
      </div>
    </dl>
  );
}

function ResultExtras({ result, language }: { result: CheckResult; language: ChecksLanguage }) {
  if (!result.canaries.length && !result.assertions.length && !result.diagnosticCodes.length)
    return null;
  return (
    <div className="check-result-extras">
      {result.canaries.length > 0 && (
        <section>
          <h4>Canary</h4>
          <ul>
            {result.canaries.map((canary, index) => (
              <li key={`${canary.id ?? "canary"}-${index}`}>
                <Glyph>
                  {canary.success === true ? "✓" : canary.success === false ? "!" : "?"}
                </Glyph>
                <span>{canary.id ?? tx(language, "Основная canary", "Primary canary")}</span>
                <b>
                  {canary.success === true
                    ? tx(language, "успешно", "passed")
                    : canary.success === false
                      ? tx(language, "ошибка", "failed")
                      : tx(language, "нет данных", "unknown")}
                </b>
              </li>
            ))}
          </ul>
        </section>
      )}
      {result.assertions.length > 0 && (
        <section>
          <h4>Assertions</h4>
          <ul>
            {result.assertions.map((assertion) => (
              <li key={assertion.key}>
                <Glyph>
                  {assertion.success === true ? "✓" : assertion.success === false ? "!" : "?"}
                </Glyph>
                <code>{assertion.key}</code>
                <b>
                  {assertion.success === true
                    ? tx(language, "выполнено", "passed")
                    : assertion.success === false
                      ? tx(language, "не выполнено", "failed")
                      : tx(language, "нет данных", "unknown")}
                </b>
              </li>
            ))}
          </ul>
        </section>
      )}
      {result.diagnosticCodes.length > 0 && (
        <section>
          <h4>{tx(language, "Диагностика", "Diagnostics")}</h4>
          <ul>
            {result.diagnosticCodes.map((code) => (
              <li key={code}>
                <Glyph>△</Glyph>
                <code>{code}</code>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function CompactResult({ result, language }: { result: CheckResult; language: ChecksLanguage }) {
  return (
    <article className="check-compact-result">
      <div className="check-compact-result__head">
        <div>
          {result.source && <span>Source · {result.source}</span>}
          {result.scenario && <span>Scenario · {result.scenario}</span>}
          {result.variant && <span>Variant · {result.variant}</span>}
        </div>
        <CheckStatusBadge status={result.status} language={language} />
      </div>
      {result.statusReason && <p>{reasonLabel(language, result.statusReason)}</p>}
      {(result.stale || result.dataIncomplete) && (
        <div className="checks-inline-warning">
          <Glyph>△</Glyph>
          {result.stale
            ? tx(language, "Результат устарел", "Result is stale")
            : tx(language, "Результат неполон", "Result is incomplete")}
        </div>
      )}
      <ResultMetrics result={result} language={language} />
      <ResultExtras result={result} language={language} />
    </article>
  );
}

function ResultsMatrix({
  check,
  language,
  expanded,
  onToggle,
}: {
  check: CheckDetail;
  language: ChecksLanguage;
  expanded: Set<string>;
  onToggle: (key: string, open: boolean) => void;
}) {
  const matrix = resultMatrix(check);
  return (
    <div
      className="check-matrix-wrap"
      role="region"
      tabIndex={0}
      aria-label={tx(language, "Матрица Source × Scenario", "Source by Scenario matrix")}
    >
      <table className="check-matrix">
        <thead>
          <tr>
            <th>Source ↓ / Scenario →</th>
            {matrix.scenarios.map((scenario, index) => (
              <th key={scenario ?? `scenario-${index}`}>
                {scenario ?? tx(language, "Основной", "Primary")}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.sources.map((source, sourceIndex) => (
            <tr key={source ?? `source-${sourceIndex}`}>
              <th>{source ?? tx(language, "Основной", "Primary")}</th>
              {matrix.scenarios.map((scenario, scenarioIndex) => {
                const key = `${source ?? ""}\u0000${scenario ?? ""}`;
                const results = matrix.cells.get(key) ?? [];
                return (
                  <td key={`${key}-${scenarioIndex}`}>
                    {results.length ? (
                      results.map((result, index) => {
                        const resultKey = `${key}\u0000${result.variant ?? ""}\u0000${index}`;
                        const hasDetails =
                          result.durationSeconds !== null ||
                          result.ttfbSeconds !== null ||
                          result.canaries.length > 0 ||
                          result.assertions.length > 0 ||
                          result.diagnosticCodes.length > 0 ||
                          Boolean(result.statusReason);
                        return hasDetails ? (
                          <details
                            key={resultKey}
                            open={expanded.has(resultKey)}
                            onToggle={(event) => onToggle(resultKey, event.currentTarget.open)}
                          >
                            <summary>
                              <span>
                                {result.variant
                                  ? `Variant · ${result.variant}`
                                  : tx(language, "Основной вариант", "Primary variant")}
                              </span>
                              <CheckStatusBadge
                                status={result.status}
                                language={language}
                                compact
                              />
                            </summary>
                            {result.statusReason && (
                              <p>{reasonLabel(language, result.statusReason)}</p>
                            )}
                            <ResultMetrics result={result} language={language} />
                            <ResultExtras result={result} language={language} />
                          </details>
                        ) : (
                          <div className="check-matrix__plain" key={resultKey}>
                            {result.variant && <span>{result.variant}</span>}
                            <CheckStatusBadge status={result.status} language={language} />
                          </div>
                        );
                      })
                    ) : (
                      <span className="check-matrix__missing">
                        ? {tx(language, "Нет результата", "No result")}
                      </span>
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LinksPanel({
  check,
  language,
  navigate,
}: {
  check: CheckDetail;
  language: ChecksLanguage;
  navigate: Navigate;
}) {
  const incidentIdsFromAlerts = new Set(check.alerts.flatMap((alert) => alert.incidentId ?? []));
  const incidentHrefsFromAlerts = new Set(check.alerts.flatMap((alert) => alert.href ?? []));
  const standaloneIncidents = check.incidents.filter(
    (incident) =>
      !incidentIdsFromAlerts.has(incident.id) &&
      (!incident.href || !incidentHrefsFromAlerts.has(incident.href)),
  );
  const relationsIncomplete =
    check.relationsIncomplete ||
    (check.relatedAlertsTotal !== null && check.relatedAlertsTotal > check.alerts.length) ||
    (check.incidentsTotal !== null && check.incidentsTotal > check.incidents.length);
  return (
    <Panel
      className="check-links-panel"
      eyebrow={tx(language, "Связи", "Relationships")}
      title={tx(language, "Алерты и инциденты", "Alerts and incidents")}
    >
      {relationsIncomplete && (
        <div className="checks-notice checks-notice--warning check-relation-summary" role="status">
          <Glyph>△</Glyph>
          <span>
            <b>{tx(language, "Связи показаны не полностью.", "Relationships are incomplete.")}</b>
            <span>
              {tx(language, "Получено активных алертов", "Active alerts returned")}:{" "}
              {check.alerts.length}/{check.relatedAlertsTotal ?? "?"};{" "}
              {tx(language, "инцидентов", "incidents")}: {check.incidents.length}/
              {check.incidentsTotal ?? "?"}.
            </span>
            {check.relationWarningCodes.length > 0 && (
              <span className="checks-warning-codes">
                {check.relationWarningCodes.map((code) => (
                  <code key={code}>{code}</code>
                ))}
              </span>
            )}
          </span>
        </div>
      )}
      {!check.alertLinksAvailable || check.activeAlerts === null ? (
        <div className="checks-notice" role="status">
          <Glyph>?</Glyph>
          {tx(
            language,
            "Связи с алертами временно недоступны; статус Check не изменён.",
            "Alert relationships are temporarily unavailable; the Check status is unchanged.",
          )}
        </div>
      ) : check.alerts.length === 0 && standaloneIncidents.length === 0 ? (
        relationsIncomplete ? null : (
          <p className="check-links-empty">
            {tx(language, "Активных связанных алертов нет.", "No linked active alerts.")}
          </p>
        )
      ) : (
        <div className="check-link-list">
          {check.alerts.map((alert, index) => (
            <article key={alert.id ?? `${alert.name}-${index}`}>
              <Glyph>!</Glyph>
              <span>
                <b>{alert.name}</b>
                <small>
                  {alert.severity && `${alert.severity} · `}
                  {formatTimestamp(language, alert.startsAt)}
                </small>
              </span>
              {(alert.href || alert.incidentId) && (
                <button
                  className="text-button"
                  onClick={() =>
                    navigate(
                      alert.href ?? `/incidents/${encodeURIComponent(alert.incidentId ?? "")}`,
                    )
                  }
                >
                  {tx(language, "Подробнее", "Details")} →
                </button>
              )}
            </article>
          ))}
          {standaloneIncidents.map((incident) => (
            <article key={incident.id}>
              <Glyph>◇</Glyph>
              <span>
                <b>{incident.title}</b>
                {incident.status && <small>{incident.status}</small>}
              </span>
              <button
                className="text-button"
                onClick={() =>
                  navigate(incident.href ?? `/incidents/${encodeURIComponent(incident.id)}`)
                }
              >
                {tx(language, "Открыть", "Open")} →
              </button>
            </article>
          ))}
        </div>
      )}
    </Panel>
  );
}

export function CheckDetailPage({
  checkId,
  request,
  runtimeMode,
  language,
  navigate,
}: {
  checkId: string;
  request: ChecksRequest;
  runtimeMode: ChecksRuntimeMode;
  language: ChecksLanguage;
  navigate: Navigate;
}) {
  const [state, refresh] = useCheckDetail(request, runtimeMode, checkId);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const onToggle = (key: string, open: boolean) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (open) next.add(key);
      else next.delete(key);
      return next;
    });
  };

  if (!state.check) {
    return (
      <div className="page-stack check-detail-page">
        <button className="breadcrumb-button" onClick={() => navigate("/checks")}>
          ← Checks
        </button>
        <Panel>
          <StateMessage
            language={language}
            phase={state.phase}
            error={state.error}
            onRetry={refresh}
          />
          <WarningCodesNotice codes={state.meta?.warningCodes ?? []} language={language} />
          {state.phase === "not_found" && (
            <div className="checks-state-action">
              <button className="button button--quiet" onClick={() => navigate("/checks")}>
                {tx(language, "Вернуться к списку", "Back to Checks")}
              </button>
            </div>
          )}
        </Panel>
      </div>
    );
  }

  const check = state.check;
  return (
    <div className="page-stack check-detail-page">
      <button className="breadcrumb-button" onClick={() => navigate("/checks")}>
        ← Checks
      </button>
      <header className={`check-detail-hero check-detail-hero--${check.status}`}>
        <CheckStatusBadge status={check.status} language={language} />
        <div>
          <span className="eyebrow">{check.group ?? tx(language, "Без группы", "Ungrouped")}</span>
          <h1>{check.name}</h1>
          <p>
            <code>{check.checkId}</code>
            {check.target && <> · Target: {check.target}</>}
          </p>
          {check.statusReason && <strong>{reasonLabel(language, check.statusReason)}</strong>}
        </div>
        <div className="check-detail-actions">
          <button className="button button--quiet" onClick={refresh}>
            <Glyph>↻</Glyph>
            {tx(language, "Обновить", "Refresh")}
          </button>
          {check.grafanaUrl ? (
            <a
              className="button button--primary"
              href={check.grafanaUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Glyph>↗</Glyph> Grafana
            </a>
          ) : (
            <span className="button button--quiet checks-disabled-link" aria-disabled="true">
              Grafana {tx(language, "не настроена", "not configured")}
            </span>
          )}
        </div>
      </header>

      <WarningCodesNotice codes={state.meta?.warningCodes ?? []} language={language} />

      {(state.phase === "stale" || check.dataIncomplete || check.staleResults > 0) && (
        <div className="checks-notice checks-notice--stale" role="status">
          <Glyph>△</Glyph>
          <span>
            {state.phase === "stale" || check.staleResults > 0
              ? tx(language, "Есть устаревшие результаты. ", "Some results are stale. ")
              : ""}
            {check.dataIncomplete
              ? tx(
                  language,
                  "Набор данных неполон; статус учитывает только достоверные результаты.",
                  "The data set is incomplete; status uses only trustworthy results.",
                )
              : ""}
          </span>
        </div>
      )}

      <div className="check-detail-summary">
        <div>
          <span>Sources</span>
          <b>
            {check.sourcesUp}/{check.sourcesTotal}
          </b>
          <small>{tx(language, "полностью успешны", "fully successful")}</small>
        </div>
        <div>
          <span>{tx(language, "Последний запуск", "Latest run")}</span>
          <b>{formatTimestamp(language, check.lastCheckedAt)}</b>
        </div>
        <div>
          <span>{tx(language, "Самый старый результат", "Oldest result")}</span>
          <b>{formatTimestamp(language, check.oldestCheckedAt)}</b>
        </div>
        <div>
          <span>{tx(language, "Макс. latency успешных", "Max successful latency")}</span>
          <b>{formatDuration(language, check.latencySeconds)}</b>
        </div>
      </div>

      <Panel
        className="check-results-panel"
        eyebrow={tx(language, "Текущий снимок", "Current snapshot")}
        title={tx(language, "Результаты", "Results")}
      >
        {check.results.length === 0 ? (
          <div className="checks-state checks-state--compact" role="status">
            <Glyph>?</Glyph>
            <div>
              <h3>{tx(language, "Результатов нет", "No results")}</h3>
              <p>
                {tx(
                  language,
                  "Check известен по inventory, но завершённый запуск ещё не получен.",
                  "The Check is known from inventory, but no completed run has been received.",
                )}
              </p>
            </div>
          </div>
        ) : check.results.length === 1 ? (
          <CompactResult result={check.results[0]} language={language} />
        ) : (
          <ResultsMatrix
            check={check}
            language={language}
            expanded={expanded}
            onToggle={onToggle}
          />
        )}
      </Panel>

      <LinksPanel check={check} language={language} navigate={navigate} />
      {state.meta && (
        <p className="checks-snapshot-meta">
          Snapshot <code>{state.meta.snapshotId ?? "—"}</code> ·{" "}
          {tx(language, "получен", "fetched")} {formatTimestamp(language, state.meta.fetchedAt)} ·{" "}
          {tx(language, "оценён", "evaluated")} {formatTimestamp(language, state.meta.evaluatedAt)}
        </p>
      )}
    </div>
  );
}

import {
  type AlertHistorySnapshot,
  type AlertHistoryState,
  type AlertHistoryWindow,
  type AlertRule,
  historyForRule,
} from "./model";

type Language = "ru" | "en";

function tx(language: Language, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

function windowLabel(language: Language, window: AlertHistoryWindow) {
  if (window === "24h") return tx(language, "24 часа", "24 hours");
  if (window === "7d") return tx(language, "7 дней", "7 days");
  return tx(language, "30 дней", "30 days");
}

function stateLabel(language: Language, state: AlertHistoryState) {
  if (state === "firing") return "Firing";
  if (state === "pending") return "Pending";
  if (state === "inactive") return tx(language, "Спокойно", "Quiet");
  return tx(language, "Нет данных", "Unknown");
}

function formatPercent(language: Language, value: number | null) {
  if (value === null) return "—";
  return `${new Intl.NumberFormat(language === "ru" ? "ru-RU" : "en-GB", {
    maximumFractionDigits: value === 100 ? 0 : 1,
  }).format(value)}%`;
}

function formatBucket(language: Language, startsAt: string, endsAt: string) {
  const formatter = new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `${formatter.format(new Date(startsAt))} — ${formatter.format(new Date(endsAt))}`;
}

export function AlertHistory({
  rule,
  snapshot,
  window,
  language,
  loading,
  error,
}: {
  rule: AlertRule;
  snapshot: AlertHistorySnapshot | null;
  window: AlertHistoryWindow;
  language: Language;
  loading: boolean;
  error: string | null;
}) {
  const timeline = historyForRule(snapshot, rule);
  const counts = timeline
    ? timeline.states.reduce<Record<AlertHistoryState, number>>(
        (result, state) => ({ ...result, [state]: result[state] + 1 }),
        { inactive: 0, pending: 0, firing: 0, unknown: 0 },
      )
    : null;
  const mutedCount = timeline?.muted.filter((value) => value === true).length ?? 0;
  const ariaLabel = timeline
    ? tx(
        language,
        `История ${rule.name} за ${windowLabel(language, window)}: спокойно ${counts?.inactive ?? 0}, firing ${counts?.firing ?? 0}, pending ${counts?.pending ?? 0}, без данных ${counts?.unknown ?? 0}, приглушено в Alert Hub ${mutedCount}.`,
        `${rule.name} history for ${windowLabel(language, window)}: quiet ${counts?.inactive ?? 0}, firing ${counts?.firing ?? 0}, pending ${counts?.pending ?? 0}, unknown ${counts?.unknown ?? 0}, silenced in Alert Hub ${mutedCount}.`,
      )
    : "";

  return (
    <section className="alert-history" aria-label={tx(language, "История алерта", "Alert history")}>
      <header className="alert-history__head">
        <span>
          <b>{tx(language, "История состояния", "State history")}</b>
          <small>{windowLabel(language, window)} · Prometheus</small>
        </span>
        <span className="alert-history__score">
          <b>{formatPercent(language, timeline?.quietPercent ?? null)}</b>
          <small>{tx(language, "спокойных интервалов", "quiet intervals")}</small>
        </span>
      </header>

      {timeline && snapshot ? (
        <>
          <div className="alert-history__segments" role="img" aria-label={ariaLabel}>
            {timeline.states.map((state, index) => {
              const muted = timeline.muted[index] === true;
              const bucket = snapshot.buckets[index];
              const title = bucket
                ? `${formatBucket(language, bucket.startsAt, bucket.endsAt)} · ${stateLabel(language, state)}${muted ? ` · ${tx(language, "приглушено в Alert Hub", "silenced in Alert Hub")}` : ""}`
                : stateLabel(language, state);
              return (
                <span
                  className={`alert-history__segment alert-history__segment--${state} ${muted ? "is-muted" : ""}`}
                  title={title}
                  aria-hidden="true"
                  key={bucket?.startsAt ?? index}
                />
              );
            })}
          </div>
          <ul className="sr-only">
            {timeline.states.map((state, index) => {
              const bucket = snapshot.buckets[index];
              if (!bucket) return null;
              const muteState =
                timeline.muted[index] === true
                  ? tx(language, "приглушено в Alert Hub", "silenced in Alert Hub")
                  : timeline.muted[index] === false
                    ? tx(language, "не приглушено", "not silenced")
                    : tx(language, "статус приглушения неизвестен", "silence status unknown");
              return (
                <li key={`accessible-${bucket.startsAt}`}>
                  {formatBucket(language, bucket.startsAt, bucket.endsAt)}:{" "}
                  {stateLabel(language, state)}; {muteState}.
                </li>
              );
            })}
          </ul>
          <footer className="alert-history__footer">
            <ul className="alert-history__legend" aria-label={tx(language, "Легенда", "Legend")}>
              {(["inactive", "pending", "firing", "unknown"] as AlertHistoryState[]).map(
                (state) => (
                  <li key={state}>
                    <i className={`alert-history__key alert-history__key--${state}`} />
                    {stateLabel(language, state)}
                  </li>
                ),
              )}
              <li>
                <i className="alert-history__key alert-history__key--firing is-muted" />
                {tx(language, "Приглушено в Alert Hub", "Silenced in Alert Hub")}
              </li>
            </ul>
            {timeline.coveragePercent < 100 ? (
              <small>
                {tx(language, "Покрытие", "Coverage")}{" "}
                {formatPercent(language, timeline.coveragePercent)}
              </small>
            ) : null}
          </footer>
        </>
      ) : (
        <div className="alert-history__empty" role="status">
          {loading
            ? tx(language, "Загружаем историю…", "Loading history…")
            : error || tx(language, "История пока недоступна", "History is unavailable")}
        </div>
      )}
    </section>
  );
}

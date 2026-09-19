import {
  stateHistoryRuns,
  type StateHistoryBucket,
  type StateHistoryTimeline,
  type StateHistoryTone,
} from "./model";

type Language = "ru" | "en";
type HistoryWindow = "24h" | "7d" | "30d";

export type StateHistoryLabels = Record<StateHistoryTone, string> & {
  score: string;
};

function tx(language: Language, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

function windowLabel(language: Language, window: HistoryWindow) {
  if (window === "24h") return tx(language, "24 часа", "24 hours");
  if (window === "7d") return tx(language, "7 дней", "7 days");
  return tx(language, "30 дней", "30 days");
}

function formatPercent(language: Language, value: number | null) {
  if (value === null) return "—";
  return `${new Intl.NumberFormat(language === "ru" ? "ru-RU" : "en-GB", {
    maximumFractionDigits: value === 100 ? 0 : 1,
  }).format(value)}%`;
}

function formatBucket(language: Language, bucket: StateHistoryBucket) {
  const formatter = new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `${formatter.format(new Date(bucket.startsAt))} — ${formatter.format(new Date(bucket.endsAt))}`;
}

function periodSummary(period: StateHistoryTone[], labels: StateHistoryLabels): string {
  return stateHistoryRuns(period)
    .map((run) => `${labels[run.tone]} ${Math.round((run.units / period.length) * 100)}%`)
    .join(" → ");
}

export function StateHistoryPills({
  buckets,
  timeline,
  window,
  language,
  subject,
  labels,
  loading = false,
  error = null,
  compact = false,
  className = "",
}: {
  buckets: StateHistoryBucket[];
  timeline: StateHistoryTimeline | null;
  window: HistoryWindow;
  language: Language;
  subject: string;
  labels: StateHistoryLabels;
  loading?: boolean;
  error?: string | null;
  compact?: boolean;
  className?: string;
}) {
  const samples = timeline?.periods.flat() ?? [];
  const counts = samples.reduce<Record<StateHistoryTone, number>>(
    (result, tone) => ({ ...result, [tone]: result[tone] + 1 }),
    { healthy: 0, warning: 0, critical: 0 },
  );
  const partialLabel = timeline?.partial
    ? tx(language, "Некоторые datasources недоступны.", "Some datasources are unavailable.")
    : "";
  const ariaLabel = timeline
    ? tx(
        language,
        `История ${subject} за ${windowLabel(language, window)}: ${labels.healthy} ${counts.healthy}, ${labels.warning} ${counts.warning}, ${labels.critical} ${counts.critical}. Хронология внутри каждой капсулы идёт сверху вниз. ${partialLabel}`,
        `${subject} history for ${windowLabel(language, window)}: ${labels.healthy} ${counts.healthy}, ${labels.warning} ${counts.warning}, ${labels.critical} ${counts.critical}. Chronology inside each pill runs top to bottom. ${partialLabel}`,
      )
    : tx(language, `История ${subject} недоступна`, `${subject} history is unavailable`);

  const pills = timeline ? (
    <div className="state-history__pills" role="img" aria-label={ariaLabel}>
      {timeline.periods.map((period, index) => {
        const bucket = buckets[index];
        const title = bucket
          ? `${formatBucket(language, bucket)} · ${periodSummary(period, labels)}`
          : periodSummary(period, labels);
        return (
          <span
            className="state-history__pill"
            title={title}
            aria-hidden="true"
            key={bucket?.startsAt ?? index}
          >
            {stateHistoryRuns(period).map((run, runIndex) => (
              <i
                className={`state-history__slice state-history__slice--${run.tone}`}
                style={{ flexGrow: run.units }}
                key={`${run.tone}-${runIndex}`}
              />
            ))}
          </span>
        );
      })}
    </div>
  ) : null;

  if (compact) {
    return (
      <div className={`state-history state-history--compact ${className}`.trim()}>
        {pills ?? (
          <span className="state-history__compact-empty" role="status" aria-label={ariaLabel}>
            —
          </span>
        )}
        {timeline?.partial ? (
          <span
            className="state-history__partial-marker"
            role="status"
            aria-label={partialLabel}
            title={partialLabel}
          >
            !
          </span>
        ) : null}
      </div>
    );
  }

  return (
    <section
      className={`state-history state-history--full ${className}`.trim()}
      aria-label={tx(language, "История состояния", "State history")}
    >
      <header className="state-history__head">
        <span>
          <b>{tx(language, "История состояния", "State history")}</b>
          <small>{windowLabel(language, window)} · Prometheus</small>
        </span>
        <span className="state-history__score">
          <b>{formatPercent(language, timeline?.healthyPercent ?? null)}</b>
          <small>{labels.score}</small>
        </span>
      </header>

      {pills ? (
        <>
          {pills}
          <ul className="sr-only">
            {timeline?.periods.map((period, index) => {
              const bucket = buckets[index];
              if (!bucket) return null;
              return (
                <li key={`accessible-${bucket.startsAt}`}>
                  {formatBucket(language, bucket)}: {periodSummary(period, labels)}.
                </li>
              );
            })}
          </ul>
          <footer className="state-history__footer">
            <ul className="state-history__legend" aria-label={tx(language, "Легенда", "Legend")}>
              {(["healthy", "warning", "critical"] as StateHistoryTone[]).map((tone) => (
                <li key={tone}>
                  <i className={`state-history__key state-history__key--${tone}`} />
                  {labels[tone]}
                </li>
              ))}
            </ul>
            <small>
              {timeline?.partial
                ? tx(language, "Часть datasources недоступна · ", "Some datasources unavailable · ")
                : ""}
              {tx(language, "раньше сверху → позже снизу", "earlier at top → later at bottom")}
            </small>
          </footer>
        </>
      ) : (
        <div className="state-history__empty" role="status">
          {loading
            ? tx(language, "Загружаем историю…", "Loading history…")
            : error || tx(language, "История пока недоступна", "History is unavailable")}
        </div>
      )}
    </section>
  );
}

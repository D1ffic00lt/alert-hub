import { useId } from "react";

import "./statistics.css";

import { formatStatisticsDuration } from "./format";
import {
  isStatisticsSnapshotEmpty,
  type StatisticsChannel,
  type StatisticsSnapshot,
  type StatisticsTimelinePoint,
  type StatisticsWindow,
} from "./model";

export type StatisticsLanguage = "ru" | "en";

export type StatisticsOverviewProps = {
  snapshot: StatisticsSnapshot | null;
  language: StatisticsLanguage;
  grafanaUrl?: string | null;
  loading?: boolean;
};

function tx(language: StatisticsLanguage, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

function formatNumber(language: StatisticsLanguage, value: number) {
  return new Intl.NumberFormat(language === "ru" ? "ru-RU" : "en-GB", {
    maximumFractionDigits: 0,
  }).format(value);
}

function formatPercent(language: StatisticsLanguage, value: number | null) {
  if (value === null || !Number.isFinite(value)) return "—";
  return `${new Intl.NumberFormat(language === "ru" ? "ru-RU" : "en-GB", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(value)}%`;
}

function formatTimestamp(language: StatisticsLanguage, value: string | null) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

function formatBucketLabel(
  language: StatisticsLanguage,
  value: string,
  bucketSeconds: number | null,
) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    day: "numeric",
    month: "short",
    ...(bucketSeconds !== null && bucketSeconds < 86_400
      ? { hour: "2-digit", minute: "2-digit" }
      : {}),
    timeZone: "UTC",
  }).format(date);
}

function formatBucketAxisLabel(
  language: StatisticsLanguage,
  value: string,
  bucketSeconds: number | null,
) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(language === "ru" ? "ru-RU" : "en-GB", {
    ...(bucketSeconds !== null && bucketSeconds < 21_600
      ? { hour: "2-digit", minute: "2-digit" }
      : { day: "numeric", month: "short" }),
    timeZone: "UTC",
  }).format(date);
}

function showBucketAxisLabel(
  points: StatisticsTimelinePoint[],
  index: number,
  stride: number,
  language: StatisticsLanguage,
  bucketSeconds: number | null,
) {
  if (index % stride === 0) return true;
  if (index !== points.length - 1) return false;
  const previousIndex = Math.floor(index / stride) * stride;
  return (
    formatBucketAxisLabel(language, points[previousIndex]?.startsAt ?? "", bucketSeconds) !==
    formatBucketAxisLabel(language, points[index]?.startsAt ?? "", bucketSeconds)
  );
}

function windowLabel(language: StatisticsLanguage, window: StatisticsWindow) {
  const labels: Record<StatisticsWindow, readonly [string, string]> = {
    "24h": ["24 часа", "24 hours"],
    "7d": ["7 дней", "7 days"],
    "30d": ["30 дней", "30 days"],
  };
  return tx(language, labels[window][0], labels[window][1]);
}

function safeExternalUrl(value: string | null | undefined) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

function StatisticsHeader({ snapshot, language, grafanaUrl }: StatisticsOverviewProps) {
  const url = safeExternalUrl(grafanaUrl);
  const window = snapshot?.window ?? "7d";
  const generatedAt = formatTimestamp(language, snapshot?.generatedAt ?? null);
  return (
    <header className="statistics-overview__header">
      <div>
        <span className="statistics-overview__eyebrow">
          {tx(language, "Операционная аналитика", "Operational analytics")}
        </span>
        <h2 id="statistics-overview-title">
          {tx(
            language,
            `Статистика за ${windowLabel(language, window)}`,
            `Statistics for ${windowLabel(language, window)}`,
          )}
        </h2>
        <p>
          {tx(
            language,
            "Инциденты и доставка уведомлений по подтверждённому снимку.",
            "Incidents and notification delivery from the verified snapshot.",
          )}
          {generatedAt ? (
            <>
              {" "}
              {tx(language, "Обновлено", "Updated")}{" "}
              <time dateTime={snapshot?.generatedAt ?? undefined}>{generatedAt}</time>.
            </>
          ) : null}
        </p>
      </div>
      {url ? (
        <a
          className="button button--quiet statistics-overview__grafana"
          href={url}
          target="_blank"
          rel="noopener noreferrer"
        >
          <span aria-hidden="true">↗</span>
          {tx(language, "Подробнее в Grafana", "Explore in Grafana")}
        </a>
      ) : null}
    </header>
  );
}

function StatisticsState({
  language,
  kind,
}: {
  language: StatisticsLanguage;
  kind: "empty" | "unavailable";
}) {
  const unavailable = kind === "unavailable";
  return (
    <div className={`statistics-state statistics-state--${kind}`} role="status">
      <span className="statistics-state__icon" aria-hidden="true">
        {unavailable ? "!" : "◇"}
      </span>
      <div>
        <h3>
          {unavailable
            ? tx(language, "Статистика недоступна", "Statistics unavailable")
            : tx(language, "За период событий нет", "No activity in this period")}
        </h3>
        <p>
          {unavailable
            ? tx(
                language,
                "Сервер не вернул подтверждённый снимок. Нулевые значения не подставляются.",
                "The server did not return a verified snapshot. Zero values are not substituted.",
              )
            : tx(
                language,
                "Подтверждённый снимок не содержит инцидентов или попыток доставки.",
                "The verified snapshot contains no incidents or delivery attempts.",
              )}
        </p>
      </div>
    </div>
  );
}

function StatisticsLoading({ language }: { language: StatisticsLanguage }) {
  return (
    <div
      className="statistics-loading"
      role="status"
      aria-busy="true"
      aria-label={tx(language, "Статистика загружается", "Statistics are loading")}
    >
      <span className="sr-only">
        {tx(language, "Загружаем статистику за 7 дней.", "Loading seven-day statistics.")}
      </span>
      <div className="statistics-loading__kpis" aria-hidden="true">
        {Array.from({ length: 4 }, (_, index) => (
          <i key={index} />
        ))}
      </div>
      <div className="statistics-loading__charts" aria-hidden="true">
        <i />
        <i />
      </div>
    </div>
  );
}

function StatisticsKpi({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: string;
  note: string;
  tone: "accent" | "danger" | "success" | "warning";
}) {
  return (
    <article className="statistics-kpi" data-tone={tone}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function ChartLegend({ items }: { items: Array<{ className: string; label: string }> }) {
  return (
    <div className="statistics-chart__legend">
      {items.map((item) => (
        <span key={item.label}>
          <i className={item.className} aria-hidden="true" />
          {item.label}
        </span>
      ))}
    </div>
  );
}

function ChartEmpty({ language }: { language: StatisticsLanguage }) {
  return (
    <div className="statistics-chart__empty" role="status">
      {tx(language, "Динамика за период не передана.", "No timeline was returned for this period.")}
    </div>
  );
}

function IncidentTrendChart({
  points,
  language,
  bucketSeconds,
}: {
  points: StatisticsTimelinePoint[];
  language: StatisticsLanguage;
  bucketSeconds: number | null;
}) {
  const titleId = useId();
  const descriptionId = useId();
  if (points.length === 0) {
    return (
      <article className="statistics-panel statistics-chart-panel">
        <h3>{tx(language, "Динамика инцидентов", "Incident trend")}</h3>
        <ChartEmpty language={language} />
      </article>
    );
  }
  const width = 640;
  const height = 224;
  const inset = { top: 18, right: 16, bottom: 42, left: 38 };
  const plotWidth = width - inset.left - inset.right;
  const plotHeight = height - inset.top - inset.bottom;
  const maximum = Math.max(
    1,
    ...points.flatMap((point) => [point.incidentsStarted, point.incidentsResolved]),
  );
  const x = (index: number) =>
    points.length === 1
      ? inset.left + plotWidth / 2
      : inset.left + (index / (points.length - 1)) * plotWidth;
  const y = (value: number) => inset.top + plotHeight - (value / maximum) * plotHeight;
  const line = (key: "incidentsStarted" | "incidentsResolved") =>
    points.map((point, index) => `${x(index)},${y(point[key])}`).join(" ");
  const labelStride = Math.max(1, Math.ceil(points.length / 7));
  return (
    <article className="statistics-panel statistics-chart-panel">
      <div className="statistics-panel__heading">
        <h3 id={titleId}>{tx(language, "Динамика инцидентов", "Incident trend")}</h3>
        <ChartLegend
          items={[
            {
              className: "statistics-legend-mark statistics-legend-mark--started",
              label: tx(language, "Начались", "Started"),
            },
            {
              className: "statistics-legend-mark statistics-legend-mark--resolved",
              label: tx(language, "Разрешены", "Resolved"),
            },
          ]}
        />
      </div>
      <p className="sr-only" id={descriptionId}>
        {tx(
          language,
          "Линейный график количества начавшихся и разрешённых инцидентов по периодам.",
          "Line chart of incidents started and resolved in each period.",
        )}
      </p>
      <div
        className="statistics-chart__viewport"
        role="region"
        tabIndex={0}
        aria-label={tx(language, "Прокручиваемый график инцидентов", "Scrollable incident chart")}
      >
        <svg
          className="statistics-chart"
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-labelledby={`${titleId} ${descriptionId}`}
        >
          {[0, 0.5, 1].map((ratio) => {
            const lineY = inset.top + plotHeight * ratio;
            const value = Math.round(maximum * (1 - ratio));
            return (
              <g key={ratio}>
                <line
                  className="statistics-chart__grid"
                  x1={inset.left}
                  x2={width - inset.right}
                  y1={lineY}
                  y2={lineY}
                />
                <text className="statistics-chart__axis" x={inset.left - 9} y={lineY + 4}>
                  {value}
                </text>
              </g>
            );
          })}
          <polyline
            className="statistics-chart__line statistics-chart__line--started"
            points={line("incidentsStarted")}
          />
          <polyline
            className="statistics-chart__line statistics-chart__line--resolved"
            points={line("incidentsResolved")}
          />
          {points.map((point, index) => (
            <g key={point.startsAt}>
              <circle
                className="statistics-chart__point statistics-chart__point--started"
                cx={x(index)}
                cy={y(point.incidentsStarted)}
                r="3.2"
              />
              <rect
                className="statistics-chart__point statistics-chart__point--resolved"
                x={x(index) - 3}
                y={y(point.incidentsResolved) - 3}
                width="6"
                height="6"
                transform={`rotate(45 ${x(index)} ${y(point.incidentsResolved)})`}
              />
              {showBucketAxisLabel(points, index, labelStride, language, bucketSeconds) && (
                <text className="statistics-chart__label" x={x(index)} y={height - 13}>
                  {formatBucketAxisLabel(language, point.startsAt, bucketSeconds)}
                </text>
              )}
            </g>
          ))}
        </svg>
      </div>
      <table className="sr-only">
        <caption>{tx(language, "Данные динамики инцидентов", "Incident trend data")}</caption>
        <thead>
          <tr>
            <th>{tx(language, "Период", "Period")}</th>
            <th>{tx(language, "Начались", "Started")}</th>
            <th>{tx(language, "Разрешены", "Resolved")}</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point) => (
            <tr key={point.startsAt}>
              <td>{formatBucketLabel(language, point.startsAt, bucketSeconds)}</td>
              <td>{point.incidentsStarted}</td>
              <td>{point.incidentsResolved}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}

function DeliveryTrendChart({
  points,
  language,
  bucketSeconds,
}: {
  points: StatisticsTimelinePoint[];
  language: StatisticsLanguage;
  bucketSeconds: number | null;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const failurePatternId = `${useId().replaceAll(":", "")}-delivery-failure`;
  if (points.length === 0) {
    return (
      <article className="statistics-panel statistics-chart-panel">
        <h3>{tx(language, "Доставка уведомлений", "Notification delivery")}</h3>
        <ChartEmpty language={language} />
      </article>
    );
  }
  const width = 640;
  const height = 224;
  const inset = { top: 18, right: 16, bottom: 42, left: 38 };
  const plotWidth = width - inset.left - inset.right;
  const plotHeight = height - inset.top - inset.bottom;
  const totals = points.map((point) => point.deliveriesSucceeded + point.deliveriesFailed);
  const maximum = Math.max(1, ...totals);
  const slot = plotWidth / Math.max(1, points.length);
  const barWidth = Math.min(42, slot * 0.58);
  const labelStride = Math.max(1, Math.ceil(points.length / 7));
  return (
    <article className="statistics-panel statistics-chart-panel">
      <div className="statistics-panel__heading">
        <h3 id={titleId}>{tx(language, "Доставка уведомлений", "Notification delivery")}</h3>
        <ChartLegend
          items={[
            {
              className: "statistics-legend-mark statistics-legend-mark--succeeded",
              label: tx(language, "Успешно", "Succeeded"),
            },
            {
              className: "statistics-legend-mark statistics-legend-mark--failed",
              label: tx(language, "Ошибки", "Failed"),
            },
          ]}
        />
      </div>
      <p className="sr-only" id={descriptionId}>
        {tx(
          language,
          "Столбчатый график успешных и неуспешных попыток доставки по периодам.",
          "Stacked bar chart of successful and failed delivery attempts in each period.",
        )}
      </p>
      <div
        className="statistics-chart__viewport"
        role="region"
        tabIndex={0}
        aria-label={tx(language, "Прокручиваемый график доставки", "Scrollable delivery chart")}
      >
        <svg
          className="statistics-chart"
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-labelledby={`${titleId} ${descriptionId}`}
        >
          <defs>
            <pattern
              id={failurePatternId}
              width="6"
              height="6"
              patternUnits="userSpaceOnUse"
              patternTransform="rotate(45)"
            >
              <rect className="statistics-chart__failure-fill" width="6" height="6" />
              <line className="statistics-chart__failure-hatch" x1="0" y1="0" x2="0" y2="6" />
            </pattern>
          </defs>
          {[0, 0.5, 1].map((ratio) => {
            const lineY = inset.top + plotHeight * ratio;
            const value = Math.round(maximum * (1 - ratio));
            return (
              <g key={ratio}>
                <line
                  className="statistics-chart__grid"
                  x1={inset.left}
                  x2={width - inset.right}
                  y1={lineY}
                  y2={lineY}
                />
                <text className="statistics-chart__axis" x={inset.left - 9} y={lineY + 4}>
                  {value}
                </text>
              </g>
            );
          })}
          {points.map((point, index) => {
            const total = totals[index] ?? 0;
            const successHeight = (point.deliveriesSucceeded / maximum) * plotHeight;
            const failedHeight = (point.deliveriesFailed / maximum) * plotHeight;
            const left = inset.left + index * slot + (slot - barWidth) / 2;
            const bottom = inset.top + plotHeight;
            return (
              <g key={point.startsAt}>
                <title>
                  {formatBucketLabel(language, point.startsAt, bucketSeconds)}:{" "}
                  {point.deliveriesSucceeded} {tx(language, "успешно", "succeeded")},{" "}
                  {point.deliveriesFailed} {tx(language, "ошибок", "failed")}, {total}{" "}
                  {tx(language, "всего", "total")}
                </title>
                <rect
                  className="statistics-chart__bar statistics-chart__bar--succeeded"
                  x={left}
                  y={bottom - successHeight}
                  width={barWidth}
                  height={successHeight}
                  rx="3"
                />
                <rect
                  className="statistics-chart__bar statistics-chart__bar--failed"
                  x={left}
                  y={bottom - successHeight - failedHeight}
                  width={barWidth}
                  height={failedHeight}
                  fill={`url(#${failurePatternId})`}
                  rx="3"
                />
                {showBucketAxisLabel(points, index, labelStride, language, bucketSeconds) && (
                  <text className="statistics-chart__label" x={left + barWidth / 2} y={height - 13}>
                    {formatBucketAxisLabel(language, point.startsAt, bucketSeconds)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
      <table className="sr-only">
        <caption>
          {tx(language, "Данные доставки уведомлений", "Notification delivery data")}
        </caption>
        <thead>
          <tr>
            <th>{tx(language, "Период", "Period")}</th>
            <th>{tx(language, "Успешно", "Succeeded")}</th>
            <th>{tx(language, "Ошибки", "Failed")}</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point) => (
            <tr key={point.startsAt}>
              <td>{formatBucketLabel(language, point.startsAt, bucketSeconds)}</td>
              <td>{point.deliveriesSucceeded}</td>
              <td>{point.deliveriesFailed}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}

function severityTone(severity: string) {
  if (severity === "critical") return "critical";
  if (severity === "warning") return "warning";
  if (severity === "info") return "info";
  return "unknown";
}

function severityLabel(language: StatisticsLanguage, severity: string) {
  const labels: Record<string, readonly [string, string]> = {
    critical: ["Критические", "Critical"],
    warning: ["Предупреждения", "Warning"],
    info: ["Информационные", "Info"],
    unknown: ["Неизвестные", "Unknown"],
  };
  const label = labels[severity];
  return label ? tx(language, label[0], label[1]) : severity.replaceAll("_", " ");
}

function SeverityBreakdown({
  snapshot,
  language,
}: {
  snapshot: StatisticsSnapshot;
  language: StatisticsLanguage;
}) {
  const items = snapshot.severities.filter((item) => item.count > 0);
  const total = items.reduce((sum, item) => sum + item.count, 0);
  const maximum = Math.max(1, ...items.map((item) => item.count));
  return (
    <article className="statistics-panel statistics-breakdown">
      <h3>{tx(language, "Инциденты по важности", "Incidents by severity")}</h3>
      {items.length === 0 ? (
        <p className="statistics-panel__empty">
          {tx(language, "Разбивка по важности не передана.", "No severity breakdown was returned.")}
        </p>
      ) : (
        <dl>
          {items.map((item) => (
            <div key={item.severity} data-tone={severityTone(item.severity)}>
              <dt>
                <span>{severityLabel(language, item.severity)}</span>
                <small>{total > 0 ? `${Math.round((item.count / total) * 100)}%` : "0%"}</small>
              </dt>
              <dd>
                <span className="statistics-meter" aria-hidden="true">
                  <i style={{ width: `${(item.count / maximum) * 100}%` }} />
                </span>
                <strong>{formatNumber(language, item.count)}</strong>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </article>
  );
}

function TopSources({
  snapshot,
  language,
}: {
  snapshot: StatisticsSnapshot;
  language: StatisticsLanguage;
}) {
  const items = [...snapshot.sources]
    .filter((item) => item.count > 0)
    .sort((left, right) => right.count - left.count || left.name.localeCompare(right.name))
    .slice(0, 5);
  return (
    <article className="statistics-panel statistics-ranking">
      <h3>{tx(language, "Основные источники", "Top sources")}</h3>
      {items.length === 0 ? (
        <p className="statistics-panel__empty">
          {tx(language, "Данных по источникам нет.", "No source data was returned.")}
        </p>
      ) : (
        <ol>
          {items.map((item) => (
            <li key={item.sourceId}>
              <span className="statistics-ranking__index" aria-hidden="true" />
              <span>
                <b>{item.name}</b>
                <small>{item.region ?? tx(language, "Регион не указан", "No region")}</small>
              </span>
              <strong>{formatNumber(language, item.count)}</strong>
            </li>
          ))}
        </ol>
      )}
    </article>
  );
}

function channelRate(channel: StatisticsChannel) {
  if (channel.successRate !== null) return channel.successRate;
  return channel.total > 0 ? (channel.succeeded / channel.total) * 100 : null;
}

function TopChannels({
  snapshot,
  language,
}: {
  snapshot: StatisticsSnapshot;
  language: StatisticsLanguage;
}) {
  const items = [...snapshot.channels]
    .filter((item) => item.total > 0)
    .sort((left, right) => right.total - left.total || left.name.localeCompare(right.name))
    .slice(0, 5);
  return (
    <article className="statistics-panel statistics-channels">
      <h3>{tx(language, "Каналы доставки", "Delivery channels")}</h3>
      {items.length === 0 ? (
        <p className="statistics-panel__empty">
          {tx(language, "Данных по каналам нет.", "No channel data was returned.")}
        </p>
      ) : (
        <ul>
          {items.map((item) => {
            const rate = channelRate(item);
            return (
              <li key={item.channelId}>
                <div>
                  <span>
                    <b>{item.name}</b>
                    <small>{item.kind.replaceAll("_", " ")}</small>
                  </span>
                  <strong>{formatPercent(language, rate)}</strong>
                </div>
                <span
                  className="statistics-channel-meter"
                  role="progressbar"
                  aria-label={`${item.name}: ${tx(language, "успешность доставки", "delivery success rate")}`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={rate ?? undefined}
                >
                  <i style={{ width: `${rate ?? 0}%` }} />
                </span>
                <small>
                  {formatNumber(language, item.succeeded)} / {formatNumber(language, item.total)}{" "}
                  {tx(language, "успешно", "succeeded")}
                  {item.failed > 0
                    ? ` · ${formatNumber(language, item.failed)} ${tx(language, "ошибок", "failed")}`
                    : ""}
                </small>
              </li>
            );
          })}
        </ul>
      )}
    </article>
  );
}

export function StatisticsOverview({
  snapshot,
  language,
  grafanaUrl = null,
  loading = false,
}: StatisticsOverviewProps) {
  const timeline = snapshot
    ? [...snapshot.timeline].sort(
        (left, right) => Date.parse(left.startsAt) - Date.parse(right.startsAt),
      )
    : [];
  return (
    <section className="statistics-overview" aria-labelledby="statistics-overview-title">
      <StatisticsHeader snapshot={snapshot} language={language} grafanaUrl={grafanaUrl} />
      {!snapshot && loading ? (
        <StatisticsLoading language={language} />
      ) : !snapshot ? (
        <StatisticsState language={language} kind="unavailable" />
      ) : isStatisticsSnapshotEmpty(snapshot) ? (
        <StatisticsState language={language} kind="empty" />
      ) : (
        <>
          <div className="statistics-kpi-grid">
            <StatisticsKpi
              label={tx(language, "Началось инцидентов", "Incidents started")}
              value={formatNumber(language, snapshot.totals.incidentsStarted)}
              note={tx(
                language,
                `Активно ${formatNumber(language, snapshot.totals.activeIncidents)} · критических ${formatNumber(language, snapshot.totals.activeCritical)}`,
                `${formatNumber(language, snapshot.totals.activeIncidents)} active · ${formatNumber(language, snapshot.totals.activeCritical)} critical`,
              )}
              tone={snapshot.totals.activeCritical > 0 ? "danger" : "accent"}
            />
            <StatisticsKpi
              label={tx(
                language,
                "Разрешено среди начавшихся",
                "Resolution rate for new incidents",
              )}
              value={formatPercent(language, snapshot.totals.resolutionRate)}
              note={tx(
                language,
                `${formatNumber(language, snapshot.totals.incidentsResolved)} разрешений за период · среднее для начавшихся ${formatStatisticsDuration(language, snapshot.totals.meanTimeToResolveSeconds)}`,
                `${formatNumber(language, snapshot.totals.incidentsResolved)} resolutions in period · mean for new incidents ${formatStatisticsDuration(language, snapshot.totals.meanTimeToResolveSeconds)}`,
              )}
              tone="success"
            />
            <StatisticsKpi
              label={tx(language, "Среднее до принятия", "Mean time to acknowledge")}
              value={formatStatisticsDuration(
                language,
                snapshot.totals.meanTimeToAcknowledgeSeconds,
              )}
              note={
                snapshot.totals.acknowledgementRate === null
                  ? tx(language, "Доля принятых не рассчитана", "Acknowledgement rate unavailable")
                  : tx(
                      language,
                      `${formatPercent(language, snapshot.totals.acknowledgementRate)} принято в работу`,
                      `${formatPercent(language, snapshot.totals.acknowledgementRate)} acknowledged`,
                    )
              }
              tone="warning"
            />
            <StatisticsKpi
              label={tx(language, "Успешность доставки", "Delivery success rate")}
              value={formatPercent(language, snapshot.totals.deliverySuccessRate)}
              note={tx(
                language,
                `${formatNumber(language, snapshot.totals.deliveriesSucceeded)} из ${formatNumber(language, snapshot.totals.deliveries)} · ошибок ${formatNumber(language, snapshot.totals.deliveriesFailed)}`,
                `${formatNumber(language, snapshot.totals.deliveriesSucceeded)} of ${formatNumber(language, snapshot.totals.deliveries)} · ${formatNumber(language, snapshot.totals.deliveriesFailed)} failed`,
              )}
              tone={snapshot.totals.deliveriesFailed > 0 ? "warning" : "success"}
            />
          </div>

          <div className="statistics-chart-grid">
            <IncidentTrendChart
              points={timeline}
              language={language}
              bucketSeconds={snapshot.bucketSeconds}
            />
            <DeliveryTrendChart
              points={timeline}
              language={language}
              bucketSeconds={snapshot.bucketSeconds}
            />
          </div>

          <div className="statistics-detail-grid">
            <SeverityBreakdown snapshot={snapshot} language={language} />
            <TopSources snapshot={snapshot} language={language} />
            <TopChannels snapshot={snapshot} language={language} />
          </div>
        </>
      )}
    </section>
  );
}

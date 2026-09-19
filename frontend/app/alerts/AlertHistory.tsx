import { StateHistoryPills } from "../state-history/StateHistoryPills";
import {
  type AlertHistorySnapshot,
  type AlertHistoryWindow,
  type AlertRule,
  historyForRule,
  historyForScope,
} from "./model";

type Language = "ru" | "en";

function tx(language: Language, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

function labels(language: Language) {
  return {
    healthy: tx(language, "Спокойно", "Quiet"),
    warning: "Pending",
    critical: "Firing",
    score: tx(language, "спокойного времени", "quiet time"),
  };
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
  return (
    <StateHistoryPills
      buckets={snapshot?.buckets ?? []}
      timeline={historyForRule(snapshot, rule)}
      window={window}
      language={language}
      subject={rule.name}
      labels={labels(language)}
      loading={loading}
      error={error}
      className="alert-history"
    />
  );
}

export function IncidentAlertHistory({
  incidentTitle,
  snapshot,
  window,
  language,
  loading,
  error,
}: {
  incidentTitle: string;
  snapshot: AlertHistorySnapshot | null;
  window: AlertHistoryWindow;
  language: Language;
  loading: boolean;
  error: string | null;
}) {
  return (
    <StateHistoryPills
      buckets={snapshot?.buckets ?? []}
      timeline={historyForScope(snapshot)}
      window={window}
      language={language}
      subject={incidentTitle}
      labels={labels(language)}
      loading={loading}
      error={error}
      className="state-history--standalone"
    />
  );
}

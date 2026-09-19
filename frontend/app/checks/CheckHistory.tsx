import { StateHistoryPills } from "../state-history/StateHistoryPills";
import { type CheckHistorySnapshot, type CheckHistoryWindow, historyForCheck } from "./model";

type Language = "ru" | "en";

function tx(language: Language, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

export function CheckHistory({
  checkId,
  snapshot,
  window,
  language,
  loading,
  error,
  compact = false,
}: {
  checkId: string;
  snapshot: CheckHistorySnapshot | null;
  window: CheckHistoryWindow;
  language: Language;
  loading: boolean;
  error: string | null;
  compact?: boolean;
}) {
  return (
    <StateHistoryPills
      buckets={snapshot?.buckets ?? []}
      timeline={historyForCheck(snapshot, checkId)}
      window={window}
      language={language}
      subject={checkId}
      labels={{
        healthy: tx(language, "Успешно", "Up"),
        warning: tx(language, "Деградация", "Degraded"),
        critical: tx(language, "Ошибка", "Down"),
        score: tx(language, "успешного времени", "successful time"),
      }}
      loading={loading}
      error={error}
      compact={compact}
      className={
        compact ? "check-history check-history--compact" : "state-history--standalone check-history"
      }
    />
  );
}

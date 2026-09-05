export type StatisticsFormatLanguage = "ru" | "en";

function tx(language: StatisticsFormatLanguage, russian: string, english: string) {
  return language === "ru" ? russian : english;
}

export function formatStatisticsDuration(
  language: StatisticsFormatLanguage,
  seconds: number | null,
) {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) return "—";
  const roundedSeconds = Math.round(seconds);
  if (roundedSeconds < 60) {
    return tx(language, `${roundedSeconds} сек.`, `${roundedSeconds} sec`);
  }
  const totalMinutes = Math.round(roundedSeconds / 60);
  if (totalMinutes < 60) {
    return tx(language, `${totalMinutes} мин.`, `${totalMinutes} min`);
  }
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes > 0
    ? tx(language, `${hours} ч ${minutes} мин`, `${hours}h ${minutes}m`)
    : tx(language, `${hours} ч`, `${hours}h`);
}

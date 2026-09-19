export type StateHistoryTone = "healthy" | "warning" | "critical";

export type StateHistoryBucket = {
  startsAt: string;
  endsAt: string;
};

export type StateHistoryTimeline = {
  periods: StateHistoryTone[][];
  healthyPercent: number | null;
  partial: boolean;
};

export type StateHistoryRun = {
  tone: StateHistoryTone;
  units: number;
};

const TONE_PRIORITY: Record<StateHistoryTone, number> = {
  healthy: 0,
  warning: 1,
  critical: 2,
};

export function mergeStateHistoryActivities(
  activities: StateHistoryTone[][][],
  partial: boolean,
): StateHistoryTimeline | null {
  const template = activities[0];
  if (!template?.length || template.some((period) => period.length === 0)) return null;
  const periods = template.map((period, periodIndex) =>
    period.map((_, sampleIndex) => {
      let selected: StateHistoryTone = "healthy";
      for (const activity of activities) {
        const tone = activity[periodIndex]?.[sampleIndex];
        if (tone && TONE_PRIORITY[tone] > TONE_PRIORITY[selected]) selected = tone;
      }
      return selected;
    }),
  );
  const samples = periods.flat();
  const healthy = samples.filter((tone) => tone === "healthy").length;
  return {
    periods,
    healthyPercent: samples.length > 0 ? (healthy / samples.length) * 100 : null,
    partial,
  };
}

export function stateHistoryRuns(period: StateHistoryTone[]): StateHistoryRun[] {
  const runs: StateHistoryRun[] = [];
  for (const tone of period) {
    const previous = runs.at(-1);
    if (previous?.tone === tone) previous.units += 1;
    else runs.push({ tone, units: 1 });
  }
  return runs;
}

export function mergeIncidentSummariesWithHistory<T extends { id: string; events: unknown[] }>(
  summaries: T[],
  current: T[],
): T[] {
  const currentById = new Map(current.map((incident) => [incident.id, incident]));
  return summaries.map((summary) => {
    const detailed = currentById.get(summary.id);
    if (summary.events.length || !detailed?.events.length) return summary;
    return { ...summary, events: detailed.events };
  });
}

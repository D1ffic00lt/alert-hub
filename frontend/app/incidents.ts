type IncidentSnapshot = {
  id: string;
  events: unknown[];
  checkIds?: string[];
  checksRelationState?: string;
};

export function mergeIncidentSummariesWithHistory<T extends IncidentSnapshot>(
  summaries: T[],
  current: T[],
): T[] {
  const currentById = new Map(current.map((incident) => [incident.id, incident]));
  return summaries.map((summary) => {
    const detailed = currentById.get(summary.id);
    let merged = summary;
    if (!summary.events.length && detailed?.events.length) {
      merged = { ...merged, events: detailed.events };
    }
    if (
      summary.checksRelationState === "available" &&
      detailed?.checksRelationState === "available"
    ) {
      merged = {
        ...merged,
        checkIds: [...new Set([...(summary.checkIds ?? []), ...(detailed.checkIds ?? [])])],
      };
    }
    return merged;
  });
}

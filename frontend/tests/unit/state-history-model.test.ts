import { describe, expect, it } from "vitest";

import { mergeStateHistoryActivities, stateHistoryRuns } from "../../app/state-history/model";

describe("State history model", () => {
  it("keeps repeated chronological runs instead of sorting or collapsing them", () => {
    expect(stateHistoryRuns(["critical", "critical", "warning", "healthy", "critical"])).toEqual([
      { tone: "critical", units: 2 },
      { tone: "warning", units: 1 },
      { tone: "healthy", units: 1 },
      { tone: "critical", units: 1 },
    ]);
  });

  it("merges HA samples by severity without adding a fourth state", () => {
    const timeline = mergeStateHistoryActivities(
      [[["healthy", "warning", "healthy"]], [["healthy", "healthy", "critical"]]],
      false,
    );

    expect(timeline?.periods).toEqual([["healthy", "warning", "critical"]]);
    expect(timeline?.healthyPercent).toBeCloseTo(100 / 3);
    expect(timeline?.partial).toBe(false);
  });
});

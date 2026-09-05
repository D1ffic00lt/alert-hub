import { describe, expect, it } from "vitest";
import { mergeIncidentSummariesWithHistory } from "../../app/incidents";

describe("incident snapshot merging", () => {
  it("preserves a loaded timeline when a background list refresh returns summaries", () => {
    const history = [
      { id: "event-1", type: "firing" },
      { id: "event-2", type: "acknowledged" },
    ];

    const merged = mergeIncidentSummariesWithHistory(
      [{ id: "incident-1", status: "acknowledged", events: [] }],
      [{ id: "incident-1", status: "open", events: history }],
    );

    expect(merged).toEqual([{ id: "incident-1", status: "acknowledged", events: history }]);
  });

  it("keeps an incoming detailed timeline authoritative", () => {
    const incomingHistory = [{ id: "event-2", type: "resolved" }];

    const merged = mergeIncidentSummariesWithHistory(
      [{ id: "incident-1", events: incomingHistory }],
      [{ id: "incident-1", events: [{ id: "event-1", type: "firing" }] }],
    );

    expect(merged[0]?.events).toBe(incomingHistory);
  });

  it("preserves detail-only related Checks when list polling returns a shorter summary", () => {
    const history = [{ id: "event-1", type: "firing" }];
    const [merged] = mergeIncidentSummariesWithHistory(
      [
        {
          id: "incident-1",
          events: [],
          checkIds: ["label-check"],
          checksRelationState: "available",
        },
      ],
      [
        {
          id: "incident-1",
          events: history,
          checkIds: ["label-check", "timeline-check"],
          checksRelationState: "available",
        },
      ],
    );

    expect(merged).toMatchObject({
      events: history,
      checkIds: ["label-check", "timeline-check"],
      checksRelationState: "available",
    });
  });

  it("does not retain related Checks when the incoming state disables relationships", () => {
    const [merged] = mergeIncidentSummariesWithHistory(
      [
        {
          id: "incident-1",
          events: [],
          checkIds: [],
          checksRelationState: "disabled",
        },
      ],
      [
        {
          id: "incident-1",
          events: [],
          checkIds: ["previous-check"],
          checksRelationState: "available",
        },
      ],
    );

    expect(merged).toMatchObject({ checkIds: [], checksRelationState: "disabled" });
  });
});

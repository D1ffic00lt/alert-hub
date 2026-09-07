import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createRefreshBurstCoalescer,
  incidentListPath,
  mergeIncidentSummariesWithHistory,
  normalizeIncidentSearch,
  sseReconnectDelay,
} from "../../app/incidents";

afterEach(() => {
  vi.useRealTimers();
});

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

  it("keeps detail-only fields when a compact summary refreshes mutable list fields", () => {
    const [merged] = mergeIncidentSummariesWithHistory(
      [
        {
          id: "incident-1",
          title: "Fresh title",
          status: "resolved",
          summaryOnly: true,
          description: "",
          labels: {},
          annotations: {},
          events: [],
        },
      ],
      [
        {
          id: "incident-1",
          title: "Old title",
          status: "open",
          summaryOnly: false,
          description: "Detailed description",
          labels: { service: "api" },
          annotations: { runbook: "safe" },
          events: [{ id: "event-1" }],
        },
      ],
    );

    expect(merged).toMatchObject({
      title: "Fresh title",
      status: "resolved",
      summaryOnly: false,
      description: "Detailed description",
      labels: { service: "api" },
      annotations: { runbook: "safe" },
      events: [{ id: "event-1" }],
    });
  });
});

describe("incident list request", () => {
  it("treats whitespace-only and trailing-whitespace edits as the same search", () => {
    expect(normalizeIncidentSearch("   ")).toBe("");
    expect(normalizeIncidentSearch(" active api ")).toBe("active api");
    expect(normalizeIncidentSearch("active api   ")).toBe(normalizeIncidentSearch("active api"));
  });

  it("encodes server-side filters and keeps wildcard input literal at the HTTP boundary", () => {
    const path = incidentListPath({
      status: "active",
      severity: "critical",
      query: " api % ",
      limit: 50,
      offset: 100,
    });

    expect(path).toBe(
      "/incidents?limit=50&offset=100&view=compact&status=active&severity=critical&q=api+%25",
    );
  });
});

describe("SSE refresh burst coalescing", () => {
  it("backs reconnects off with bounded jitter", () => {
    expect(sseReconnectDelay(0, () => 0)).toBe(800);
    expect(sseReconnectDelay(2, () => 0.5)).toBe(4_000);
    expect(sseReconnectDelay(20, () => 1)).toBe(30_000);
  });

  it("turns a burst into one refresh", async () => {
    vi.useFakeTimers();
    const run = vi.fn(async () => undefined);
    const coalescer = createRefreshBurstCoalescer(run, 250);

    coalescer.request();
    coalescer.request();
    coalescer.request();
    await vi.advanceTimersByTimeAsync(249);
    expect(run).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("keeps exactly one trailing refresh when events arrive during an active refresh", async () => {
    vi.useFakeTimers();
    let finishFirst: (() => void) | undefined;
    const run = vi
      .fn<() => Promise<void>>()
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            finishFirst = resolve;
          }),
      )
      .mockResolvedValue(undefined);
    const coalescer = createRefreshBurstCoalescer(run, 250);

    coalescer.request();
    await vi.advanceTimersByTimeAsync(250);
    expect(run).toHaveBeenCalledTimes(1);
    coalescer.request();
    coalescer.request();
    finishFirst?.();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(250);
    expect(run).toHaveBeenCalledTimes(2);
  });
});

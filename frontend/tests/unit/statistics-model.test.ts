import { describe, expect, test } from "vitest";

import {
  createDemoStatisticsSnapshot,
  EMPTY_STATISTICS,
  emptyStatisticsSnapshot,
  isStatisticsSnapshotEmpty,
  normalizeStatisticsSnapshot,
} from "../../app/statistics/model";

function validPayload() {
  return {
    window: "7d",
    generated_at: "2026-09-06T00:00:00Z",
    starts_at: "2026-08-30T00:00:00Z",
    ends_at: "2026-09-06T00:00:00Z",
    bucket_seconds: 21_600,
    totals: {
      incidents_started: 12,
      incidents_resolved: 10,
      active_incidents: 3,
      active_critical: 1,
      acknowledgement_rate: 91.7,
      resolution_rate: 83.3,
      mean_time_to_acknowledge_seconds: 420,
      mean_time_to_resolve_seconds: 3_600,
      deliveries: 100,
      deliveries_succeeded: 96,
      deliveries_failed: 3,
      delivery_success_rate: 96,
    },
    timeline: [
      {
        starts_at: "2026-08-30T06:00:00Z",
        incidents_started: 7,
        incidents_resolved: 4,
        deliveries_succeeded: 51,
        deliveries_failed: 2,
      },
      {
        starts_at: "2026-08-30T00:00:00Z",
        incidents_started: 5,
        incidents_resolved: 6,
        deliveries_succeeded: 45,
        deliveries_failed: 1,
      },
    ],
    severities: [
      { severity: "warning", count: 7 },
      { severity: "critical", count: 3 },
      { severity: "info", count: 2 },
    ],
    sources: [
      { source_id: "source-b", name: "Source B", region: null, count: 4 },
      { source_id: "source-a", name: "Source A", region: "EU", count: 8 },
    ],
    channels: [
      {
        channel_id: "telegram",
        name: "Telegram",
        kind: "telegram",
        total: 40,
        succeeded: 39,
        failed: 1,
        success_rate: 97.5,
      },
      {
        channel_id: "push",
        name: "Web Push",
        kind: "web_push",
        total: 60,
        succeeded: 57,
        failed: 2,
        success_rate: 95,
      },
    ],
  };
}

describe("normalizeStatisticsSnapshot", () => {
  test("normalizes the wire contract and gives collections deterministic ordering", () => {
    const snapshot = normalizeStatisticsSnapshot(validPayload());

    expect(snapshot).not.toBeNull();
    expect(snapshot).toMatchObject({
      window: "7d",
      generatedAt: "2026-09-06T00:00:00.000Z",
      startsAt: "2026-08-30T00:00:00.000Z",
      endsAt: "2026-09-06T00:00:00.000Z",
      bucketSeconds: 21_600,
      totals: {
        incidentsStarted: 12,
        incidentsResolved: 10,
        activeIncidents: 3,
        activeCritical: 1,
        acknowledgementRate: 91.7,
        resolutionRate: 83.3,
        meanTimeToAcknowledgeSeconds: 420,
        meanTimeToResolveSeconds: 3_600,
        deliveries: 100,
        deliveriesSucceeded: 96,
        deliveriesFailed: 3,
        deliverySuccessRate: 96,
      },
    });
    expect(snapshot?.timeline.map((point) => point.incidentsStarted)).toEqual([5, 7]);
    expect(snapshot?.severities.map((item) => item.severity)).toEqual([
      "critical",
      "warning",
      "info",
    ]);
    expect(snapshot?.sources.map((item) => item.sourceId)).toEqual(["source-a", "source-b"]);
    expect(snapshot?.sources[1]?.region).toBeNull();
    expect(snapshot?.channels.map((item) => item.channelId)).toEqual(["push", "telegram"]);
  });

  test("accepts a statistics envelope and finite numeric strings", () => {
    const payload = validPayload();
    payload.bucket_seconds = "21600" as unknown as number;
    payload.totals.incidents_started = "12" as unknown as number;

    const snapshot = normalizeStatisticsSnapshot({ statistics: payload });

    expect(snapshot?.bucketSeconds).toBe(21_600);
    expect(snapshot?.totals.incidentsStarted).toBe(12);
  });

  test.each([
    null,
    [],
    {},
    { ...validPayload(), window: "week" },
    { ...validPayload(), generated_at: "not-a-date" },
    {
      ...validPayload(),
      starts_at: "2026-09-06T00:00:00Z",
      ends_at: "2026-08-30T00:00:00Z",
    },
    { ...validPayload(), bucket_seconds: 0 },
    { ...validPayload(), bucket_seconds: 700_000 },
    {
      ...validPayload(),
      totals: { ...validPayload().totals, incidents_started: -1 },
    },
    {
      ...validPayload(),
      totals: { ...validPayload().totals, active_incidents: 1, active_critical: 2 },
    },
    {
      ...validPayload(),
      totals: {
        ...validPayload().totals,
        deliveries: 10,
        deliveries_succeeded: 8,
        deliveries_failed: 3,
      },
    },
    {
      ...validPayload(),
      totals: { ...validPayload().totals, delivery_success_rate: 101 },
    },
    {
      ...validPayload(),
      totals: { ...validPayload().totals, mean_time_to_resolve_seconds: -1 },
    },
  ])("rejects an invalid required snapshot %#", (payload) => {
    expect(normalizeStatisticsSnapshot(payload)).toBeNull();
  });

  test("keeps a valid snapshot while dropping malformed optional rows", () => {
    const payload = validPayload();
    payload.timeline.push(
      {
        starts_at: "outside-the-window",
        incidents_started: 1,
        incidents_resolved: 1,
        deliveries_succeeded: 1,
        deliveries_failed: 0,
      },
      {
        starts_at: "2026-09-06T00:00:00Z",
        incidents_started: 1,
        incidents_resolved: 1,
        deliveries_succeeded: 1,
        deliveries_failed: 0,
      },
    );
    payload.severities.push({ severity: "critical", count: 1 });
    payload.sources.push({ source_id: "", name: "No id", region: "EU", count: 50 });
    payload.channels.push({
      channel_id: "broken",
      name: "Broken",
      kind: "smtp",
      total: 2,
      succeeded: 2,
      failed: 1,
      success_rate: 100,
    });

    const snapshot = normalizeStatisticsSnapshot(payload);

    expect(snapshot?.timeline).toHaveLength(2);
    expect(snapshot?.severities[0]).toEqual({ severity: "critical", count: 4 });
    expect(snapshot?.sources).toHaveLength(2);
    expect(snapshot?.channels).toHaveLength(2);
  });

  test("preserves explicit null rates and durations instead of fabricating values", () => {
    const payload = validPayload();
    payload.totals.acknowledgement_rate = null as unknown as number;
    payload.totals.resolution_rate = null as unknown as number;
    payload.totals.mean_time_to_acknowledge_seconds = null as unknown as number;
    payload.totals.mean_time_to_resolve_seconds = null as unknown as number;
    payload.totals.delivery_success_rate = null as unknown as number;
    payload.channels[0]!.success_rate = null as unknown as number;

    const snapshot = normalizeStatisticsSnapshot(payload);

    expect(snapshot?.totals).toMatchObject({
      acknowledgementRate: null,
      resolutionRate: null,
      meanTimeToAcknowledgeSeconds: null,
      meanTimeToResolveSeconds: null,
      deliverySuccessRate: null,
    });
    expect(
      snapshot?.channels.find((item) => item.channelId === "telegram")?.successRate,
    ).toBeNull();
  });

  test("rejects collections larger than the bounded API contract", () => {
    const payload = validPayload();
    expect(
      normalizeStatisticsSnapshot({
        ...payload,
        timeline: Array.from({ length: 31 }, () => payload.timeline[0]),
      }),
    ).toBeNull();
    expect(
      normalizeStatisticsSnapshot({
        ...payload,
        severities: Array.from({ length: 5 }, () => payload.severities[0]),
      }),
    ).toBeNull();
    expect(
      normalizeStatisticsSnapshot({
        ...payload,
        sources: Array.from({ length: 6 }, () => payload.sources[0]),
      }),
    ).toBeNull();
    expect(
      normalizeStatisticsSnapshot({
        ...payload,
        channels: Array.from({ length: 6 }, () => payload.channels[0]),
      }),
    ).toBeNull();
  });
});

describe("statistics fixtures and empty state", () => {
  test("exposes an explicit seven-day empty snapshot", () => {
    expect(EMPTY_STATISTICS).toEqual(emptyStatisticsSnapshot("7d"));
    expect(EMPTY_STATISTICS.bucketSeconds).toBe(21_600);
    expect(isStatisticsSnapshotEmpty(EMPTY_STATISTICS)).toBe(true);
  });

  test("provides a deterministic internally consistent demo snapshot", () => {
    const snapshot = createDemoStatisticsSnapshot();
    const timelineTotals = snapshot.timeline.reduce(
      (totals, point) => ({
        incidentsStarted: totals.incidentsStarted + point.incidentsStarted,
        incidentsResolved: totals.incidentsResolved + point.incidentsResolved,
        deliveriesSucceeded: totals.deliveriesSucceeded + point.deliveriesSucceeded,
        deliveriesFailed: totals.deliveriesFailed + point.deliveriesFailed,
      }),
      {
        incidentsStarted: 0,
        incidentsResolved: 0,
        deliveriesSucceeded: 0,
        deliveriesFailed: 0,
      },
    );

    expect(snapshot.timeline).toHaveLength(28);
    expect(snapshot.generatedAt).toBe(snapshot.endsAt);
    expect(timelineTotals).toEqual({
      incidentsStarted: snapshot.totals.incidentsStarted,
      incidentsResolved: snapshot.totals.incidentsResolved,
      deliveriesSucceeded: snapshot.totals.deliveriesSucceeded,
      deliveriesFailed: snapshot.totals.deliveriesFailed,
    });
    expect(snapshot.severities.reduce((sum, item) => sum + item.count, 0)).toBe(
      snapshot.totals.incidentsStarted,
    );
    expect(snapshot.sources.reduce((sum, item) => sum + item.count, 0)).toBe(
      snapshot.totals.incidentsStarted,
    );
    expect(snapshot.channels.reduce((sum, item) => sum + item.total, 0)).toBe(
      snapshot.totals.deliveries,
    );
    expect(isStatisticsSnapshotEmpty(snapshot)).toBe(false);
  });
});

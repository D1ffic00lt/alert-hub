import { describe, expect, it } from "vitest";

import {
  buildAlertRulesPath,
  mergeAvailability,
  normalizeAlertRules,
  normalizeAvailability,
} from "../../app/alerts/model";

describe("Alerts API model", () => {
  it("builds only supported server-side filters", () => {
    expect(
      buildAlertRulesPath({
        datasourceId: "prom-1",
        state: "firing",
        query: " API Down ",
        page: 2,
        pageSize: 25,
      }),
    ).toBe("/alert-rules?page=2&page_size=25&datasource_id=prom-1&state=firing&q=API+Down");
  });

  it("keeps rule, instance, incident, and error totals separate", () => {
    const snapshot = normalizeAlertRules({
      data_state: "partial",
      totals: {
        rules: 12,
        firing_instances: 3,
        pending_instances: 2,
        unhealthy_rules: 1,
        related_incidents: 7,
      },
      rules: [
        {
          id: "rule-1",
          datasource_id: "prom-1",
          datasource_name: "Primary",
          name: "ApiDown",
          state: "firing",
          health: "ok",
          firing_instances: 3,
          pending_instances: 0,
          related_incidents: 2,
          incidents_href: "/incidents?q=ApiDown",
        },
      ],
      pagination: { page: 1, page_size: 25, total_items: 1, total_pages: 1 },
    });

    expect(snapshot.dataState).toBe("partial");
    expect(snapshot.totals).toEqual({
      rules: 12,
      firingInstances: 3,
      pendingInstances: 2,
      unhealthyRules: 1,
      relatedIncidents: 7,
    });
    expect(snapshot.rules[0]).toMatchObject({
      name: "ApiDown",
      firingInstances: 3,
      relatedIncidents: 2,
    });
  });

  it("merges availability windows without replacing unknown values with zero", () => {
    const windows = (["24h", "7d", "30d"] as const).map((window, index) =>
      normalizeAvailability(
        {
          data_state: "ok",
          targets: [
            {
              datasource_id: "prom-1",
              datasource_name: "Primary",
              source: "ru",
              target: "api",
              observed_availability_percent: index === 2 ? null : 99.9 - index,
              samples_count: index === 2 ? null : 100,
              last_sample_at: index === 2 ? null : "2026-09-07T00:00:00Z",
              data_state: index === 1 ? "stale" : index === 2 ? "unknown" : "ok",
            },
          ],
        },
        window,
      ),
    );

    const rows = mergeAvailability(windows);
    expect(rows).toHaveLength(1);
    expect(rows[0].windows["24h"]?.observedAvailabilityPercent).toBe(99.9);
    expect(rows[0].windows["7d"]?.dataState).toBe("stale");
    expect(rows[0].windows["30d"]?.observedAvailabilityPercent).toBeNull();
  });
});

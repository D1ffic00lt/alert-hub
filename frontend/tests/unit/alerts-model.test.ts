import { describe, expect, it } from "vitest";

import {
  UNCATEGORIZED_FILTER,
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
        category: "infrastructure",
        state: "firing",
        query: " API Down ",
        page: 2,
        pageSize: 25,
      }),
    ).toBe(
      "/alert-rules?page=2&page_size=25&datasource_id=prom-1&category=infrastructure&state=firing&q=API+Down",
    );
    expect(
      buildAlertRulesPath({
        datasourceId: "",
        category: UNCATEGORIZED_FILTER,
        state: "all",
        query: "",
        page: 1,
        pageSize: 25,
      }),
    ).toBe("/alert-rules?page=1&page_size=25&uncategorized=true");
  });

  it("normalizes unique rule totals and preserves per-datasource replicas", () => {
    const snapshot = normalizeAlertRules({
      data_state: "partial",
      last_successful_refresh: "2026-09-07T00:00:00Z",
      totals: {
        rules: 12,
        firing_rules: 3,
        pending_rules: 2,
        error_rules: 1,
        datasources: 3,
        related_incidents: 7,
      },
      filtered_rules: 1,
      categories: ["infrastructure"],
      has_uncategorized: true,
      rules: [
        {
          id: "rule-1",
          name: "ApiDown",
          category: "infrastructure",
          state: "firing",
          firing_instances: 3,
          pending_instances: 0,
          has_error: false,
          datasource_count: 2,
          related_incidents: 2,
          replicas: [
            {
              id: "replica-1",
              datasource_id: "prom-1",
              datasource_name: "Primary",
              name: "ApiDown",
              state: "firing",
              health: "ok",
              firing_instances: 3,
              pending_instances: 0,
              labels: { alert_category: "infrastructure" },
              related_incidents: 2,
              incidents_href: "/incidents?alertname=ApiDown&datasource_id=prom-1",
            },
          ],
        },
      ],
      pagination: { page: 1, page_size: 25, total_items: 1, total_pages: 1 },
    });

    expect(snapshot.dataState).toBe("partial");
    expect(snapshot.totals).toEqual({
      rules: 12,
      firingRules: 3,
      pendingRules: 2,
      errorRules: 1,
      datasources: 3,
      relatedIncidents: 7,
    });
    expect(snapshot.filteredRules).toBe(1);
    expect(snapshot.categories).toEqual(["infrastructure"]);
    expect(snapshot.hasUncategorized).toBe(true);
    expect(snapshot.rules[0]).toMatchObject({
      name: "ApiDown",
      firingInstances: 3,
      datasourceCount: 2,
      relatedIncidents: 2,
    });
    expect(snapshot.rules[0].replicas[0]).toMatchObject({
      datasourceId: "prom-1",
      firingInstances: 3,
      labels: { alert_category: "infrastructure" },
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

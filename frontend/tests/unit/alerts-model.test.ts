import { describe, expect, it } from "vitest";

import {
  UNCATEGORIZED_FILTER,
  buildAlertHistoryPath,
  buildAlertRulesPath,
  historyForRule,
  historyForScope,
  mergeAvailability,
  normalizeAlertHistory,
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

  it("normalizes chronological alert activity and aggregates replicas conservatively", () => {
    expect(buildAlertHistoryPath("7d")).toBe("/alert-history?window=7d");
    expect(buildAlertHistoryPath("30d", { incidentId: "incident / one" })).toBe(
      "/alert-history?window=30d&incident_id=incident+%2F+one",
    );
    const snapshot = normalizeAlertHistory(
      {
        data_state: "partial",
        generated_at: "2026-09-07T00:00:00Z",
        window: "24h",
        bucket_seconds: 3_600,
        sample_seconds: 900,
        samples_per_bucket: 4,
        buckets: [
          { starts_at: "2026-09-06T21:00:00Z", ends_at: "2026-09-06T22:00:00Z" },
          { starts_at: "2026-09-06T22:00:00Z", ends_at: "2026-09-06T23:00:00Z" },
          { starts_at: "2026-09-06T23:00:00Z", ends_at: "2026-09-07T00:00:00Z" },
        ],
        datasources: [
          { id: "prom-1", name: "Primary" },
          { id: "prom-2", name: "Secondary" },
        ],
        series: [
          {
            datasource_id: "prom-1",
            datasource_name: "Primary",
            name: "ApiDown",
            category: "infrastructure",
            activity: [
              ["inactive", "firing", "pending", "inactive"],
              ["inactive", "inactive", "inactive", "inactive"],
              ["firing", "firing", "pending", "inactive"],
            ],
          },
          {
            datasource_id: "prom-2",
            datasource_name: "Secondary",
            name: "ApiDown",
            category: "infrastructure",
            activity: [
              ["inactive", "inactive", "pending", "inactive"],
              ["inactive", "pending", "inactive", "inactive"],
              ["inactive", "inactive", "inactive", "inactive"],
            ],
          },
          {
            datasource_id: "prom-2",
            datasource_name: "Secondary",
            name: "Broken",
            category: "infrastructure",
            activity: [["broken"]],
          },
        ],
        errors: [
          {
            datasource_id: "prom-4",
            datasource_name: "Unavailable",
            code: "timeout",
            detail: "Prometheus request timed out",
          },
        ],
      },
      "24h",
    );
    const rules = normalizeAlertRules({
      data_state: "ok",
      totals: {},
      rules: [
        {
          id: "api-down",
          name: "ApiDown",
          category: "infrastructure",
          state: "firing",
          replicas: [
            { id: "one", datasource_id: "prom-1", name: "ApiDown", state: "firing" },
            { id: "two", datasource_id: "prom-2", name: "ApiDown", state: "pending" },
            { id: "three", datasource_id: "prom-3", name: "ApiDown", state: "inactive" },
          ],
        },
      ],
      pagination: {},
    });

    expect(snapshot.series).toHaveLength(2);
    expect(historyForRule(snapshot, rules.rules[0])).toEqual({
      periods: [
        ["healthy", "critical", "warning", "healthy"],
        ["healthy", "warning", "healthy", "healthy"],
        ["critical", "critical", "warning", "healthy"],
      ],
      healthyPercent: 50,
      partial: true,
    });
    expect(historyForScope(snapshot)?.periods[0]).toEqual([
      "healthy",
      "critical",
      "warning",
      "healthy",
    ]);

    expect(historyForScope({ ...snapshot, series: [] })).toBeNull();

    const neverFired = historyForRule(snapshot, {
      ...rules.rules[0],
      name: "NeverFired",
      replicas: [{ ...rules.rules[0].replicas[0], name: "NeverFired" }],
    });
    expect(neverFired).toMatchObject({
      healthyPercent: 100,
      partial: true,
    });
  });
});

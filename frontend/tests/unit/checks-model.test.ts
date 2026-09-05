import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildChecksQuery,
  groupChecks,
  hasActiveCheckFilters,
  normalizeCheckDetail,
  normalizeCheckListItem,
  normalizeChecksList,
  normalizeChecksSummary,
  problemChecks,
  resultMatrix,
  safeExternalUrl,
  safeInternalHref,
} from "../../app/checks/model";

afterEach(() => vi.unstubAllGlobals());

describe("Checks API model", () => {
  it("keeps a minimal Check protocol-neutral and preserves absent optionals as null", () => {
    const check = normalizeCheckListItem({
      check_id: "minimum",
      name: "Minimum",
      status: "up",
      sources_total: 1,
      sources_up: 1,
      latency_seconds: null,
      active_alerts: null,
    });

    expect(check).toMatchObject({
      checkId: "minimum",
      group: null,
      target: null,
      status: "up",
      latencySeconds: null,
      activeAlerts: null,
      scenarios: [],
      sources: [],
      diagnosticCodes: [],
    });
  });

  it("normalizes all five summary states and common snapshot metadata", () => {
    const response = normalizeChecksSummary({
      enabled: true,
      data_state: "ready",
      snapshot_id: "snapshot-42",
      fetched_at: "2026-09-05T12:00:00Z",
      evaluated_at: "2026-09-05T12:00:01Z",
      cache_expires_at: "2026-09-05T12:00:05Z",
      warning_codes: ["optional_metric_unavailable"],
      total: 15,
      up: 5,
      degraded: 4,
      down: 3,
      stale: 2,
      unknown: 1,
      problem_checks: [{ check_id: "broken", name: "Broken", status: "down" }],
    });

    expect(response.summary).toEqual({
      total: 15,
      up: 5,
      degraded: 4,
      down: 3,
      stale: 2,
      unknown: 1,
    });
    expect(response.meta).toMatchObject({
      enabled: true,
      dataState: "ready",
      snapshotId: "snapshot-42",
      warningCodes: ["optional_metric_unavailable"],
    });
    expect(response.problemChecks.map((item) => item.checkId)).toEqual(["broken"]);
  });

  it("does not turn unavailable data into an empty trustworthy summary", () => {
    const response = normalizeChecksSummary({
      enabled: true,
      data_state: "unavailable",
      error_code: "prometheus_unavailable",
      total: 0,
      up: 0,
    });

    expect(response.meta).toMatchObject({
      enabled: true,
      dataState: "unavailable",
      code: "prometheus_unavailable",
    });
    expect(response.summary).toBeNull();
    expect(response.problemChecks).toEqual([]);
  });

  it("normalizes compact and matrix detail without inventing optional metrics", () => {
    const response = normalizeCheckDetail({
      enabled: true,
      data_state: "ready",
      check: {
        check_id: "checkout",
        name: "Checkout",
        group: "customer-paths",
        target: null,
        status: "degraded",
        status_reason: "mixed_results",
        sources_total: 2,
        sources_up: 1,
        active_alerts: 1,
        latency_seconds: 0,
        results: [
          {
            source: "eu",
            scenario: "purchase",
            variant: null,
            target: null,
            status: "up",
            success: true,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: 0,
            ttfb_seconds: null,
            canaries: [],
            assertions: [],
            diagnostic_codes: ["conflicting_duration"],
          },
          {
            source: "us",
            scenario: "purchase",
            variant: "guest",
            target: null,
            status: "down",
            success: false,
            last_run_at: "2026-09-05T12:00:00Z",
            duration_seconds: null,
            ttfb_seconds: 0.2,
            canaries: [{ canary: "control", success: true, status_reason: null }],
            assertions: [{ key: "egress_match", success: false, status_reason: "mismatch" }],
          },
        ],
        parts: [
          {
            scenario: "purchase",
            variant: "guest",
            status: "down",
            status_reason: "confirmed_failure",
            sources_total: 2,
            sources_up: 1,
            stale_results: 0,
            data_incomplete: false,
          },
        ],
        related_alerts: [
          {
            id: "alert-1",
            title: "Checkout failed",
            severity: "critical",
            status: "firing",
            starts_at: "2026-09-05T11:58:00Z",
            href: "/incidents/inc-1",
          },
        ],
        incidents: [
          { id: "inc-1", title: "Checkout incident", status: "open", href: "/incidents/inc-1" },
        ],
        alerts_available: true,
        related_alerts_total: 2,
        incidents_total: 3,
        relations_incomplete: true,
        relation_warning_codes: ["related_alerts_truncated", "related_incidents_truncated"],
        grafana_url: "https://grafana.example.test/d/checks?var-check_id=checkout",
      },
    });

    expect(response.check?.latencySeconds).toBe(0);
    expect(response.check?.results[0]).toMatchObject({
      source: "eu",
      scenario: "purchase",
      variant: null,
      target: null,
      durationSeconds: 0,
      ttfbSeconds: null,
      diagnosticCodes: ["conflicting_duration"],
    });
    expect(response.check?.results[1].assertions[0]).toEqual({
      key: "egress_match",
      success: false,
      statusReason: "mismatch",
    });
    expect(response.check?.parts[0]).toMatchObject({ status: "down", sourcesTotal: 2 });
    expect(response.check?.alerts[0]).toMatchObject({
      name: "Checkout failed",
      href: "/incidents/inc-1",
    });
    expect(response.check).toMatchObject({
      alertLinksAvailable: true,
      relatedAlertsTotal: 2,
      incidentsTotal: 3,
      relationsIncomplete: true,
      relationWarningCodes: ["related_alerts_truncated", "related_incidents_truncated"],
    });
    expect(response.check?.grafanaUrl).toContain("var-check_id=checkout");

    const matrix = resultMatrix(response.check!);
    expect(matrix.sources).toEqual(["eu", "us"]);
    expect(matrix.scenarios).toEqual(["purchase"]);
    expect(matrix.cells.get("us\u0000purchase")?.[0].variant).toBe("guest");
  });

  it("orders problem Checks by severity and then stable public identifier", () => {
    const list = normalizeChecksList({
      enabled: true,
      data_state: "ready",
      items: [
        { check_id: "z-stale", status: "stale" },
        { check_id: "b-down", status: "down" },
        { check_id: "healthy", status: "up" },
        { check_id: "a-down", status: "down" },
        { check_id: "degraded", status: "degraded" },
        { check_id: "unknown", status: "unknown" },
      ],
    });

    expect(problemChecks(list.items).map((item) => item.checkId)).toEqual([
      "a-down",
      "b-down",
      "degraded",
      "unknown",
      "z-stale",
    ]);
    expect(groupChecks(list.items).at(-1)?.label).toBeNull();
  });

  it("builds bounded server-side filter and pagination parameters", () => {
    const query = buildChecksQuery({
      status: "degraded",
      group: " backend ",
      source: "eu",
      target: "",
      scenario: "purchase",
      search: "checkout api",
      limit: 50,
      offset: 100,
    });
    const params = new URLSearchParams(query);

    expect(Object.fromEntries(params)).toEqual({
      status: "degraded",
      group: "backend",
      source: "eu",
      scenario: "purchase",
      search: "checkout api",
      limit: "50",
      offset: "100",
    });
    expect(
      hasActiveCheckFilters({
        status: "all",
        group: "",
        source: "",
        target: "",
        scenario: "",
        search: "  checkout api ",
        limit: 50,
        offset: 0,
      }),
    ).toBe(true);
  });

  it("rejects non-incident internal links without a browser origin", () => {
    vi.stubGlobal("window", undefined);

    expect(safeInternalHref("/incidents/inc-1")).toBe("/incidents/inc-1");
    expect(safeInternalHref("/checks/secret")).toBeNull();
    expect(safeInternalHref("/settings")).toBeNull();
    expect(safeInternalHref("/incidents/../settings")).toBeNull();
    expect(safeInternalHref("//evil.example/incidents/inc-1")).toBeNull();
  });

  it("rejects unsafe Grafana URLs", () => {
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
    expect(safeExternalUrl("https://user:secret@grafana.example.test/d/checks")).toBeNull();
    expect(safeExternalUrl("https://grafana.example.test/d/checks")).toBe(
      "https://grafana.example.test/d/checks",
    );
  });
});

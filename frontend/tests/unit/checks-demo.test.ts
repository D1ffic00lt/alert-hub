import { describe, expect, it } from "vitest";

import { createDemoChecksRequest } from "../../app/checks/demo";
import {
  normalizeCheckDetail,
  normalizeChecksList,
  normalizeChecksSummary,
} from "../../app/checks/model";

async function demoRequest(path: string) {
  return createDemoChecksRequest("ru")(path, new AbortController().signal);
}

describe("Checks demo data", () => {
  it("covers every operational status with a populated summary", async () => {
    const response = await demoRequest("/checks/summary");
    const normalized = normalizeChecksSummary(response.payload);

    expect(response.status).toBe(200);
    expect(normalized.meta.enabled).toBe(true);
    expect(normalized.meta.dataState).toBe("ready");
    expect(normalized.summary).toEqual({
      total: 6,
      up: 2,
      degraded: 1,
      down: 1,
      stale: 1,
      unknown: 1,
    });
    expect(normalized.problemChecks.map((check) => check.status)).toEqual([
      "down",
      "degraded",
      "unknown",
      "stale",
    ]);
  });

  it("supports list filters, search, and pagination without an API", async () => {
    const down = normalizeChecksList((await demoRequest("/checks?status=down")).payload);
    const search = normalizeChecksList(
      (await demoRequest("/checks?search=VLESS&limit=1&offset=0")).payload,
    );
    const page = normalizeChecksList((await demoRequest("/checks?limit=2&offset=2")).payload);

    expect(down.items.map((check) => check.checkId)).toEqual(["vless-nl-edge"]);
    expect(search.total).toBe(1);
    expect(search.items[0]?.checkId).toBe("vless-nl-edge");
    expect(page.items).toHaveLength(2);
    expect(page.total).toBe(6);
    expect(page.limit).toBe(2);
    expect(page.offset).toBe(2);
  });

  it("matches the live API's exact dimension filters and bounded search fields", async () => {
    const exactGroup = normalizeChecksList(
      (await demoRequest(`/checks?group=${encodeURIComponent("Сетевые точки")}`)).payload,
    );
    const partialGroup = normalizeChecksList(
      (await demoRequest(`/checks?group=${encodeURIComponent("Сетевые")}`)).payload,
    );
    const exactSource = normalizeChecksList((await demoRequest("/checks?source=probe-ru")).payload);
    const partialSource = normalizeChecksList((await demoRequest("/checks?source=probe")).payload);
    const groupOnlySearch = normalizeChecksList(
      (await demoRequest(`/checks?search=${encodeURIComponent("Фоновые процессы")}`)).payload,
    );

    expect(exactGroup.total).toBe(2);
    expect(partialGroup.total).toBe(0);
    expect(exactSource.items.map((check) => check.checkId)).toEqual(["vless-nl-edge"]);
    expect(partialSource.total).toBe(0);
    expect(groupOnlySearch.total).toBe(0);
  });

  it("provides detailed results and bidirectional incident links", async () => {
    const response = await demoRequest("/checks/checkout-flow");
    const normalized = normalizeCheckDetail(response.payload);

    expect(response.status).toBe(200);
    expect(normalized.check?.results).toHaveLength(2);
    expect(normalized.check?.statusReason).toBe("mixed_results");
    expect(normalized.check?.results.map((result) => result.statusReason)).toEqual([
      "result_up",
      "result_failed",
    ]);
    expect(normalized.check?.alerts[0]?.incidentId).toBe("inc-01J7ZQ4K8W8AWMRV77B9");
    expect(normalized.check?.alerts[0]?.startsAt).toBe("2026-09-01T12:39:02Z");
    expect(normalized.check?.incidents[0]?.href).toBe("/incidents/inc-01J7ZQ4K8W8AWMRV77B9");
  });

  it("keeps related incident status and time aligned with the main demo snapshot", async () => {
    const normalized = normalizeCheckDetail((await demoRequest("/checks/vless-nl-edge")).payload);

    expect(normalized.check?.alerts[0]?.status).toBe("acknowledged");
    expect(normalized.check?.alerts[0]?.lastEventAt).toBe("2026-09-01T12:42:52Z");
    expect(normalized.check?.incidents[0]?.status).toBe("acknowledged");
  });

  it("uses result-level reasons for an executor that reports unknown", async () => {
    const normalized = normalizeCheckDetail((await demoRequest("/checks/dns-resolution")).payload);

    expect(normalized.check?.statusReason).toBe("insufficient_sources");
    expect(normalized.check?.results.map((result) => result.statusReason)).toEqual([
      "result_failed",
      "executor_unknown",
    ]);
  });

  it("returns an enabled 404 envelope for an unknown demo Check", async () => {
    const response = await demoRequest("/checks/missing-demo-check");
    const normalized = normalizeCheckDetail(response.payload);

    expect(response.status).toBe(404);
    expect(normalized.meta.enabled).toBe(true);
    expect(normalized.meta.dataState).toBe("ready");
    expect(normalized.check).toBeNull();
  });
});

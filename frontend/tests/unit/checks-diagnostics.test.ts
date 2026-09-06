import { describe, expect, it } from "vitest";

import {
  describeCheckDiagnostic,
  describeCheckErrorReason,
  describeCheckExecutorState,
} from "../../app/checks/diagnostics";

describe("Checks diagnostics copy", () => {
  it("explains a known diagnostic with the affected metric and operator action", () => {
    const diagnostic = describeCheckDiagnostic("conflicting_ttfb", "ru");

    expect(diagnostic).toMatchObject({
      code: "conflicting_ttfb",
      title: "Источники вернули разные значения TTFB",
      metric: "synthetic_check_ttfb_seconds",
      known: true,
    });
    expect(diagnostic.detail).toContain("несколько значений");
    expect(diagnostic.action).toContain("дублирующиеся серии");
  });

  it("explains optional-query warnings without implying the Check itself failed", () => {
    const diagnostic = describeCheckDiagnostic("check_ttfb_unavailable", "en");

    expect(diagnostic.title).toBe("The TTFB metric is temporarily unavailable");
    expect(diagnostic.metric).toBe("synthetic_check_ttfb_seconds");
    expect(diagnostic.action).toContain("no Check status change is required");
  });

  it("covers additive executor diagnostics and optional-query warnings", () => {
    expect(describeCheckDiagnostic("conflicting_target_state_status", "en")).toMatchObject({
      known: true,
      metric: "synthetic_check_target_state / synthetic_check_target_success",
      title: "Target state and status disagree",
    });
    expect(describeCheckDiagnostic("check_error_reasons_unavailable", "en")).toMatchObject({
      known: true,
      metric: "synthetic_check_errors_total",
      title: "Error counters are temporarily unavailable",
    });
  });

  it("localizes executor states and safely describes cumulative error categories", () => {
    expect(describeCheckExecutorState("mismatch", "ru")).toMatchObject({
      state: "mismatch",
      label: "Не совпадает",
      known: true,
    });
    expect(describeCheckExecutorState("future-state", "en")).toMatchObject({
      state: "unknown",
      label: "Unknown executor state",
      known: false,
    });
    expect(describeCheckErrorReason("timeout", "ru")).toMatchObject({
      reason: "timeout",
      label: "Тайм-аут",
      known: true,
    });
    expect(describeCheckErrorReason("<secret>", "en")).toMatchObject({
      reason: "unknown_reason",
      label: "Other reason",
      known: false,
    });
  });

  it("uses a neutral fallback and never reflects an unsafe unknown code", () => {
    const future = describeCheckDiagnostic("future_executor_signal", "en");
    const unsafe = describeCheckDiagnostic("<img src=x onerror=alert(1)>", "en");

    expect(future).toMatchObject({
      code: "future_executor_signal",
      title: "Unknown diagnostic signal",
      known: false,
    });
    expect(unsafe).toMatchObject({
      code: "unknown_diagnostic",
      title: "Unknown diagnostic signal",
      known: false,
    });
    expect(JSON.stringify(unsafe)).not.toContain("onerror");
  });
});

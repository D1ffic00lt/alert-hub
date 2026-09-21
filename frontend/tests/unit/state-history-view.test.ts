import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, test } from "vitest";

import { StateHistoryPills } from "../../app/state-history/StateHistoryPills";

describe("StateHistoryPills", () => {
  test("exposes every full-size period to pointer and keyboard inspection", () => {
    const markup = renderToStaticMarkup(
      createElement(StateHistoryPills, {
        buckets: [
          {
            startsAt: "2026-09-20T10:00:00.000Z",
            endsAt: "2026-09-20T11:00:00.000Z",
          },
        ],
        timeline: {
          periods: [["healthy", "warning", "critical"]],
          healthyPercent: 100 / 3,
          partial: false,
        },
        window: "24h",
        language: "en",
        subject: "alert",
        labels: {
          healthy: "Quiet",
          warning: "Pending",
          critical: "Firing",
          score: "quiet time",
        },
      }),
    );

    expect(markup).toContain('class="state-history__pills" role="list"');
    expect(markup).toContain('class="state-history__pill" role="listitem"');
    expect(markup).toContain('tabindex="0"');
    expect(markup).toContain("Quiet 33% → Pending 33% → Firing 33%");
  });

  test("keeps compact histories out of the tab order when nested in a check link", () => {
    const markup = renderToStaticMarkup(
      createElement(StateHistoryPills, {
        buckets: [
          {
            startsAt: "2026-09-20T10:00:00.000Z",
            endsAt: "2026-09-20T11:00:00.000Z",
          },
        ],
        timeline: {
          periods: [["healthy"]],
          healthyPercent: 100,
          partial: false,
        },
        window: "24h",
        language: "en",
        subject: "check",
        labels: {
          healthy: "Up",
          warning: "Degraded",
          critical: "Down",
          score: "uptime",
        },
        compact: true,
      }),
    );

    expect(markup).toContain('class="state-history__pills" role="img"');
    expect(markup).not.toContain('tabindex="0"');
  });
});

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, test } from "vitest";

import { formatStatisticsDuration } from "../../app/statistics/format";
import { StatisticsOverview } from "../../app/statistics/StatisticsOverview";
import { DEMO_STATISTICS_SNAPSHOT } from "../../app/statistics/model";

describe("formatStatisticsDuration", () => {
  test.each([
    [59.8, "1 min"],
    [3_599, "1h"],
    [7_199, "2h"],
    [7_140, "1h 59m"],
  ])("normalizes rounded boundaries without rendering 60-unit remainders", (seconds, expected) => {
    expect(formatStatisticsDuration("en", seconds)).toBe(expected);
  });

  test("preserves an explicit unavailable value", () => {
    expect(formatStatisticsDuration("ru", null)).toBe("—");
  });
});

describe("StatisticsOverview", () => {
  test("labels resolution volume separately from the new-incident cohort rate", () => {
    const snapshot = {
      ...DEMO_STATISTICS_SNAPSHOT,
      totals: {
        ...DEMO_STATISTICS_SNAPSHOT.totals,
        incidentsStarted: 3,
        incidentsResolved: 7,
        resolutionRate: 66.7,
      },
    };

    const markup = renderToStaticMarkup(
      createElement(StatisticsOverview, { snapshot, language: "ru" }),
    );

    expect(markup).toContain("Разрешено среди начавшихся");
    expect(markup).toContain("7 разрешений за период");
    expect(markup).toContain("среднее для начавшихся");
  });

  test("makes every timeline point inspectable by pointer or keyboard", () => {
    const markup = renderToStaticMarkup(
      createElement(StatisticsOverview, {
        snapshot: DEMO_STATISTICS_SNAPSHOT,
        language: "en",
      }),
    );

    expect(markup.match(/class="statistics-chart__datum"/g)).toHaveLength(
      DEMO_STATISTICS_SNAPSHOT.timeline.length * 2,
    );
    expect(markup).toContain('tabindex="0"');
    expect(markup).toContain("started 1, resolved 0");
    expect(markup).toContain("8 succeeded, 0 failed, 8 total");
  });
});

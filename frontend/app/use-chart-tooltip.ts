import { useEffect, useId, useState } from "react";

import { chartTooltipPosition, type ChartTooltipPosition } from "./chart-tooltip-position";

const CHART_TOOLTIP_OPEN_EVENT = "alert-hub:chart-tooltip-open";

export type ActiveChartTooltip = {
  index: number;
  position: ChartTooltipPosition;
};

export function useChartTooltip() {
  const tooltipId = useId();
  const [activeTooltip, setActiveTooltip] = useState<ActiveChartTooltip | null>(null);

  useEffect(() => {
    const closeWhenAnotherTooltipOpens = (event: Event) => {
      if ((event as CustomEvent<string>).detail !== tooltipId) setActiveTooltip(null);
    };
    window.addEventListener(CHART_TOOLTIP_OPEN_EVENT, closeWhenAnotherTooltipOpens);
    return () => window.removeEventListener(CHART_TOOLTIP_OPEN_EVENT, closeWhenAnotherTooltipOpens);
  }, [tooltipId]);

  const showTooltip = (index: number, target: Element) => {
    window.dispatchEvent(new CustomEvent(CHART_TOOLTIP_OPEN_EVENT, { detail: tooltipId }));
    setActiveTooltip({ index, position: chartTooltipPosition(target) });
  };

  const hideTooltip = (index: number) => {
    setActiveTooltip((current) => (current?.index === index ? null : current));
  };

  return { activeTooltip, hideTooltip, showTooltip, tooltipId };
}

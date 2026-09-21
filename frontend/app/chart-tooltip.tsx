import type { ReactNode } from "react";

import type { ChartTooltipPosition } from "./chart-tooltip-position";

export function FloatingChartTooltip({
  id,
  position,
  children,
  hiddenFromAssistiveTechnology = false,
}: {
  id: string;
  position: ChartTooltipPosition | null;
  children: ReactNode;
  hiddenFromAssistiveTechnology?: boolean;
}) {
  if (!position) return null;
  return (
    <div
      className="chart-tooltip"
      id={id}
      role="tooltip"
      aria-hidden={hiddenFromAssistiveTechnology || undefined}
      style={{ left: position.x, top: position.y }}
    >
      {children}
    </div>
  );
}

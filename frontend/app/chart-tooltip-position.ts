export type ChartTooltipPosition = {
  x: number;
  y: number;
};

export function chartTooltipPosition(target: Element): ChartTooltipPosition {
  const bounds = target.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const halfTooltipWidth = Math.min(140, Math.max(0, (viewportWidth - 24) / 2));
  const minimumX = 12 + halfTooltipWidth;
  const maximumX = viewportWidth - 12 - halfTooltipWidth;
  return {
    x: Math.min(Math.max(bounds.left + bounds.width / 2, minimumX), maximumX),
    y: Math.max(96, bounds.top),
  };
}

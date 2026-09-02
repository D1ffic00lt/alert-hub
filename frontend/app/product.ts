export const DEFAULT_APP_NAME = "Alert Hub";

declare global {
  var __ALERT_HUB_CONFIG__: Readonly<{ appName?: unknown }> | undefined;
}

export function normalizeAppName(value: unknown): string {
  if (typeof value !== "string") return DEFAULT_APP_NAME;
  const withoutControls = Array.from(value, (character) => {
    const codepoint = character.codePointAt(0) ?? 0;
    return codepoint <= 31 || codepoint === 127 ? " " : character;
  }).join("");
  const normalized = withoutControls.replace(/\s+/g, " ").trim();
  return normalized ? normalized.slice(0, 80) : DEFAULT_APP_NAME;
}

export function getAppName(): string {
  return normalizeAppName(globalThis.__ALERT_HUB_CONFIG__?.appName);
}

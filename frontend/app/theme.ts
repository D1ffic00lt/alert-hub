export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = Exclude<ThemePreference, "system">;

export const THEME_STORAGE_KEY = "alert-hub-ui-theme";

export function normalizeThemePreference(value: unknown): ThemePreference {
  return value === "light" || value === "dark" || value === "system" ? value : "dark";
}

export function resolveThemePreference(
  preference: ThemePreference,
  prefersDark: boolean,
): ResolvedTheme {
  return preference === "system" ? (prefersDark ? "dark" : "light") : preference;
}

export function themeColor(theme: ResolvedTheme) {
  return theme === "dark" ? "#0A0A0B" : "#FFFFFF";
}

export function readThemePreference(): ThemePreference {
  if (typeof window === "undefined") return "dark";
  try {
    return normalizeThemePreference(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return "dark";
  }
}

export function applyThemePreference(
  preference: ThemePreference,
  prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true,
): ResolvedTheme {
  const resolved = resolveThemePreference(preference, prefersDark);
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.themePreference = preference;
  root.style.colorScheme = resolved;
  document
    .querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute("content", themeColor(resolved));
  return resolved;
}

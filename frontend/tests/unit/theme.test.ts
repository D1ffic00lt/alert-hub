import { describe, expect, it } from "vitest";

import { normalizeThemePreference, resolveThemePreference, themeColor } from "../../app/theme";

describe("interface theme", () => {
  it("accepts only supported stored preferences", () => {
    expect(normalizeThemePreference("light")).toBe("light");
    expect(normalizeThemePreference("dark")).toBe("dark");
    expect(normalizeThemePreference("system")).toBe("system");
    expect(normalizeThemePreference("contrast")).toBe("dark");
    expect(normalizeThemePreference(null)).toBe("dark");
  });

  it("resolves the system preference while keeping explicit choices stable", () => {
    expect(resolveThemePreference("system", true)).toBe("dark");
    expect(resolveThemePreference("system", false)).toBe("light");
    expect(resolveThemePreference("light", true)).toBe("light");
    expect(resolveThemePreference("dark", false)).toBe("dark");
  });

  it("uses the palette background as the browser chrome color", () => {
    expect(themeColor("dark")).toBe("#0A0A0B");
    expect(themeColor("light")).toBe("#FFFFFF");
  });
});

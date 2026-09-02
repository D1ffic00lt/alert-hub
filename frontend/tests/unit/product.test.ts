import { describe, expect, it } from "vitest";
import { DEFAULT_APP_NAME, getAppName, normalizeAppName } from "../../app/product";

describe("runtime product name", () => {
  it("normalizes control characters, whitespace, empties, and length", () => {
    expect(normalizeAppName("  North\nStar\u0000  Ops  ")).toBe("North Star Ops");
    expect(normalizeAppName("\u0000\t ")).toBe(DEFAULT_APP_NAME);
    expect(normalizeAppName("x".repeat(100))).toHaveLength(80);
    expect(normalizeAppName(null)).toBe(DEFAULT_APP_NAME);
  });

  it("reads only the immutable public runtime namespace", () => {
    const previous = globalThis.__ALERT_HUB_CONFIG__;
    globalThis.__ALERT_HUB_CONFIG__ = Object.freeze({ appName: "  Runtime Ops  " });
    try {
      expect(getAppName()).toBe("Runtime Ops");
    } finally {
      globalThis.__ALERT_HUB_CONFIG__ = previous;
    }
  });
});

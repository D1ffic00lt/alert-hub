import { describe, expect, it } from "vitest";

import { checksEnabledForRuntime } from "../../app/checks/hooks";

describe("Checks runtime visibility", () => {
  it("keeps a known disabled module hidden when the runtime becomes unavailable", () => {
    expect(checksEnabledForRuntime("unavailable", false)).toBe(false);
  });

  it("keeps an unknown or previously enabled module discoverable while offline", () => {
    expect(checksEnabledForRuntime("unavailable", null)).toBe(true);
    expect(checksEnabledForRuntime("unavailable", true)).toBe(true);
  });
});

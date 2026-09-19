import { describe, expect, it } from "vitest";

import { checksEnabledForRuntime } from "../../app/checks/hooks";

describe("Checks runtime visibility", () => {
  it("keeps Checks discoverable while offline regardless of legacy server metadata", () => {
    expect(checksEnabledForRuntime("unavailable", false)).toBe(true);
    expect(checksEnabledForRuntime("unavailable", null)).toBe(true);
    expect(checksEnabledForRuntime("unavailable", true)).toBe(true);
  });
});

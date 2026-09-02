import { describe, expect, it, vi } from "vitest";

import {
  applicationServerKeyMatches,
  blockedPermissionHelp,
  classifyPushClient,
  decodeApplicationServerKey,
  pushDeviceName,
  withPushTimeout,
} from "../../app/push.ts";

const VAPID_PUBLIC_KEY =
  "BHqKzvWvL4jD7SjGmLTrgV9eQYB3sE0JQF3mVZl-B4gtUJvrYJJaM7_zsY4ErX5L5E8cTDPb5i7-pwQ6S2K4h3A";

describe("Web Push client helpers", () => {
  it("recognizes iPad desktop user agents and requires standalone mode", () => {
    expect(
      classifyPushClient(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
        "MacIntel",
        5,
        false,
      ),
    ).toEqual({ browser: "safari", ios: true, standalone: false });
  });

  it("creates stable, bounded device labels without control characters", () => {
    const name = pushDeviceName(" MacIntel\n", "Mozilla/5.0 Safari/605.1.15", true);
    expect(name).toBe("MacIntel · installed app");
    expect(name.length).toBeLessThanOrEqual(255);
  });

  it("returns actionable permission recovery per browser", () => {
    expect(blockedPermissionHelp({ browser: "safari", ios: false, standalone: false })).toContain(
      "Safari → Settings",
    );
    expect(blockedPermissionHelp({ browser: "chromium", ios: false, standalone: false })).toContain(
      "site's permissions",
    );
  });

  it("decodes a canonical application server key and compares rotations", () => {
    const expected = decodeApplicationServerKey(VAPID_PUBLIC_KEY);
    expect(expected).toHaveLength(65);
    expect(applicationServerKeyMatches(expected.buffer, expected)).toBe(true);
    const changed = expected.slice();
    changed[64] ^= 1;
    expect(applicationServerKeyMatches(changed.buffer, expected)).toBe(false);
    expect(() => decodeApplicationServerKey(`${VAPID_PUBLIC_KEY}=`)).toThrow(/invalid VAPID/);
  });

  it("bounds a stalled service worker operation", async () => {
    vi.useFakeTimers();
    const stalled = withPushTimeout(
      new Promise<never>(() => undefined),
      1_000,
      "Service worker registration timed out.",
    );
    const rejection = expect(stalled).rejects.toThrow("Service worker registration timed out.");
    await vi.advanceTimersByTimeAsync(1_000);
    await rejection;
    vi.useRealTimers();
  });
});

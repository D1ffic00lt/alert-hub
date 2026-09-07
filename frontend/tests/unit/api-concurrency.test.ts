import { describe, expect, it, vi } from "vitest";

import { createAsyncRequestLimiter } from "../../app/api/concurrency";

describe("API request concurrency", () => {
  it("keeps only the configured number of reads in flight", async () => {
    const limiter = createAsyncRequestLimiter(2);
    let active = 0;
    let peak = 0;
    const releases: Array<() => void> = [];
    const tasks = Array.from({ length: 5 }, (_, index) =>
      limiter.run(
        () =>
          new Promise<number>((resolve) => {
            active += 1;
            peak = Math.max(peak, active);
            releases.push(() => {
              active -= 1;
              resolve(index);
            });
          }),
      ),
    );

    expect(active).toBe(2);
    while (releases.length) {
      releases.shift()?.();
      await Promise.resolve();
      await Promise.resolve();
    }
    await expect(Promise.all(tasks)).resolves.toEqual([0, 1, 2, 3, 4]);
    expect(peak).toBe(2);
  });

  it("drops an aborted read before it reaches the network", async () => {
    const limiter = createAsyncRequestLimiter(1);
    let releaseFirst: () => void = () => undefined;
    const first = limiter.run(
      () =>
        new Promise<void>((resolve) => {
          releaseFirst = resolve;
        }),
    );
    const controller = new AbortController();
    const queued = vi.fn(async () => undefined);
    const second = limiter.run(queued, controller.signal);

    controller.abort();
    await expect(second).rejects.toMatchObject({ name: "AbortError" });
    releaseFirst();
    await first;
    await Promise.resolve();
    expect(queued).not.toHaveBeenCalled();
  });
});

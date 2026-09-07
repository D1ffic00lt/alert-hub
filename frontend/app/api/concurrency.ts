export type AsyncRequestLimiter = {
  run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T>;
};

type QueuedTask<T> = {
  cancelled: boolean;
  reject: (reason: unknown) => void;
  resolve: (value: T) => void;
  signal?: AbortSignal;
  start: () => Promise<T>;
};

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

export function createAsyncRequestLimiter(limit: number): AsyncRequestLimiter {
  if (!Number.isInteger(limit) || limit < 1) throw new Error("Request limit must be positive");
  let active = 0;
  const queue: QueuedTask<unknown>[] = [];

  const drain = () => {
    while (active < limit && queue.length) {
      const queued = queue.shift();
      if (!queued || queued.cancelled) continue;
      active += 1;
      void queued
        .start()
        .then(queued.resolve, queued.reject)
        .finally(() => {
          active -= 1;
          drain();
        });
    }
  };

  return {
    run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
      if (signal?.aborted) return Promise.reject(abortError());
      return new Promise<T>((resolve, reject) => {
        const queued: QueuedTask<T> = {
          cancelled: false,
          reject,
          resolve,
          signal,
          start: task,
        };
        const onAbort = () => {
          if (queued.cancelled) return;
          queued.cancelled = true;
          reject(abortError());
        };
        if (signal) signal.addEventListener("abort", onAbort, { once: true });
        const start = queued.start;
        queued.start = async () => {
          if (signal) signal.removeEventListener("abort", onAbort);
          if (queued.cancelled) throw abortError();
          return start();
        };
        queue.push(queued as QueuedTask<unknown>);
        drain();
      });
    },
  };
}

import { useEffect, useState } from "react";

import {
  type AlertHistorySnapshot,
  type AlertHistoryWindow,
  buildAlertHistoryPath,
  normalizeAlertHistory,
} from "./model";

type Request = (
  path: string,
  signal: AbortSignal,
) => Promise<{ payload: unknown; status?: number }>;

export type AlertHistoryViewState = {
  snapshot: AlertHistorySnapshot | null;
  loading: boolean;
  error: string | null;
};

export function useIncidentAlertHistory(
  request: Request,
  enabled: boolean,
  incidentId: string,
  window: AlertHistoryWindow,
  revision = 0,
): AlertHistoryViewState {
  const [state, setState] = useState<AlertHistoryViewState>({
    snapshot: null,
    loading: enabled,
    error: null,
  });

  useEffect(() => {
    if (!enabled || !incidentId) {
      queueMicrotask(() => setState({ snapshot: null, loading: false, error: null }));
      return undefined;
    }
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted)
        setState((current) => ({ ...current, loading: current.snapshot === null, error: null }));
    });
    void request(buildAlertHistoryPath(window, { incidentId }), controller.signal)
      .then((response) => {
        if (controller.signal.aborted) return;
        if (response.status !== undefined && response.status >= 400)
          throw new Error("alert_history_unavailable");
        setState({
          snapshot: normalizeAlertHistory(response.payload, window),
          loading: false,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({
          snapshot: null,
          loading: false,
          error: error instanceof Error ? error.message : "alert_history_unavailable",
        });
      });
    return () => controller.abort();
  }, [enabled, incidentId, request, revision, window]);

  return enabled ? state : { snapshot: null, loading: false, error: null };
}
